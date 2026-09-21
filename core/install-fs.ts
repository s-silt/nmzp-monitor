import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

export function sha256Text(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

export interface AtomicFs {
  mkdirSync: (path: string, opts: { recursive: boolean }) => void;
  writeFileSync: (path: string, body: string, opts: { encoding: BufferEncoding; mode: number }) => void;
  renameSync: (from: string, to: string) => void;
  existsSync: (path: string) => boolean;
  unlinkSync: (path: string) => void;
}

const defaultAtomicFs: AtomicFs = {
  mkdirSync: (path, opts) => {
    mkdirSync(path, opts);
  },
  writeFileSync: (path, body, opts) => {
    writeFileSync(path, body, opts);
  },
  renameSync,
  existsSync,
  unlinkSync,
};

/** Single rename onto the live path. Never move or unlink the official file. Fail with a fixed code. */
export function atomicWriteFile(path: string, body: string, mode = 0o600, io: AtomicFs = defaultAtomicFs): void {
  io.mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}`;
  io.writeFileSync(tmp, body, { encoding: "utf8", mode });
  try {
    io.renameSync(tmp, path);
  } catch {
    try {
      io.unlinkSync(tmp);
    } catch {
      /* ignore tmp cleanup */
    }
    throw new Error("atomic_write_failed");
  }
}

/** Path is passed via env, never interpolated into the script. */
export const ACL_RESTRICT_PS = `
$ErrorActionPreference = 'Stop'
$p = $env:NMZP_ACL_PATH
if (-not $p) { throw 'acl_restrict_failed' }
$item = Get-Item -LiteralPath $p
if ($item.PSIsContainer) {
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $inh = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
} else {
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $inh = [System.Security.AccessControl.InheritanceFlags]::None
}
$prop = [System.Security.AccessControl.PropagationFlags]::None
$acl.SetAccessRuleProtection($true, $false)
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$user = New-Object System.Security.Principal.NTAccount($id.Name)
$sys = New-Object System.Security.Principal.NTAccount('NT AUTHORITY\\SYSTEM')
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'Modify', $inh, $prop, 'Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sys, 'FullControl', $inh, $prop, 'Allow')))
$item.SetAccessControl($acl)
`;

export function restrictPath(target: string): void {
  if (!existsSync(target)) return;
  if (process.platform !== "win32") {
    const st = statSync(target);
    chmodSync(target, st.isDirectory() ? 0o700 : 0o600);
    return;
  }
  const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ACL_RESTRICT_PS], {
    windowsHide: true,
    encoding: "utf8",
    env: { ...process.env, NMZP_ACL_PATH: target },
  });
  if (r.status !== 0) {
    throw new Error("acl_restrict_failed");
  }
}

export class FileRollback {
  private created: string[] = [];
  private backups: Array<{ dest: string; bak: string }> = [];
  private backupDir: string;

  constructor(backupDir: string) {
    this.backupDir = backupDir;
    mkdirSync(backupDir, { recursive: true });
  }

  noteCreated(path: string): void {
    this.created.push(path);
  }

  backupExisting(path: string): string | null {
    if (!existsSync(path)) return null;
    const bak = join(this.backupDir, `${basename(path)}.${this.backups.length}`);
    copyFileSync(path, bak);
    restrictPath(bak);
    this.backups.push({ dest: path, bak });
    return bak;
  }

  rollback(): void {
    for (const c of [...this.created].reverse()) {
      try {
        rmSync(c, { force: true });
      } catch {
        /* ignore */
      }
    }
    for (const b of [...this.backups].reverse()) {
      try {
        copyFileSync(b.bak, b.dest);
      } catch {
        /* ignore */
      }
    }
  }
}

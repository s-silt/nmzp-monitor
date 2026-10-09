export interface EmergencyDenial {
  stdout: string;
  exitCode: number;
  stderr?: string;
}

export const EMERGENCY_DENY: Record<string, EmergencyDenial>;

export function emergencyDeny(argv: readonly string[]): EmergencyDenial;

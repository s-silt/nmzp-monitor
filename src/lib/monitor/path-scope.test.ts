import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { workdirScope } from "./engine.ts";
import { classifyWorkdir } from "./path-scope.ts";

describe("workdir scope", () => {
  it("keeps the engine label on the lexical classifier", () => {
    assert.equal(workdirScope("/home/u/proj/src", "/home/u/proj"), classifyWorkdir("/home/u/proj/src", "/home/u/proj"));
  });

  it("does not treat a posix sibling or a prefix without a separator as the project", () => {
    assert.equal(workdirScope("/home/u/proj/src", "/home/u/proj"), "project");
    assert.equal(workdirScope("/home/u/proj", "/home/u/proj"), "project");
    assert.notEqual(workdirScope("/home/u/project2", "/home/u/proj"), "project");
    assert.equal(workdirScope("/home/u/project2", "/home/u/proj"), "home");
    assert.notEqual(workdirScope("/work/application", "/work/app"), "project");
    assert.equal(workdirScope("/work/application", "/work/app"), "other");
  });

  it("does not treat another windows drive or a longer prefix as the project", () => {
    assert.equal(workdirScope("C:\\work\\app\\src", "C:\\work\\app"), "project");
    assert.equal(workdirScope("c:\\work\\app\\src", "C:\\work\\app"), "project");
    assert.equal(workdirScope("C:\\work\\app", "C:\\work\\app"), "project");
    assert.notEqual(workdirScope("D:\\work\\app", "C:\\work\\app"), "project");
    assert.equal(workdirScope("D:\\work\\app", "C:\\work\\app"), "other");
    assert.notEqual(workdirScope("C:\\work\\application", "C:\\work\\app"), "project");
    assert.equal(workdirScope("C:\\Users\\a\\src", "D:\\work"), "home");
    assert.notEqual(workdirScope("C:\\Users2\\a", "D:\\work"), "home");
    assert.equal(workdirScope("\\\\server\\share\\child", "\\\\server\\share"), "project");
    assert.notEqual(workdirScope("\\\\server\\share2", "\\\\server\\share"), "project");
  });

  it("classifies system and home only on a separator boundary", () => {
    assert.equal(workdirScope("/etc", "/work"), "system");
    assert.equal(workdirScope("/etc/passwd", "/work"), "system");
    assert.notEqual(workdirScope("/etc2", "/work"), "system");
    assert.equal(workdirScope("/etc2", "/work"), "other");
    assert.notEqual(workdirScope("/opt2", "/work"), "system");
    assert.equal(workdirScope("/home/someone/docs", "/work"), "home");
    assert.equal(workdirScope("/Users/someone/docs", "/work"), "home");
  });

  it("maps tilde to home without inventing a username", () => {
    assert.equal(workdirScope("~", "/work"), "home");
    assert.equal(workdirScope("~/docs", "/work"), "home");
    assert.equal(workdirScope("~\\docs", "C:\\work"), "home");
    assert.equal(workdirScope("~other", "/work"), "project");
    assert.equal(workdirScope(undefined, "/work"), "project");
    assert.equal(workdirScope("", "/work"), "project");
    assert.equal(workdirScope("src/main", "/work"), "project");
    assert.equal(workdirScope("../project2", "/home/u/proj"), "home");
  });

  it("source contract: the classifier does not read the filesystem or hardcode a user", () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "path-scope.ts"), "utf8");
    assert.equal(source.includes("/home/max"), false);
    assert.equal(source.includes("homedir"), false);
    assert.equal(source.includes("readFile"), false);
    assert.equal(source.includes("realpath"), false);
  });
});

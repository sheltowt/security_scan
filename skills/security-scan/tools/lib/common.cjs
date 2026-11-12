"use strict";

/**
 * Shared helpers for the security-scan tools. Zero dependencies.
 *
 * Every tool treats the target repository and every imported report as
 * untrusted input: reads are bounded and do not follow symlinks, diagnostic
 * output is escaped, and emitted paths are repository-relative.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { TextDecoder } = require("util");

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UNSAFE_DIAGNOSTIC_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const PATH_FORBIDDEN_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;
const VISIBLE_CONTENT = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;

class SafeInputError extends Error {}

function escapeDiagnostic(value) {
  return String(value).replace(UNSAFE_DIAGNOSTIC_CHARACTER, (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0xffff
      ? `\\u${codePoint.toString(16).padStart(4, "0")}`
      : `\\u{${codePoint.toString(16)}}`;
  });
}

function hasVisibleProse(value) {
  return typeof value === "string" && VISIBLE_CONTENT.test(value);
}

/**
 * Read a regular file without following a symlink, refusing FIFOs and devices,
 * and enforcing a byte limit both before and during the read. Returns a Buffer.
 */
function readBoundedBuffer(file, maxBytes) {
  const noFollow = fs.constants.O_NOFOLLOW;
  const nonBlock = fs.constants.O_NONBLOCK;
  if (!Number.isInteger(noFollow) || noFollow === 0 || !Number.isInteger(nonBlock) || nonBlock === 0) {
    throw new SafeInputError("OS no-follow and nonblocking input protection is unavailable");
  }
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlock);
  } catch (error) {
    if (error && (error.code === "ELOOP" || error.code === "EMLINK")) throw new SafeInputError("input must not be a symlink");
    if (error && error.code === "ENOENT") throw new SafeInputError("input does not exist");
    throw new SafeInputError("input could not be opened safely");
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new SafeInputError("input must be a regular file");
    if (stat.size > maxBytes) throw new SafeInputError(`input exceeds ${maxBytes} byte limit`);
    const chunks = [];
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let total = 0;
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      total += count;
      if (total > maxBytes) throw new SafeInputError(`input exceeds ${maxBytes} byte limit`);
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    return Buffer.concat(chunks, total);
  } finally {
    fs.closeSync(descriptor);
  }
}

function readBoundedText(file, maxBytes) {
  const buffer = readBoundedBuffer(file, maxBytes);
  try {
    return UTF8.decode(buffer);
  } catch {
    throw new SafeInputError("input is not valid UTF-8");
  }
}

function readBoundedJson(file, maxBytes) {
  const text = readBoundedText(file, maxBytes);
  try {
    return JSON.parse(text);
  } catch {
    throw new SafeInputError("input is not valid JSON");
  }
}

/** Write a file atomically (temp file in the same directory, then rename). */
function writeAtomic(file, contents) {
  const directory = path.dirname(file);
  const temp = path.join(directory, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`);
  fs.writeFileSync(temp, contents, { flag: "wx", mode: 0o644 });
  fs.renameSync(temp, file);
}

const WINDOWS_RESERVED_COMPONENT = /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)/iu;

/** Same contract as isSafeRelativeSourcePath in validate-findings.cjs. */
function isSafeRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value || PATH_FORBIDDEN_CHARACTER.test(value) || value.includes("\\") || value.includes(":")) return false;
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || value.startsWith("~")) return false;
  return value.split("/").every((segment) =>
    segment !== "" && segment !== "." && segment !== ".." && !/[ .]$/u.test(segment) && !WINDOWS_RESERVED_COMPONENT.test(segment));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

/** Lexicographic comparison by UTF-16 code units, matching validator sort order. */
function compareStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/**
 * Minimal argv parser: `--flag value`, `--flag=value`, repeated flags collect
 * into arrays when listed in `repeatable`, booleans when listed in `booleans`.
 */
function parseArgs(argv, { booleans = [], repeatable = [] } = {}) {
  const options = { _: [] };
  for (const name of repeatable) options[name] = [];
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (argument === "--") {
      options._.push(...argv.slice(index + 1));
      break;
    }
    if (!argument.startsWith("--")) {
      options._.push(argument);
      continue;
    }
    let name = argument.slice(2);
    let value;
    const equals = name.indexOf("=");
    if (equals !== -1) {
      value = name.slice(equals + 1);
      name = name.slice(0, equals);
    }
    if (booleans.includes(name)) {
      options[name] = value === undefined ? true : value !== "false";
      continue;
    }
    if (value === undefined) {
      if (index + 1 >= argv.length) throw new Error(`--${name} requires a value`);
      value = argv[++index];
    }
    if (repeatable.includes(name)) options[name].push(value);
    else options[name] = value;
  }
  return options;
}

module.exports = {
  ID_PATTERN,
  SafeInputError,
  compareStrings,
  escapeDiagnostic,
  hasVisibleProse,
  isSafeRelativePath,
  parseArgs,
  readBoundedBuffer,
  readBoundedJson,
  readBoundedText,
  sha256,
  writeAtomic,
};

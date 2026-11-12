#!/usr/bin/env python3
"""Promote predeclared files from an agent's scratch/ to its artifacts/.

Usage:
  python3 -I promote.py --scratch DIR --artifacts DIR --allow REL [--allow REL]...
                        --max-file-bytes N --max-total-bytes N

Reference implementation of the artifact promotion procedure in SKILL.md
("Write isolation"). Scratch content is target-controlled, so every step works
from directory descriptors opened once, never re-resolves a path, never follows
a symlink, and accepts only regular single-link files within byte limits.

Output: one JSON object per --allow entry on stdout, then exit 0 if every file
was promoted, 1 if any was refused, 2 on usage error or missing OS support.
Run with `python3 -I` so the interpreter ignores PYTHON* variables and the
current directory.
"""

import argparse
import hashlib
import json
import os
import stat
import sys

REQUIRED_FLAGS = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC")
CHUNK = 64 * 1024


class Refused(Exception):
    pass


def os_support_problem():
    for name in REQUIRED_FLAGS:
        if not getattr(os, name, 0):
            return f"os.{name} is unavailable"
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        return "dir_fd support for open/mkdir/unlink is unavailable"
    return None


def open_root(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise SystemExit(f"promote: cannot open root {path!r} as a real directory: {error.strerror}")
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise SystemExit(f"promote: root {path!r} is not a directory")
    return fd


def split_relative(value):
    """Step 1: validate the declared relative path and return its components."""
    if not value or "\x00" in value or "\\" in value or value.startswith("/") or value.startswith("~"):
        raise Refused("path must be a non-empty relative POSIX path")
    parts = value.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise Refused("path must not contain empty, '.', or '..' components")
    return parts


def walk_existing(root_fd, components):
    """Step 2: open each parent component relative to its parent descriptor, no-follow."""
    current = root_fd
    opened = []
    try:
        for part in components:
            try:
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
            except OSError as error:
                raise Refused(f"source parent component {part!r} is not a real directory ({error.strerror})")
            opened.append(fd)
            current = fd
        return current, opened
    except Refused:
        for fd in opened:
            os.close(fd)
        raise


def walk_or_create(root_fd, components):
    """Step 7: walk destination parents no-follow, creating missing ones exclusively."""
    current = root_fd
    opened = []
    try:
        for part in components:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    pass  # raced into existence; the no-follow open below verifies it
                try:
                    fd = os.open(part, flags, dir_fd=current)
                except OSError as error:
                    raise Refused(f"destination component {part!r} could not be opened after creation ({error.strerror})")
            except OSError as error:
                raise Refused(f"destination component {part!r} is not a real directory ({error.strerror})")
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                os.close(fd)
                raise Refused(f"destination component {part!r} is not a directory")
            opened.append(fd)
            current = fd
        return current, opened
    except Refused:
        for fd in opened:
            os.close(fd)
        raise


def identity(st):
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_nlink, st.st_size)


def read_source(parent_fd, name, max_file, remaining_total):
    """Steps 3-6: open leaf no-follow and nonblocking, check, bounded read, re-check."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError as error:
        raise Refused(f"source file could not be opened no-follow ({error.strerror})")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Refused("source is not a regular file")
        if before.st_nlink != 1:
            raise Refused("source has a link count other than one")
        if before.st_size > max_file:
            raise Refused(f"source exceeds the per-file limit of {max_file} bytes")
        if before.st_size > remaining_total:
            raise Refused("source exceeds the remaining cumulative byte limit")
        chunks = []
        total = 0
        limit = min(max_file, remaining_total)
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit or total > before.st_size:
                raise Refused("source grew while being read")
            chunks.append(chunk)
        after = os.fstat(fd)
        if identity(after) != identity(before) or total != before.st_size:
            raise Refused("source changed identity, type, link count, or size while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_destination(parent_fd, name, data):
    """Step 8: create the leaf exclusively without following links and verify it."""
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
    except FileExistsError:
        raise Refused("destination already exists")
    except OSError as error:
        raise Refused(f"destination could not be created exclusively ({error.strerror})")
    created = True
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise Refused("destination is not a fresh regular file")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        created = False
    finally:
        os.close(fd)
        if created:
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass


def promote(scratch_fd, artifacts_fd, relative, max_file, state):
    parts = split_relative(relative)
    src_parent, src_opened = walk_existing(scratch_fd, parts[:-1])
    try:
        data = read_source(src_parent, parts[-1], max_file, state["remaining"])
    finally:
        for fd in src_opened:
            os.close(fd)
    dst_parent, dst_opened = walk_or_create(artifacts_fd, parts[:-1])
    try:
        write_destination(dst_parent, parts[-1], data)
    finally:
        for fd in dst_opened:
            os.close(fd)
    state["remaining"] -= len(data)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--allow", action="append", default=[], required=True)
    parser.add_argument("--max-file-bytes", type=int, required=True)
    parser.add_argument("--max-total-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    if args.max_file_bytes < 1 or args.max_total_bytes < 1:
        print("promote: byte limits must be positive", file=sys.stderr)
        return 2

    problem = os_support_problem()
    if problem:
        # Step 11: a required primitive is unavailable, so nothing is promoted.
        for relative in args.allow:
            print(json.dumps({"path": relative, "status": "refused", "reason": f"promotion blocked: {problem}"}))
        return 2

    scratch_fd = open_root(args.scratch)
    artifacts_fd = open_root(args.artifacts)
    if identity(os.fstat(scratch_fd))[:2] == identity(os.fstat(artifacts_fd))[:2]:
        print("promote: scratch and artifacts must be different directories", file=sys.stderr)
        return 2

    state = {"remaining": args.max_total_bytes}
    seen = set()
    failures = 0
    try:
        for relative in args.allow:
            result = {"path": relative}
            try:
                if relative in seen:
                    raise Refused("duplicate --allow entry")
                seen.add(relative)
                result.update(promote(scratch_fd, artifacts_fd, relative, args.max_file_bytes, state))
                result["status"] = "promoted"
            except Refused as refusal:
                failures += 1
                result.update({"status": "refused", "reason": str(refusal)})
            print(json.dumps(result))
    finally:
        os.close(scratch_fd)
        os.close(artifacts_fd)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

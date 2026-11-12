# Sandbox

Every target-controlled build, test, process, fuzzer, browser, or fixture runs under the controls in `SKILL.md` ("Universal execution safety"). This file gives concrete ways to meet them. `tools/sandbox-run.sh` is the reference wrapper, and `tools/promote.py` is the reference promotion code.

## Check what the machine can enforce

```sh
bash <skill-dir>/tools/sandbox-run.sh --check
```

Record the JSON in `run-metadata.json` under `sandbox`. It lists each backend (`docker`, `podman`, `bwrap`), whether it is usable now, and which controls it enforces. The parent decides once per run:

- **A backend is available and scratch is size-limited** (see below): target execution is allowed. Candidates can climb to E2–E4.
- **A backend is available but scratch is not size-limited**: the cumulative disk control is missing. Either create a size-limited scratch or treat execution as blocked.
- **No backend**: execution is blocked. Every candidate tops out at E1 (`needs_validation`), and the report says so.

Never fall back to running target code directly on the host.

## `sandbox-run.sh`

```sh
bash <skill-dir>/tools/sandbox-run.sh --backend docker --image <local-image> \
  --target <target-or-scratch-copy> --scratch <output-dir>/agents/<id>/scratch \
  --cpus 1 --memory 1g --pids 128 --file-size 64m --timeout 120 \
  --env CI=1 -- <command> [args...]
```

| Control | docker / podman | bwrap (Linux) |
|---|---|---|
| No external network | `--network none` | `--unshare-all` (new, empty net namespace with loopback only) |
| Empty allowlisted env | container gets only `HOME`, `TMPDIR`, and `--env` pairs (plus the image's own `ENV`) | `--clearenv`, then `HOME`, `TMPDIR`, `PATH`, and `--env` pairs |
| Read-only target | `-v target:/src:ro` | `--ro-bind target /src` |
| Read-only toolchain | `--read-only` image root; `--ro DIR` for extra tool dirs | system dirs `--ro-bind`; `$HOME` is never bound, and `--ro` refuses paths under `$HOME` |
| Scratch-only writes | `/scratch` and `/tmp` both map to the agent scratch dir | same |
| CPU / memory / processes | `--cpus`, `--memory` (swap disabled), `--pids-limit` | `prlimit --cpu --as --nproc`; cgroup `MemoryMax`/`TasksMax` via `systemd-run --user --scope` when available |
| File size | `--ulimit fsize` | `prlimit --fsize` |
| Wall clock | watchdog `kill` by container name, exit 124 | `timeout --kill-after=5`, exit 124 |
| Privilege | `--cap-drop ALL`, `no-new-privileges`, non-root `--user` | unprivileged user namespace, `--new-session`, `--die-with-parent` |
| Fetching | `--pull never`: the image must already exist locally | n/a |

The wrapper refuses a scratch directory inside the target (or the reverse), `--env` overrides of `HOME`, `TMPDIR`, `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `DYLD_*`, and a missing image. `--dry-run` prints the exact command without running it. Record that command in the ledger check.

**Choosing an image.** Use an image the user already has with the target's toolchain (for example a project dev-container image, or `node:22`, `python:3.12`, or `golang:1.23` if those are already pulled). Do not pull or build images during the run. If the right toolchain is not present, report the missing toolchain as the blocker.

**Builds that write beside source.** Point `--target` at a disposable copy inside the agent's scratch instead of the real target (see REMEDIATION.md, Step 1). The copy is then target-controlled. Never promote anything from it except through `promote.py`.

**Loopback services.** To start a target server and drive it with a client, run both inside one sandbox invocation (for example a small script that starts the server, waits for the port, runs the client, then exits). Separate sandbox invocations do not share a network.

## Size-limited scratch (cumulative disk control)

`RLIMIT_FSIZE` caps single files, not total disk. Put each agent's scratch on a filesystem with a hard size:

- **Linux**: `sudo mount -t tmpfs -o size=512m,mode=0700,uid=$(id -u) tmpfs <output-dir>/agents/<id>/scratch`, or a loopback ext4 image of fixed size.
- **macOS**: `hdiutil create -size 512m -fs APFS -volname scratch-<id> /path/scratch-<id>.dmg && hdiutil attach -nobrowse -mountpoint <output-dir>/agents/<id>/scratch /path/scratch-<id>.dmg`. Detach with `hdiutil detach` after promotion.
- **Docker Desktop on macOS**: bind-mounting a size-limited `hdiutil` volume works the same way.

If none is possible, tell the user that the disk control is missing and ask whether to proceed with execution blocked.

## Promotion (`promote.py`)

After the sandbox exits, the parent promotes only predeclared files from scratch to the agent's `artifacts/`:

```sh
python3 -I <skill-dir>/tools/promote.py \
  --scratch <output-dir>/agents/<id>/scratch --artifacts <output-dir>/agents/<id>/artifacts \
  --allow results/asan.txt --allow patches/<fingerprint>.diff \
  --max-file-bytes 1048576 --max-total-bytes 4194304
```

It implements the eleven-step procedure in `SKILL.md`. It opens both roots once as directory descriptors, walks every component with `O_NOFOLLOW | O_DIRECTORY` relative to the parent descriptor, opens the leaf `O_NOFOLLOW | O_NONBLOCK`, requires a regular file with link count 1, enforces the per-file and cumulative byte limits before and during the copy, re-checks identity and size after reading, and creates the destination with `O_CREAT | O_EXCL | O_NOFOLLOW`. It prints one JSON line per file (`promoted` or `refused` with a reason) and exits 1 if any declared file was refused. It needs `dir_fd` support in `os.open` and `os.mkdir`, which every Linux and macOS Python 3 provides. If that support is missing, it refuses everything rather than falling back to path-based copies.

## macOS without Docker

`sandbox-exec` profiles can deny network and writes, but they cannot enforce memory, process, or CPU limits, and Apple has deprecated the tool. Treat it as insufficient. Use Docker Desktop, Colima, or Podman machine, or a Linux VM with `bwrap`.

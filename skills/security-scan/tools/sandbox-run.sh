#!/usr/bin/env bash
# Run one target-controlled command inside an OS-enforced sandbox.
#
#   sandbox-run.sh --check
#   sandbox-run.sh [--backend auto|docker|podman|bwrap] --target DIR --scratch DIR
#                  [--image IMAGE] [--cpus N] [--memory SIZE] [--pids N]
#                  [--file-size SIZE] [--timeout SECONDS] [--ro DIR]...
#                  [--env NAME=VALUE]... [--dry-run] -- COMMAND [ARG...]
#
# Controls (SKILL.md "Universal execution safety"):
#   * no external network            docker/podman --network none; bwrap --unshare-net (loopback only)
#   * empty allowlisted environment  only --env pairs plus HOME/TMPDIR/PATH reach the command
#   * read-only target and toolchain target mounted read-only at /src; image root or host
#                                    system dirs read-only; nothing from $HOME is mounted
#   * scratch-only writes            scratch mounted read-write at /scratch (and /tmp -> scratch/tmp)
#   * CPU, memory, process, file-size, wall-clock limits enforced per run
#   * disk: per-file only (RLIMIT_FSIZE). Cumulative disk needs scratch on a size-limited
#     filesystem; see SANDBOX.md. --check reports this as a gap.
#
# The script never pulls images or installs anything. It is trusted parent-side
# code: run it from the skill directory, never from inside the target.

set -euo pipefail

die() { printf 'sandbox-run: %s\n' "$*" >&2; exit 2; }

backend=auto
target=""
scratch=""
image=""
cpus=1
memory=1g
pids=128
file_size=64m
timeout_s=120
dry_run=0
check=0
env_pairs=()
ro_dirs=()

while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1; shift ;;
    --backend) backend="${2:?}"; shift 2 ;;
    --target) target="${2:?}"; shift 2 ;;
    --scratch) scratch="${2:?}"; shift 2 ;;
    --image) image="${2:?}"; shift 2 ;;
    --cpus) cpus="${2:?}"; shift 2 ;;
    --memory) memory="${2:?}"; shift 2 ;;
    --pids) pids="${2:?}"; shift 2 ;;
    --file-size) file_size="${2:?}"; shift 2 ;;
    --timeout) timeout_s="${2:?}"; shift 2 ;;
    --ro) ro_dirs+=("${2:?}"); shift 2 ;;
    --env) env_pairs+=("${2:?}"); shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --) shift; break ;;
    *) die "unknown argument: $1" ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

# SIZE like 64m, 1g, 512k, or plain bytes -> bytes
to_bytes() {
  local value="$1" number unit
  number="${value%[kKmMgG]}"
  unit="${value#"$number"}"
  case "$number" in ''|*[!0-9]*) die "invalid size: $value" ;; esac
  case "$unit" in
    "") printf '%s\n' "$number" ;;
    k|K) printf '%s\n' $((number * 1024)) ;;
    m|M) printf '%s\n' $((number * 1024 * 1024)) ;;
    g|G) printf '%s\n' $((number * 1024 * 1024 * 1024)) ;;
  esac
}

container_engine_usable() {
  have "$1" && "$1" info >/dev/null 2>&1
}

if [ "$check" -eq 1 ]; then
  os="$(uname -s)"
  printf '{\n  "os": "%s",\n  "backends": {\n' "$os"
  first=1
  for engine in docker podman; do
    if container_engine_usable "$engine"; then state=available; else state=unavailable; fi
    [ $first -eq 1 ] || printf ',\n'; first=0
    printf '    "%s": {"state": "%s", "network": "none", "env": "allowlist", "readonly_target": true, "readonly_toolchain": "image root --read-only", "scratch_only_writes": true, "cpu": true, "memory": true, "pids": true, "file_size": true, "wall_clock": true, "disk_total": "requires size-limited scratch filesystem", "requires": "--image already present locally (never pulled)"}' "$engine" "$state"
  done
  if [ "$os" = "Linux" ] && have bwrap && have prlimit && have timeout; then
    state=available
    if have systemd-run && systemd-run --user --scope --quiet true >/dev/null 2>&1; then pids_mode='"cgroup TasksMax"'; mem_mode='"cgroup MemoryMax"'; else pids_mode='"RLIMIT_NPROC (per-uid, approximate)"'; mem_mode='"RLIMIT_AS"'; fi
  else
    state=unavailable; pids_mode=false; mem_mode=false
  fi
  printf ',\n    "bwrap": {"state": "%s", "network": "loopback-only namespace", "env": "clearenv + allowlist", "readonly_target": true, "readonly_toolchain": "system dirs ro-bound, $HOME never bound", "scratch_only_writes": true, "cpu": true, "memory": %s, "pids": %s, "file_size": true, "wall_clock": true, "disk_total": "requires size-limited scratch filesystem"}' "$state" "$mem_mode" "$pids_mode"
  printf '\n  },\n  "note": "If no backend is available, or the parent cannot guarantee a size-limited scratch filesystem, target execution is blocked: keep leads as needs_validation with the missing control as the blocker."\n}\n'
  exit 0
fi

[ $# -gt 0 ] || die "missing command after --"
[ -n "$target" ] && [ -d "$target" ] || die "--target must be an existing directory"
[ -n "$scratch" ] && [ -d "$scratch" ] || die "--scratch must be an existing directory"
[ -L "$scratch" ] && die "--scratch must not be a symlink"
target="$(cd "$target" && pwd -P)"
scratch="$(cd "$scratch" && pwd -P)"
case "$scratch/" in "$target/"*) die "--scratch must be outside the read-only target" ;; esac
case "$target/" in "$scratch/"*) die "--target must not be inside scratch" ;; esac
for forbidden in / "${HOME:-/nonexistent}"; do
  [ "$scratch" = "$forbidden" ] && die "--scratch must be a dedicated per-agent directory"
done
for pair in ${env_pairs[@]+"${env_pairs[@]}"}; do
  case "$pair" in
    [A-Za-z_]*=*) name="${pair%%=*}"; case "$name" in *[!A-Za-z0-9_]*) die "invalid --env name: $name" ;; esac ;;
    *) die "--env expects NAME=VALUE" ;;
  esac
  case "$name" in HOME|TMPDIR|PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_*) die "--env may not override $name" ;; esac
done
case "$timeout_s" in ''|*[!0-9]*) die "--timeout must be whole seconds" ;; esac
case "$pids" in ''|*[!0-9]*) die "--pids must be an integer" ;; esac
mem_bytes="$(to_bytes "$memory")"
fsize_bytes="$(to_bytes "$file_size")"
for dir in ${ro_dirs[@]+"${ro_dirs[@]}"}; do
  case "$dir" in /*) ;; *) die "--ro expects an absolute path: $dir" ;; esac
  case "$dir/" in "${HOME:-/nonexistent}/"*|"${HOME:-/nonexistent}/") die "--ro must not expose the host home directory: $dir" ;; esac
done
mkdir -p "$scratch/home" "$scratch/tmp"

if [ "$backend" = auto ]; then
  if [ "$(uname -s)" = Linux ] && have bwrap && have prlimit && have timeout; then backend=bwrap
  elif container_engine_usable docker; then backend=docker
  elif container_engine_usable podman; then backend=podman
  else die "no sandbox backend available (run --check); do not execute target code"
  fi
fi

cmd=()
case "$backend" in
  docker|podman)
    [ -n "$image" ] || die "--image is required for $backend (it must already exist locally)"
    name="ss-sandbox-$$-$RANDOM"
    cmd=("$backend" run --rm --name "$name" --pull never --network none --read-only
      --cap-drop ALL --security-opt no-new-privileges --init
      --user "$(id -u):$(id -g)"
      --cpus "$cpus" --memory "$mem_bytes" --memory-swap "$mem_bytes" --pids-limit "$pids"
      --ulimit "fsize=$fsize_bytes:$fsize_bytes" --ulimit "nofile=256:256" --ulimit "core=0:0"
      -v "$target:/src:ro" -v "$scratch:/scratch:rw" -v "$scratch/tmp:/tmp:rw"
      -w /scratch -e HOME=/scratch/home -e TMPDIR=/tmp)
    for dir in ${ro_dirs[@]+"${ro_dirs[@]}"}; do cmd+=(-v "$dir:$dir:ro"); done
    for pair in ${env_pairs[@]+"${env_pairs[@]}"}; do cmd+=(-e "$pair"); done
    cmd+=("$image" "$@")
    ;;
  bwrap)
    [ "$(uname -s)" = Linux ] || die "bwrap backend requires Linux"
    cmd=()
    if have systemd-run && systemd-run --user --scope --quiet true >/dev/null 2>&1; then
      cmd+=(systemd-run --user --scope --quiet -p "TasksMax=$pids" -p "MemoryMax=$mem_bytes" -p "MemorySwapMax=0" --)
    fi
    cmd+=(timeout --kill-after=5 "$timeout_s"
      prlimit "--cpu=$timeout_s" "--as=$mem_bytes" "--fsize=$fsize_bytes" "--nproc=$pids" "--nofile=256" "--core=0" --
      bwrap --unshare-all --die-with-parent --new-session --clearenv
      --proc /proc --dev /dev)
    for sys in /usr /bin /sbin /lib /lib32 /lib64 /etc/alternatives /etc/ssl /etc/ld.so.cache /etc/ld.so.conf /etc/ld.so.conf.d; do
      [ -e "$sys" ] && cmd+=(--ro-bind "$sys" "$sys")
    done
    for dir in ${ro_dirs[@]+"${ro_dirs[@]}"}; do cmd+=(--ro-bind "$dir" "$dir"); done
    cmd+=(--ro-bind "$target" /src --bind "$scratch" /scratch --bind "$scratch/tmp" /tmp
      --chdir /scratch --setenv HOME /scratch/home --setenv TMPDIR /tmp --setenv PATH /usr/local/bin:/usr/bin:/bin)
    for pair in ${env_pairs[@]+"${env_pairs[@]}"}; do cmd+=(--setenv "${pair%%=*}" "${pair#*=}"); done
    cmd+=(-- "$@")
    ;;
  *) die "unknown backend: $backend" ;;
esac

if [ "$dry_run" -eq 1 ]; then
  printf '%q\n' "${cmd[@]}"
  exit 0
fi

if [ "$backend" = bwrap ]; then
  exec "${cmd[@]}"
fi

# Container engines have no wall-clock limit of their own: watchdog kills by name.
marker="$(mktemp "${TMPDIR:-/tmp}/sandbox-run-timeout.XXXXXX")"
rm -f "$marker"
"${cmd[@]}" &
child=$!
(
  sleep "$timeout_s"
  if "$backend" kill "$name" >/dev/null 2>&1; then
    : > "$marker"
    printf 'sandbox-run: wall-clock limit %ss reached; killed\n' "$timeout_s" >&2
  fi
) &
watchdog=$!
status=0
wait "$child" || status=$?
kill "$watchdog" >/dev/null 2>&1 || true
wait "$watchdog" 2>/dev/null || true
# Match timeout(1): 124 means the wall-clock limit fired (not an OOM kill).
if [ -e "$marker" ]; then status=124; rm -f "$marker"; fi
exit "$status"

#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  cat >&2 <<'USAGE'
usage: scripts/run-soak.sh [--duration-seconds N] [--sessions N]
       [--restart-every-rounds N] [--provider-delay-ms N] [--report FILE]
       [--round-interval-ms N] [--mealyd FILE] [--home DIRECTORY]
       [--release|--debug]

Runs the opt-in real-daemon fixture soak. It repeatedly exercises durable
multi-turn sessions, exact duplicate admission, hard death after provider
dispatch, startup recovery, recorded-only replay, clean drain, SQLite
integrity, residual gauges, latency, RSS, and durable-storage growth.
USAGE
}

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
duration_seconds=${MEALY_SOAK_DURATION_SECONDS:-300}
sessions=${MEALY_SOAK_SESSIONS:-8}
restart_every_rounds=${MEALY_SOAK_RESTART_EVERY_ROUNDS:-10}
provider_delay_ms=${MEALY_SOAK_PROVIDER_DELAY_MS:-250}
round_interval_ms=${MEALY_SOAK_ROUND_INTERVAL_MS:-0}
report=${MEALY_SOAK_REPORT:-}
profile=${MEALY_SOAK_PROFILE:-release}
mealyd=${MEALY_SOAK_MEALYD:-}
home=${MEALY_SOAK_HOME:-}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration-seconds)
      duration_seconds=${2-}
      shift 2
      ;;
    --sessions)
      sessions=${2-}
      shift 2
      ;;
    --restart-every-rounds)
      restart_every_rounds=${2-}
      shift 2
      ;;
    --provider-delay-ms)
      provider_delay_ms=${2-}
      shift 2
      ;;
    --round-interval-ms)
      round_interval_ms=${2-}
      shift 2
      ;;
    --report)
      report=${2-}
      shift 2
      ;;
    --mealyd)
      mealyd=${2-}
      shift 2
      ;;
    --home)
      home=${2-}
      shift 2
      ;;
    --release)
      profile=release
      shift
      ;;
    --debug)
      profile=debug
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done

if [[ $profile != release && $profile != debug ]]; then
  usage
  exit 64
fi

for value in "$duration_seconds" "$sessions" "$restart_every_rounds" "$provider_delay_ms" \
  "$round_interval_ms"; do
  if [[ ! $value =~ ^[0-9]+$ ]]; then
    usage
    exit 64
  fi
done
if (( duration_seconds < 1 || duration_seconds > 604800 \
      || sessions < 1 || sessions > 64 \
      || restart_every_rounds < 1 || restart_every_rounds > 10000 \
      || provider_delay_ms < 100 || provider_delay_ms > 10000 \
      || round_interval_ms > 60000 )); then
  usage
  exit 64
fi

if [[ -z $report ]]; then
  report="$repository_root/target/soak/$(date -u +%Y%m%dT%H%M%SZ).json"
elif [[ $report != /* ]]; then
  report="$PWD/$report"
fi
mkdir -p "$(dirname "$report")"

if [[ -n $mealyd ]]; then
  if [[ $mealyd != /* ]]; then
    mealyd="$PWD/$mealyd"
  fi
  if [[ -L $mealyd || ! -f $mealyd || ! -x $mealyd ]]; then
    echo "soak daemon must be an executable real file: $mealyd" >&2
    exit 66
  fi
  mealyd=$(readlink -f -- "$mealyd")
  expected_version=$(awk '
    $0 == "[workspace.package]" { in_package = 1; next }
    in_package && /^\[/ { exit }
    in_package && /^version = "[^"]+"$/ {
      sub(/^version = "/, "")
      sub(/"$/, "")
      print
      exit
    }
  ' "$repository_root/Cargo.toml")
  if [[ -z $expected_version || $("$mealyd" --version) != "mealyd $expected_version" ]]; then
    echo "soak daemon version does not match this harness" >&2
    exit 65
  fi
  export MEALY_SOAK_MEALYD=$mealyd
else
  unset MEALY_SOAK_MEALYD
fi

if [[ -n $home ]]; then
  if [[ $home != /* ]]; then
    home="$PWD/$home"
  fi
  if [[ -e $home || -L $home ]]; then
    echo "retained soak home must not already exist: $home" >&2
    exit 73
  fi
  home_parent=$(dirname -- "$home")
  home_name=$(basename -- "$home")
  if [[ $home_name == . || $home_name == .. || $home_name == / ]]; then
    echo "retained soak home has an invalid basename" >&2
    exit 64
  fi
  mkdir -p -- "$home_parent"
  home_parent=$(cd "$home_parent" && pwd -P)
  home="$home_parent/$home_name"
  filesystem=$(stat -f -c %T -- "$home_parent")
  if [[ $filesystem == tmpfs || $filesystem == ramfs ]]; then
    echo "retained soak home must use disk-backed storage, not $filesystem" >&2
    exit 65
  fi
  mkdir -m 0700 -- "$home"
  export MEALY_SOAK_HOME=$home
  export MEALY_SOAK_FILESYSTEM=$filesystem
else
  unset MEALY_SOAK_HOME MEALY_SOAK_FILESYSTEM
fi

revision=unknown
if command -v git >/dev/null 2>&1; then
  revision=$(git -C "$repository_root" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')
  if [[ -n $(git -C "$repository_root" status --porcelain 2>/dev/null) ]]; then
    revision="${revision}-dirty"
  fi
fi

export MEALY_SOAK_DURATION_SECONDS=$duration_seconds
export MEALY_SOAK_SESSIONS=$sessions
export MEALY_SOAK_RESTART_EVERY_ROUNDS=$restart_every_rounds
export MEALY_SOAK_PROVIDER_DELAY_MS=$provider_delay_ms
export MEALY_SOAK_ROUND_INTERVAL_MS=$round_interval_ms
export MEALY_SOAK_REPORT=$report
export MEALY_SOAK_REVISION=$revision

cd "$repository_root"
soak_target_dir=${MEALY_SOAK_CARGO_TARGET_DIR:-$repository_root/target/soak-harness}
if [[ $soak_target_dir != /* ]]; then
  soak_target_dir="$repository_root/$soak_target_dir"
fi
if [[ -L $soak_target_dir ]]; then
  echo "soak harness target directory cannot be a symlink: $soak_target_dir" >&2
  exit 65
fi
mkdir -p "$soak_target_dir"
if [[ ! -d $soak_target_dir ]]; then
  echo "soak harness target path is not a directory: $soak_target_dir" >&2
  exit 65
fi
export CARGO_TARGET_DIR
CARGO_TARGET_DIR=$(cd "$soak_target_dir" && pwd -P)
cargo_profile=()
if [[ $profile == release ]]; then
  cargo_profile=(--release)
fi
cargo test --locked "${cargo_profile[@]}" -p mealyd --test soak \
  bounded_soak_restarts_and_reports_durable_measurements -- \
  --ignored --exact --nocapture

if [[ ! -s $report ]]; then
  echo "soak completed without a non-empty report: $report" >&2
  exit 65
fi
printf 'soak report: %s\n' "$report"

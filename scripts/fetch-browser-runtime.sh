#!/usr/bin/env bash
set -euo pipefail

readonly version=150.0.7871.124
readonly archive_name=chrome-headless-shell-linux64.zip
readonly archive_sha256=98de0bcdc661d14b2fc122ae99a27df35d47e464e8d38a4a5e01f81a4ce295c2
readonly archive_bytes=120351731
readonly url="https://storage.googleapis.com/chrome-for-testing-public/${version}/linux64/${archive_name}"

if [[ $# -ne 1 || -z $1 ]]; then
  echo "usage: $0 DESTINATION_ROOT" >&2
  exit 64
fi

for command in curl sha256sum unzip find stat uname wc mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "required command is unavailable: $command" >&2
    exit 69
  }
done
if [[ $(uname -s) != Linux ]]; then
  echo "the pinned browser runtime is supported only on Linux x86_64" >&2
  exit 69
fi
case $(uname -m) in
  x86_64|amd64) ;;
  *)
    echo "the pinned browser runtime is supported only on Linux x86_64" >&2
    exit 69
    ;;
esac

umask 077
destination_root=$1
destination="${destination_root}/${version}"
if [[ -e $destination ]]; then
  echo "destination already exists: $destination" >&2
  exit 73
fi
mkdir -p "$destination_root"
temporary=$(mktemp -d "${destination_root}/.${version}.tmp.XXXXXX")
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT

archive="${temporary}/${archive_name}"
curl --fail --location --silent --show-error \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 20 --max-time 600 --max-redirs 3 \
  --max-filesize "$archive_bytes" \
  --output "$archive" "$url"
test "$(stat -c %s "$archive")" = "$archive_bytes"
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum --check --strict >/dev/null

listing="${temporary}/entries.txt"
unzip -Z1 "$archive" >"$listing"
test "$(wc -l <"$listing")" -le 512
while IFS= read -r entry; do
  [[ $entry == chrome-headless-shell-linux64/* ]]
  [[ $entry != /* && $entry != *../* && $entry != *'/..' ]]
done <"$listing"

extract="${temporary}/extract"
mkdir "$extract"
unzip -q "$archive" -d "$extract"
test -x "${extract}/chrome-headless-shell-linux64/chrome-headless-shell"
test -z "$(find "$extract" -type l -print -quit)"
test -z "$(find "$extract" ! -type d ! -type f -print -quit)"
rm "$archive" "$listing"
mv "${extract}/chrome-headless-shell-linux64" "$destination"
rmdir "$extract"
trap - EXIT
rm -rf "$temporary"

printf '%s\n' "$destination"

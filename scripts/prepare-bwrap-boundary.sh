#!/usr/bin/env bash
set -euo pipefail

readonly PROFILE_SOURCE=/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
readonly PROFILE_DESTINATION=/etc/apparmor.d/bwrap-userns-restrict
readonly APPARMOR_RESTRICTION=/proc/sys/kernel/apparmor_restrict_unprivileged_userns

die() {
  printf 'prepare-bwrap-boundary: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die 'this command does not accept arguments'
[[ ${EUID} -ne 0 ]] || die 'run as the unprivileged Mealy owner; the command invokes sudo only for host policy changes'

for command_path in \
  /usr/bin/bwrap \
  /usr/bin/grep \
  /usr/bin/install \
  /usr/bin/sudo \
  /usr/sbin/apparmor_parser \
  /usr/sbin/sysctl; do
  [[ -x "$command_path" ]] || die "required command is unavailable: $command_path"
done

if /usr/sbin/sysctl kernel.unprivileged_userns_clone >/dev/null 2>&1; then
  /usr/bin/sudo /usr/sbin/sysctl -w kernel.unprivileged_userns_clone=1
  [[ $(/usr/sbin/sysctl -n kernel.unprivileged_userns_clone) == 1 ]] ||
    die 'kernel.unprivileged_userns_clone did not remain enabled'
fi

if [[ -e "$APPARMOR_RESTRICTION" ]]; then
  [[ -f "$PROFILE_SOURCE" && ! -L "$PROFILE_SOURCE" ]] ||
    die "reviewed distro profile is unavailable: $PROFILE_SOURCE"

  /usr/bin/sudo /usr/bin/install -m 0644 -- "$PROFILE_SOURCE" "$PROFILE_DESTINATION"

  # Load only this profile. Ubuntu 24.04's aa-enforce helper scans unrelated
  # policy files and can fail on a malformed optional passt abstraction before
  # it reaches the requested Bubblewrap policy.
  /usr/bin/sudo /usr/sbin/apparmor_parser -r -K "$PROFILE_DESTINATION"
  /usr/bin/sudo /usr/sbin/sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
  [[ $(/usr/sbin/sysctl -n kernel.apparmor_restrict_unprivileged_userns) == 1 ]] ||
    die 'kernel.apparmor_restrict_unprivileged_userns did not remain enabled'

  for profile in 'bwrap (enforce)' 'unpriv_bwrap (enforce)'; do
    /usr/bin/sudo /usr/bin/grep -Fqx -- "$profile" /sys/kernel/security/apparmor/profiles ||
      die "AppArmor profile is not enforced: $profile"
  done
fi

/usr/bin/bwrap --die-with-parent --new-session --unshare-user --unshare-pid \
  --unshare-net --ro-bind / / -- /bin/true

printf 'Bubblewrap private-network boundary: ok\n'

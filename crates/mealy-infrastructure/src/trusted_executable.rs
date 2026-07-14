use std::path::Path;

/// Returns whether an executable is an exact protected installed file.
///
/// Direct-process configuration is intentionally limited to files and directory chains that an
/// unprivileged account cannot replace between identity verification and sandbox bind-mounting.
/// Outside a Linux user service, the complete path chain must be root-owned and not writable by
/// group or other. Linux systemd user units expose non-owner installed files, including root-owned
/// system files, through the kernel overflow UID. That representation is accepted only under an
/// exact one-entry user/group mapping and a completely read-only path chain. This is a single-owner
/// boundary: a separate hostile local account with write access to such an underlying file is not
/// contained by the read-only view. The executable must already be canonical; callers still pin
/// and re-check its content digest.
#[must_use]
pub fn is_trusted_system_executable(path: &Path) -> bool {
    platform_trust(path)
}

#[cfg(unix)]
fn platform_trust(path: &Path) -> bool {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    if !path.is_absolute() || !fs::canonicalize(path).is_ok_and(|canonical| canonical == path) {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    let owner_uid = metadata.uid();
    let Some(owner_requires_read_only_mount) = trusted_owner_policy(owner_uid) else {
        return false;
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
        || owner_requires_read_only_mount && !path_is_on_read_only_mount(path)
    {
        return false;
    }
    path.ancestors().skip(1).all(|directory| {
        fs::symlink_metadata(directory).is_ok_and(|metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == owner_uid
                && metadata.permissions().mode() & 0o022 == 0
                && (!owner_requires_read_only_mount || path_is_on_read_only_mount(directory))
        })
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
const fn trusted_owner_policy(owner: u32) -> Option<bool> {
    if owner == 0 { Some(false) } else { None }
}

#[cfg(target_os = "linux")]
fn trusted_owner_policy(owner: u32) -> Option<bool> {
    if owner == 0 {
        return Some(false);
    }
    let uid_map = std::fs::read_to_string("/proc/self/uid_map").ok()?;
    let gid_map = std::fs::read_to_string("/proc/self/gid_map").ok()?;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let overflow_uid = std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()?;
    (namespace_overflow_owner(&uid_map, &gid_map, &status, overflow_uid) == Some(owner))
        .then_some(true)
}

#[cfg(target_os = "linux")]
fn namespace_overflow_owner(
    uid_map: &str,
    gid_map: &str,
    status: &str,
    overflow_uid: u32,
) -> Option<u32> {
    let mapped_user = single_identity_mapping(uid_map)?;
    let mapped_group = single_identity_mapping(gid_map)?;
    if overflow_uid == 0
        || overflow_uid == mapped_user
        || effective_identity(status, "Uid:") != Some(mapped_user)
        || effective_identity(status, "Gid:") != Some(mapped_group)
    {
        return None;
    }
    Some(overflow_uid)
}

#[cfg(target_os = "linux")]
fn single_identity_mapping(mapping: &str) -> Option<u32> {
    let mut lines = mapping.lines().filter(|line| !line.trim().is_empty());
    let mut fields = lines.next()?.split_whitespace();
    let inside = fields.next()?.parse::<u32>().ok()?;
    let _outside = fields.next()?.parse::<u32>().ok()?;
    let length = fields.next()?.parse::<u64>().ok()?;
    if fields.next().is_some() || lines.next().is_some() || inside == 0 || length != 1 {
        return None;
    }
    Some(inside)
}

#[cfg(target_os = "linux")]
fn effective_identity(status: &str, field: &str) -> Option<u32> {
    let mut values = status
        .lines()
        .find_map(|line| line.strip_prefix(field))?
        .split_whitespace();
    values.next()?.parse::<u32>().ok()?;
    let effective = values.next()?.parse::<u32>().ok()?;
    values.next()?.parse::<u32>().ok()?;
    values.next()?.parse::<u32>().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(effective)
}

#[cfg(target_os = "linux")]
fn path_is_on_read_only_mount(path: &Path) -> bool {
    rustix::fs::statvfs(path).is_ok_and(|status| {
        status
            .f_flag
            .contains(rustix::fs::StatVfsMountFlags::RDONLY)
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
const fn path_is_on_read_only_mount(_path: &Path) -> bool {
    false
}

#[cfg(not(unix))]
fn platform_trust(_path: &Path) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::is_trusted_system_executable;
    #[cfg(target_os = "linux")]
    use super::{effective_identity, namespace_overflow_owner, single_identity_mapping};
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn installed_command_is_trusted_but_writable_copy_is_not() {
        let installed = fs::canonicalize("/usr/bin/mkdir").expect("installed mkdir");
        assert!(is_trusted_system_executable(&installed));
        let home = tempfile::tempdir().expect("command fixture home");
        let copied = home.path().join("mkdir");
        fs::copy(&installed, &copied).expect("copy command fixture");
        fs::set_permissions(&copied, fs::Permissions::from_mode(0o777))
            .expect("make command fixture untrusted");
        assert!(!is_trusted_system_executable(&copied));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn single_identity_namespace_evidence_is_exact_and_bounded() {
        assert_eq!(single_identity_mapping(" 1000 1000 1\n"), Some(1000));
        assert_eq!(single_identity_mapping(" 1000 1001 1\n"), Some(1000));
        assert_eq!(single_identity_mapping(" 1000 0 1\n"), Some(1000));
        assert_eq!(single_identity_mapping(" 0 1000 1\n"), None);
        assert_eq!(single_identity_mapping(" 1000 1000 2\n"), None);
        assert_eq!(
            single_identity_mapping(" 1000 1000 1\n 2000 2000 1\n"),
            None
        );
        assert_eq!(single_identity_mapping("malformed"), None);

        let status = "Name:\tprobe\nUid:\t1000\t1000\t1000\t1000\n\
                      Gid:\t100\t100\t100\t100\n";
        assert_eq!(effective_identity(status, "Uid:"), Some(1000));
        assert_eq!(effective_identity(status, "Gid:"), Some(100));
        assert_eq!(effective_identity(status, "Groups:"), None);
        assert_eq!(
            namespace_overflow_owner("1000 1000 1", "100 100 1", status, 65534),
            Some(65534)
        );
        assert_eq!(
            namespace_overflow_owner("1000 0 1", "100 0 1", status, 65534),
            Some(65534)
        );
        assert_eq!(
            namespace_overflow_owner("1000 1000 1", "100 100 1", status, 1000),
            None
        );
        assert_eq!(
            namespace_overflow_owner(
                "1000 1000 1",
                "100 100 1",
                "Uid:\t1000\t1001\t1000\t1000\nGid:\t100\t100\t100\t100\n",
                65534
            ),
            None
        );
    }
}

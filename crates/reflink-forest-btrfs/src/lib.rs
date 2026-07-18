//! Safe orchestration primitives for the Btrfs materialization domain.
//!
//! Formatting, loop attachment, and mounting are intentionally outside this
//! unprivileged crate. A fixed-purpose privileged helper may invoke these
//! checked plans only after independently validating the configured instance.

use std::{
    ffi::{CString, OsStr},
    fs, io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Command,
};

pub use reflink_forest_core::create_sparse_image;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLayout {
    pub mount_root: PathBuf,
    pub cache: PathBuf,
    pub staging: PathBuf,
    pub trash: PathBuf,
    pub workspaces: PathBuf,
}

#[derive(Debug)]
pub enum BtrfsError {
    Io(io::Error),
    InvalidMountRoot,
    NonEmptyTarget(PathBuf),
    NotBtrfs(PathBuf),
    SymlinkMountRoot(PathBuf),
    CommandFailed {
        program: &'static str,
        status: Option<i32>,
        stderr: String,
    },
}
impl std::fmt::Display for BtrfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Btrfs I/O error: {error}"),
            Self::InvalidMountRoot => write!(f, "mount root must be an existing directory"),
            Self::NonEmptyTarget(path) => write!(
                f,
                "refusing to initialize non-empty target: {}",
                path.display()
            ),
            Self::NotBtrfs(path) => write!(f, "mount root is not Btrfs: {}", path.display()),
            Self::SymlinkMountRoot(path) => {
                write!(f, "mount root may not be a symlink: {}", path.display())
            }
            Self::CommandFailed {
                program,
                status,
                stderr,
            } => write!(f, "{program} failed ({status:?}): {stderr}"),
        }
    }
}
impl std::error::Error for BtrfsError {}
impl From<io::Error> for BtrfsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Validates a mount root and derives the one-root clone-domain topology.
/// Cache, staging, trash, and workspaces stay under the same mount so that the
/// runtime FICLONE probe tests exactly the paths production will use.
pub fn native_layout(mount_root: impl AsRef<Path>) -> Result<NativeLayout, BtrfsError> {
    let mount_root = mount_root.as_ref().to_path_buf();
    let metadata = fs::symlink_metadata(&mount_root)?;
    if metadata.file_type().is_symlink() {
        return Err(BtrfsError::SymlinkMountRoot(mount_root));
    }
    if !metadata.is_dir() {
        return Err(BtrfsError::InvalidMountRoot);
    }
    Ok(NativeLayout {
        cache: mount_root.join("internal/cache"),
        staging: mount_root.join("internal/staging"),
        trash: mount_root.join("internal/trash"),
        workspaces: mount_root.join("workspaces"),
        mount_root,
    })
}

/// Verifies that the configured root resides on a Btrfs filesystem before any
/// subvolume operation. This is a mount identity guard, not a replacement for
/// the runtime FICLONE cache-to-workspace probe.
pub fn verify_btrfs_mount(mount_root: impl AsRef<Path>) -> Result<(), BtrfsError> {
    const BTRFS_SUPER_MAGIC: libc::c_long = 0x9123_683e_u64 as libc::c_long;
    let mount_root = mount_root.as_ref();
    let metadata = fs::symlink_metadata(mount_root)?;
    if metadata.file_type().is_symlink() {
        return Err(BtrfsError::SymlinkMountRoot(mount_root.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(BtrfsError::InvalidMountRoot);
    }
    let path = CString::new(mount_root.as_os_str().as_bytes())
        .map_err(|_| BtrfsError::InvalidMountRoot)?;
    // SAFETY: `path` is NUL terminated and `stat` is valid writable storage.
    let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if stat.f_type != BTRFS_SUPER_MAGIC {
        return Err(BtrfsError::NotBtrfs(mount_root.to_path_buf()));
    }
    Ok(())
}

/// Creates an empty native layout using fixed `btrfs subvolume create`
/// arguments. It refuses any pre-existing target path and never calls a shell.
pub fn initialize_native(layout: &NativeLayout) -> Result<(), BtrfsError> {
    verify_btrfs_mount(&layout.mount_root)?;
    for path in [
        &layout.cache,
        &layout.staging,
        &layout.trash,
        &layout.workspaces,
    ] {
        if path.exists() {
            return Err(BtrfsError::NonEmptyTarget(path.clone()));
        }
    }
    fs::create_dir_all(layout.mount_root.join("internal"))?;
    for path in [
        &layout.cache,
        &layout.staging,
        &layout.trash,
        &layout.workspaces,
    ] {
        run_btrfs_subvolume_create(path)?;
    }
    Ok(())
}

fn run_btrfs_subvolume_create(path: &Path) -> Result<(), BtrfsError> {
    let output = Command::new("btrfs")
        .arg(OsStr::new("subvolume"))
        .arg(OsStr::new("create"))
        .arg(path)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(BtrfsError::CommandFailed {
        program: "btrfs subvolume create",
        status: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[test]
    fn layout_keeps_clone_paths_under_one_root() {
        let root = std::env::temp_dir().join(format!(
            "reflink-forest-btrfs-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let layout = native_layout(&root).unwrap();
        for path in [
            &layout.cache,
            &layout.staging,
            &layout.trash,
            &layout.workspaces,
        ] {
            assert!(path.starts_with(&root));
        }
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn non_btrfs_test_directory_is_rejected_before_initialization() {
        let root = std::env::temp_dir();
        assert!(matches!(
            verify_btrfs_mount(root),
            Err(BtrfsError::NotBtrfs(_))
        ));
    }
}

//! Safe orchestration primitives for the Btrfs materialization domain.
//!
//! Formatting, loop attachment, and mounting are intentionally outside this
//! unprivileged crate. A fixed-purpose privileged helper may invoke these
//! checked plans only after independently validating the configured instance.

use std::{
    ffi::{CString, OsStr},
    fs,
    io::{self, Write},
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
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
    ExistingPath(PathBuf),
    UnsafeImagePath(PathBuf),
    InvalidMarker,
    IdentityMismatch,
    DuplicateLoopAssociation(String),
    InvalidLoopDevice(String),
    InvalidSize,
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
            Self::ExistingPath(path) => {
                write!(f, "refusing to overwrite existing path: {}", path.display())
            }
            Self::UnsafeImagePath(path) => {
                write!(f, "unsafe backing-image path: {}", path.display())
            }
            Self::InvalidMarker => write!(f, "invalid Reflink Forest instance marker"),
            Self::IdentityMismatch => {
                write!(f, "Btrfs identity does not match the instance marker")
            }
            Self::DuplicateLoopAssociation(device) => {
                write!(f, "backing image is already attached to {device}")
            }
            Self::InvalidLoopDevice(device) => write!(f, "invalid loop device: {device}"),
            Self::InvalidSize => write!(f, "image size must be non-zero"),
        }
    }
}

/// Allocation policy selected only during explicit instance initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageAllocation {
    Sparse,
    Reserved,
}

/// Stable identity stored beside the configured image. It is checked before a
/// privileged helper attaches or mounts an image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceMarker {
    /// Stable Reflink Forest instance identifier, distinct from Btrfs's UUID.
    pub instance_uuid: [u8; 16],
    /// The exact formatted Btrfs filesystem expected by this instance.
    pub filesystem_uuid: [u8; 16],
    pub label: String,
}
const MARKER_MAGIC: &[u8; 8] = b"RFSINST\0";
const MARKER_VERSION: u16 = 1;
const MARKER_FIXED_LEN: usize = 8 + 2 + 16 + 16 + 2;
const FICLONE: std::ffi::c_ulong = 0x4004_9409;

unsafe extern "C" {
    fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
}

/// Creates a new image only. The parent is canonicalized, the destination is
/// rejected if it exists (including a symlink), and no existing file is ever
/// truncated. `Reserved` uses `posix_fallocate`; `Sparse` extends logically.
pub fn initialize_loopback_image(
    path: impl AsRef<Path>,
    size: u64,
    allocation: ImageAllocation,
) -> Result<PathBuf, BtrfsError> {
    if size == 0 {
        return Err(BtrfsError::InvalidSize);
    }
    let path = checked_new_file_path(path.as_ref())?;
    match allocation {
        ImageAllocation::Sparse => reflink_forest_core::create_sparse_image(&path, size)?,
        ImageAllocation::Reserved => {
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            // SAFETY: file descriptor is valid; no pointers are passed.
            use std::os::fd::AsRawFd;
            let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, size as libc::off_t) };
            if result != 0 {
                let _ = fs::remove_file(&path);
                return Err(io::Error::from_raw_os_error(result).into());
            }
            file.sync_all()?;
            fs::File::open(path.parent().expect("checked parent"))?.sync_all()?;
        }
    }
    Ok(path)
}

/// Writes a marker once, using an explicit binary v1 format and durable rename
/// semantics supplied by `create_new` plus file/directory sync.
pub fn write_instance_marker(
    path: impl AsRef<Path>,
    marker: &InstanceMarker,
) -> Result<PathBuf, BtrfsError> {
    if marker.label.is_empty() || marker.label.len() > u16::MAX as usize {
        return Err(BtrfsError::InvalidMarker);
    }
    let path = checked_new_file_path(path.as_ref())?;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(MARKER_MAGIC)?;
    file.write_all(&MARKER_VERSION.to_be_bytes())?;
    file.write_all(&marker.instance_uuid)?;
    file.write_all(&marker.filesystem_uuid)?;
    file.write_all(&(marker.label.len() as u16).to_be_bytes())?;
    file.write_all(marker.label.as_bytes())?;
    file.sync_all()?;
    fs::File::open(path.parent().expect("checked parent"))?.sync_all()?;
    Ok(path)
}
pub fn read_instance_marker(path: impl AsRef<Path>) -> Result<InstanceMarker, BtrfsError> {
    let metadata = fs::symlink_metadata(path.as_ref())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BtrfsError::InvalidMarker);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| BtrfsError::InvalidMarker)?;
    if !(MARKER_FIXED_LEN..=MARKER_FIXED_LEN + usize::from(u16::MAX)).contains(&length) {
        return Err(BtrfsError::InvalidMarker);
    }
    let data = fs::read(path)?;
    if data.len() < MARKER_FIXED_LEN
        || &data[..8] != MARKER_MAGIC
        || u16::from_be_bytes([data[8], data[9]]) != MARKER_VERSION
    {
        return Err(BtrfsError::InvalidMarker);
    }
    let length = u16::from_be_bytes([data[42], data[43]]) as usize;
    if data.len() != MARKER_FIXED_LEN + length {
        return Err(BtrfsError::InvalidMarker);
    }
    let mut instance_uuid = [0; 16];
    instance_uuid.copy_from_slice(&data[10..26]);
    let mut filesystem_uuid = [0; 16];
    filesystem_uuid.copy_from_slice(&data[26..42]);
    let label = String::from_utf8(data[MARKER_FIXED_LEN..].to_vec())
        .map_err(|_| BtrfsError::InvalidMarker)?;
    if label.is_empty() {
        return Err(BtrfsError::InvalidMarker);
    }
    Ok(InstanceMarker {
        instance_uuid,
        filesystem_uuid,
        label,
    })
}

/// Confirms the observed Btrfs UUID and label before a helper mounts the
/// configured instance. A marker is never used as evidence that an arbitrary
/// image is safe to mount.
pub fn verify_instance_identity(
    marker: &InstanceMarker,
    filesystem_uuid: [u8; 16],
    label: &str,
) -> Result<(), BtrfsError> {
    if marker.filesystem_uuid == filesystem_uuid && marker.label == label {
        Ok(())
    } else {
        Err(BtrfsError::IdentityMismatch)
    }
}

/// Parses the canonical hyphenated Btrfs UUID used by `btrfs filesystem show`
/// and `blkid`, without accepting surrounding command output or path data.
pub fn parse_filesystem_uuid(value: &str) -> Option<[u8; 16]> {
    if value.len() != 36 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    let mut pair = [0_u8; 2];
    let mut index = 0;
    for (position, byte) in value.bytes().enumerate() {
        if matches!(position, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
            continue;
        }
        if index >= bytes.len() * 2 {
            return None;
        }
        pair[index % 2] = byte;
        if index % 2 == 1 {
            bytes[index / 2] = hex_pair(pair)?;
        }
        index += 1;
    }
    (index == bytes.len() * 2).then_some(bytes)
}

fn hex_pair(pair: [u8; 2]) -> Option<u8> {
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
    Some(nibble(pair[0])? << 4 | nibble(pair[1])?)
}

/// Result of the mandatory cache-to-staging clone-domain check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloneDomainProbe {
    pub reflink_succeeded: bool,
    pub mutation_isolated: bool,
}

/// Performs the actual FICLONE and copy-on-write isolation probe on the exact
/// cache and staging roots that will serve workspaces. Both roots must already
/// exist and must not be symlinks. Any syscall or verification failure is an
/// error so startup fails closed unless a higher-level copy-fallback policy
/// explicitly handles it.
pub fn probe_clone_domain(
    cache_root: impl AsRef<Path>,
    staging_root: impl AsRef<Path>,
) -> Result<CloneDomainProbe, BtrfsError> {
    let cache_root = checked_probe_root(cache_root.as_ref())?;
    let staging_root = checked_probe_root(staging_root.as_ref())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_nanos();
    let source_path = cache_root.join(format!(".reflink-forest-probe-{nonce}"));
    let destination_path = staging_root.join(format!(".reflink-forest-probe-{nonce}"));
    let source_bytes = b"reflink-forest source bytes";
    let changed_bytes = b"reflink-forest changed-byte";
    let result = (|| -> Result<CloneDomainProbe, BtrfsError> {
        let mut source = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source_path)?;
        source.write_all(source_bytes)?;
        source.sync_all()?;
        let destination = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&destination_path)?;
        // SAFETY: both descriptors are regular freshly-created files and
        // FICLONE only consumes the source descriptor during this call.
        if unsafe { ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        drop(destination);
        drop(source);
        if fs::read(&destination_path)? != source_bytes {
            return Err(BtrfsError::IdentityMismatch);
        }
        let mut destination = fs::OpenOptions::new().write(true).open(&destination_path)?;
        destination.write_all(changed_bytes)?;
        destination.sync_all()?;
        drop(destination);
        if fs::read(&source_path)? != source_bytes {
            return Err(BtrfsError::IdentityMismatch);
        }
        Ok(CloneDomainProbe {
            reflink_succeeded: true,
            mutation_isolated: true,
        })
    })();
    let source_removed = fs::remove_file(&source_path);
    let destination_removed = fs::remove_file(&destination_path);
    if source_removed.is_ok() {
        fs::File::open(&cache_root)?.sync_all()?;
    }
    if destination_removed.is_ok() {
        fs::File::open(&staging_root)?.sync_all()?;
    }
    result
}

fn checked_probe_root(path: &Path) -> Result<PathBuf, BtrfsError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(BtrfsError::SymlinkMountRoot(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(BtrfsError::InvalidMountRoot);
    }
    Ok(path.canonicalize()?)
}

fn checked_new_file_path(path: &Path) -> Result<PathBuf, BtrfsError> {
    let parent = path
        .parent()
        .ok_or_else(|| BtrfsError::UnsafeImagePath(path.to_path_buf()))?
        .canonicalize()?;
    if !parent.is_dir() || path.file_name().is_none() {
        return Err(BtrfsError::UnsafeImagePath(path.to_path_buf()));
    }
    let result = parent.join(path.file_name().expect("checked file name"));
    if fs::symlink_metadata(&result).is_ok() {
        return Err(BtrfsError::ExistingPath(result));
    }
    Ok(result)
}

/// Returns the canonical configured image after rejecting symlinks and images
/// outside its configured canonical parent.
pub fn validate_backing_image(
    image: impl AsRef<Path>,
    configured_parent: impl AsRef<Path>,
) -> Result<PathBuf, BtrfsError> {
    let parent = configured_parent.as_ref().canonicalize()?;
    let metadata = fs::symlink_metadata(image.as_ref())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BtrfsError::UnsafeImagePath(image.as_ref().to_path_buf()));
    }
    let image = image.as_ref().canonicalize()?;
    if !image.starts_with(&parent) {
        return Err(BtrfsError::UnsafeImagePath(image));
    }
    Ok(image)
}

/// Fixed-purpose privileged operations. No variant contains a client supplied
/// program name or arbitrary argument vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivilegedPlan {
    AttachLoop { image: PathBuf },
    Mount { device: String, mount_root: PathBuf },
    GrowImage { image: PathBuf, size: u64 },
}
impl PrivilegedPlan {
    pub fn attach(
        image: impl AsRef<Path>,
        configured_parent: impl AsRef<Path>,
        losetup_output: &str,
    ) -> Result<Self, BtrfsError> {
        let image = validate_backing_image(image, configured_parent)?;
        if let Some(device) = parse_loop_association(losetup_output) {
            return Err(BtrfsError::DuplicateLoopAssociation(device));
        }
        Ok(Self::AttachLoop { image })
    }
    pub fn mount(device: &str, mount_root: impl AsRef<Path>) -> Result<Self, BtrfsError> {
        if !is_loop_device(device) {
            return Err(BtrfsError::InvalidLoopDevice(device.into()));
        }
        let metadata = fs::symlink_metadata(mount_root.as_ref())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BtrfsError::InvalidMountRoot);
        }
        Ok(Self::Mount {
            device: device.into(),
            mount_root: mount_root.as_ref().canonicalize()?,
        })
    }
    pub fn grow(
        image: impl AsRef<Path>,
        configured_parent: impl AsRef<Path>,
        size: u64,
    ) -> Result<Self, BtrfsError> {
        if size == 0 {
            return Err(BtrfsError::InvalidSize);
        }
        Ok(Self::GrowImage {
            image: validate_backing_image(image, configured_parent)?,
            size,
        })
    }
    pub fn command(&self) -> Command {
        match self {
            Self::AttachLoop { image } => {
                let mut command = Command::new("losetup");
                command.args(["--find", "--show", "--nooverlap"]).arg(image);
                command
            }
            Self::Mount { device, mount_root } => {
                let mut command = Command::new("mount");
                command
                    .args(["-t", "btrfs", "-o", "noatime,compress=zstd"])
                    .arg(device)
                    .arg(mount_root);
                command
            }
            Self::GrowImage { image, size } => {
                let mut command = Command::new("truncate");
                command.arg("--size").arg(size.to_string()).arg(image);
                command
            }
        }
    }
}
fn is_loop_device(device: &str) -> bool {
    device
        .strip_prefix("/dev/loop")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}
/// Parses `losetup -j <image>` output. A nonempty line means the image is
/// associated; malformed lines deliberately do not yield a trusted device.
pub fn parse_loop_association(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (device, _) = line.split_once(':')?;
        is_loop_device(device).then(|| device.to_owned())
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorStatus {
    Supported,
    Unsupported,
    Inconclusive,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorDiagnostics {
    pub clone_domain: DoctorStatus,
    pub discard_reclamation: DoctorStatus,
    pub host_free_bytes: Option<u64>,
    pub guest_free_bytes: Option<u64>,
    pub notes: Vec<String>,
}
/// Parses the numeric `df -B1 --output=avail` body emitted by a constrained
/// helper. Missing/unparseable values are reported as inconclusive, never 0.
pub fn parse_available_bytes(output: &str) -> Option<u64> {
    output
        .lines()
        .skip(1)
        .find_map(|line| line.trim().parse().ok())
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

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn image_initialization_is_create_new_and_marker_round_trips() {
        let parent = temp_path("reflink-forest-image");
        fs::create_dir(&parent).unwrap();
        let image = parent.join("hot.btrfs");
        let created = initialize_loopback_image(&image, 4096, ImageAllocation::Sparse).unwrap();
        assert_eq!(created, image);
        assert_eq!(fs::metadata(&image).unwrap().len(), 4096);
        assert!(matches!(
            initialize_loopback_image(&image, 4096, ImageAllocation::Sparse),
            Err(BtrfsError::ExistingPath(_))
        ));
        let marker = InstanceMarker {
            instance_uuid: [4; 16],
            filesystem_uuid: [5; 16],
            label: "test-instance".into(),
        };
        let marker_path = parent.join("instance.marker");
        write_instance_marker(&marker_path, &marker).unwrap();
        assert_eq!(read_instance_marker(&marker_path).unwrap(), marker);
        assert!(verify_instance_identity(&marker, [5; 16], "test-instance").is_ok());
        assert!(matches!(
            verify_instance_identity(&marker, [6; 16], "test-instance"),
            Err(BtrfsError::IdentityMismatch)
        ));
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn canonical_filesystem_uuid_parser_is_strict() {
        assert_eq!(
            parse_filesystem_uuid("00112233-4455-6677-8899-aabbccddeeff"),
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        assert_eq!(
            parse_filesystem_uuid("00112233445566778899aabbccddeeff"),
            None
        );
        assert_eq!(
            parse_filesystem_uuid("00112233-4455-6677-8899-aabbccddeefg"),
            None
        );
    }

    #[test]
    fn clone_domain_probe_checks_real_reflink_and_cow_when_supported() {
        let root = std::env::current_dir().unwrap().join(format!(
            ".reflink-forest-btrfs-probe-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cache = root.join("cache");
        let staging = root.join("staging");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&cache).unwrap();
        fs::create_dir(&staging).unwrap();
        match probe_clone_domain(&cache, &staging) {
            Ok(probe) => {
                assert!(probe.reflink_succeeded);
                assert!(probe.mutation_isolated);
            }
            Err(BtrfsError::Io(error)) if matches!(error.raw_os_error(), Some(18) | Some(95)) => {}
            Err(error) => panic!("clone-domain probe failed unexpectedly: {error}"),
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn association_parser_and_fixed_plans_reject_unsafe_input() {
        assert_eq!(
            parse_loop_association("/dev/loop7: [123]:4 (/var/lib/rfs/hot.btrfs)\n"),
            Some("/dev/loop7".into())
        );
        assert_eq!(parse_loop_association("not-a-device: x"), None);
        let parent = temp_path("reflink-forest-plan");
        fs::create_dir(&parent).unwrap();
        let image =
            initialize_loopback_image(parent.join("hot.btrfs"), 4096, ImageAllocation::Sparse)
                .unwrap();
        assert!(matches!(
            PrivilegedPlan::attach(&image, &parent, "/dev/loop0: x"),
            Err(BtrfsError::DuplicateLoopAssociation(_))
        ));
        assert!(matches!(
            PrivilegedPlan::mount("/dev/sda", &parent),
            Err(BtrfsError::InvalidLoopDevice(_))
        ));
        let plan = PrivilegedPlan::attach(&image, &parent, "").unwrap();
        assert!(format!("{:?}", plan.command()).contains("losetup"));
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn doctor_parsers_do_not_invent_capacity() {
        assert_eq!(parse_available_bytes("Avail\n1048576\n"), Some(1_048_576));
        assert_eq!(parse_available_bytes("Avail\nunknown\n"), None);
    }
}

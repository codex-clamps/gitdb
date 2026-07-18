//! Safe orchestration primitives for the Btrfs materialization domain.
//!
//! Formatting, loop attachment, and mounting are intentionally outside this
//! unprivileged crate. A fixed-purpose privileged helper may invoke these
//! checked plans only after independently validating the configured instance.

use std::{
    ffi::{CString, OsStr, OsString},
    fs,
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
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
    LoopBackingMismatch {
        device: String,
        backing: PathBuf,
    },
    InvalidCommandOutput(&'static str),
    ShrinkNotSupported {
        current: u64,
        requested: u64,
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
            Self::LoopBackingMismatch { device, backing } => write!(
                f,
                "loop device {device} is associated with unexpected backing image: {}",
                backing.display()
            ),
            Self::InvalidCommandOutput(what) => {
                write!(f, "invalid fixed-purpose command output: {what}")
            }
            Self::ShrinkNotSupported { current, requested } => write!(
                f,
                "refusing to shrink Btrfs image from {current} to {requested} bytes"
            ),
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
    /// Enumerates loop device names. Each resulting backing path is inspected
    /// separately and canonicalized before it may be reused.
    ListLoops,
    AttachLoop {
        image: PathBuf,
    },
    InspectLoopBacking {
        device: String,
    },
    InspectFilesystem {
        device: String,
    },
    Mount {
        device: String,
        mount_root: PathBuf,
    },
    GrowImage {
        image: PathBuf,
        size: u64,
    },
    RefreshLoopCapacity {
        device: String,
    },
    ResizeFilesystem {
        mount_root: PathBuf,
    },
    /// Reads qgroup counters with raw byte units. This is diagnostic-only:
    /// the plan neither enables quotas nor changes qgroup limits.
    ShowQgroups {
        mount_root: PathBuf,
    },
    /// Asks the filesystem for a dry-run discard estimate. `fstrim --dry-run`
    /// performs no discard; its result is advisory and is not proof that
    /// cache eviction immediately returns blocks to the backing filesystem.
    ProbeTrim {
        mount_root: PathBuf,
    },
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
    /// Builds the fixed qgroup diagnostic plan for a configured mount root.
    /// This plan never enables quotas or creates/deletes qgroups.
    pub fn show_qgroups(mount_root: impl AsRef<Path>) -> Result<Self, BtrfsError> {
        Ok(Self::ShowQgroups {
            mount_root: checked_mount_root(mount_root.as_ref())?,
        })
    }
    /// Builds the fixed, non-mutating trim capability probe for a configured
    /// mount root. It deliberately has no offset, length, or device input.
    pub fn probe_trim(mount_root: impl AsRef<Path>) -> Result<Self, BtrfsError> {
        Ok(Self::ProbeTrim {
            mount_root: checked_mount_root(mount_root.as_ref())?,
        })
    }
    pub fn command(&self) -> Command {
        match self {
            Self::ListLoops => {
                let mut command = Command::new("losetup");
                command.arg("--all");
                command
            }
            Self::AttachLoop { image } => {
                let mut command = Command::new("losetup");
                command.args(["--find", "--show", "--nooverlap"]).arg(image);
                command
            }
            Self::InspectLoopBacking { device } => {
                let mut command = Command::new("losetup");
                command
                    .args(["--list", "--noheadings", "--raw", "--output", "BACK-FILE"])
                    .arg(device);
                command
            }
            Self::InspectFilesystem { device } => {
                let mut command = Command::new("blkid");
                command
                    .args(["--output", "export", "--match-token", "TYPE=btrfs"])
                    .arg(device);
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
            Self::RefreshLoopCapacity { device } => {
                let mut command = Command::new("losetup");
                command.args(["--set-capacity", device]);
                command
            }
            Self::ResizeFilesystem { mount_root } => {
                let mut command = Command::new("btrfs");
                command
                    .args(["filesystem", "resize", "max"])
                    .arg(mount_root);
                command
            }
            Self::ShowQgroups { mount_root } => {
                let mut command = Command::new("btrfs");
                command.args(["qgroup", "show", "--raw"]).arg(mount_root);
                command
            }
            Self::ProbeTrim { mount_root } => {
                let mut command = Command::new("fstrim");
                command.args(["--dry-run", "--verbose"]).arg(mount_root);
                command
            }
        }
    }

    fn program_name(&self) -> &'static str {
        match self {
            Self::ListLoops
            | Self::AttachLoop { .. }
            | Self::InspectLoopBacking { .. }
            | Self::RefreshLoopCapacity { .. } => "losetup",
            Self::InspectFilesystem { .. } => "blkid",
            Self::Mount { .. } => "mount",
            Self::GrowImage { .. } => "truncate",
            Self::ResizeFilesystem { .. } => "btrfs filesystem resize",
            Self::ShowQgroups { .. } => "btrfs qgroup show",
            Self::ProbeTrim { .. } => "fstrim --dry-run",
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

/// The only immutable inputs accepted by the privileged loop/mount helper.
/// The helper never receives a client-selected device, backing image,
/// mountpoint, or mount options. `new` canonicalizes and validates both paths
/// before any command can be executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivilegedExecutorConfig {
    image: PathBuf,
    mount_root: PathBuf,
    marker: InstanceMarker,
}

impl PrivilegedExecutorConfig {
    pub fn new(
        image: impl AsRef<Path>,
        configured_parent: impl AsRef<Path>,
        mount_root: impl AsRef<Path>,
        marker: InstanceMarker,
    ) -> Result<Self, BtrfsError> {
        if marker.label.is_empty()
            || marker.label.len() > usize::from(u16::MAX)
            || marker.label.contains(['\n', '\r'])
        {
            return Err(BtrfsError::InvalidMarker);
        }
        let image = validate_backing_image(image, configured_parent)?;
        // The command output protocol is line-delimited. Newlines in a
        // configured path would make it impossible to identify the exact
        // backing file without a lossy parser.
        if image.as_os_str().as_bytes().contains(&b'\n')
            || image.as_os_str().as_bytes().contains(&b'\r')
        {
            return Err(BtrfsError::UnsafeImagePath(image));
        }
        let mount_root = checked_mount_root(mount_root.as_ref())?;
        Ok(Self {
            image,
            mount_root,
            marker,
        })
    }

    pub fn image(&self) -> &Path {
        &self.image
    }

    pub fn mount_root(&self) -> &Path {
        &self.mount_root
    }

    pub fn marker(&self) -> &InstanceMarker {
        &self.marker
    }
}

/// Byte-preserving output of one command from the closed privileged command
/// vocabulary. The runner reports command failures as `BtrfsError`; successful
/// output is parsed by the executor with command-specific rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }
}

/// Injection boundary for the privileged helper. Implementations can only run
/// the fixed `PrivilegedPlan` variants, never a caller-provided program or
/// argument vector. Tests use this interface without loop or mount privileges.
pub trait CommandRunner {
    fn run(&mut self, plan: &PrivilegedPlan) -> Result<CommandOutput, BtrfsError>;
}

/// The production runner for the closed privileged command vocabulary.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, plan: &PrivilegedPlan) -> Result<CommandOutput, BtrfsError> {
        let output = plan.command().output()?;
        if output.status.success() {
            Ok(CommandOutput {
                stdout: output.stdout,
                stderr: output.stderr,
            })
        } else {
            Err(BtrfsError::CommandFailed {
                program: plan.program_name(),
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }
}

/// A parsed Btrfs identity reported by the inspected loop device, before a
/// mount is considered. It deliberately excludes mountpoint-derived data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedFilesystem {
    pub filesystem_uuid: [u8; 16],
    pub label: String,
}

/// Fixed-purpose privileged loop/Btrfs executor. All device selection is
/// derived from the configured canonical image. In particular, a loop device
/// is never persisted or supplied by the caller: after a reboot we inspect all
/// current associations and reuse only a canonical backing-path match.
pub struct PrivilegedExecutor<R> {
    config: PrivilegedExecutorConfig,
    runner: R,
}

impl<R: CommandRunner> PrivilegedExecutor<R> {
    pub fn new(config: PrivilegedExecutorConfig, runner: R) -> Self {
        Self { config, runner }
    }

    pub fn config(&self) -> &PrivilegedExecutorConfig {
        &self.config
    }

    pub fn into_runner(self) -> R {
        self.runner
    }

    /// Finds a pre-existing canonical association, or attaches the configured
    /// image with `--nooverlap` and verifies the returned association before it
    /// can be used. Multiple matching loop devices are rejected rather than
    /// selecting an arbitrary transient loop number.
    pub fn attach_or_reuse(&mut self) -> Result<String, BtrfsError> {
        let output = self.run(&PrivilegedPlan::ListLoops)?;
        let mut matches = Vec::new();
        for device in parse_loop_device_listing(&output.stdout)? {
            let backing = self.inspect_loop_backing(&device)?;
            if backing == self.config.image {
                matches.push(device);
            }
        }
        match matches.as_slice() {
            [device] => Ok(device.clone()),
            [] => {
                let output = self.run(&PrivilegedPlan::AttachLoop {
                    image: self.config.image.clone(),
                })?;
                let device = parse_attached_loop_device(&output.stdout)?;
                let backing = self.inspect_loop_backing(&device)?;
                if backing != self.config.image {
                    return Err(BtrfsError::LoopBackingMismatch { device, backing });
                }
                Ok(device)
            }
            // Keep the historical error type so older callers retain their
            // duplicate-association handling, while refusing to guess.
            [_, duplicate, ..] => Err(BtrfsError::DuplicateLoopAssociation(duplicate.clone())),
        }
    }

    /// Inspects the Btrfs UUID and label on the derived loop device, compares
    /// both to the instance marker, and only then executes the fixed mount
    /// plan. Failed identity checks execute no mount command.
    pub fn mount(&mut self) -> Result<String, BtrfsError> {
        let device = self.attach_or_reuse()?;
        self.verify_loop_identity(&device)?;
        self.run(&PrivilegedPlan::Mount {
            device: device.clone(),
            mount_root: self.config.mount_root.clone(),
        })?;
        Ok(device)
    }

    /// Grows only (never shrinks) the configured image. The ordering is
    /// deliberate and observable: file length first, loop capacity refresh
    /// second, then the Btrfs filesystem resize at the configured mount root.
    pub fn grow(&mut self, size: u64) -> Result<(), BtrfsError> {
        if size == 0 {
            return Err(BtrfsError::InvalidSize);
        }
        let current = fs::metadata(&self.config.image)?.len();
        if size <= current {
            return Err(BtrfsError::ShrinkNotSupported {
                current,
                requested: size,
            });
        }
        let device = self.attach_or_reuse()?;
        self.verify_loop_identity(&device)?;
        self.run(&PrivilegedPlan::GrowImage {
            image: self.config.image.clone(),
            size,
        })?;
        self.run(&PrivilegedPlan::RefreshLoopCapacity { device })?;
        self.run(&PrivilegedPlan::ResizeFilesystem {
            mount_root: self.config.mount_root.clone(),
        })?;
        Ok(())
    }

    fn run(&mut self, plan: &PrivilegedPlan) -> Result<CommandOutput, BtrfsError> {
        self.runner.run(plan)
    }

    fn inspect_loop_backing(&mut self, device: &str) -> Result<PathBuf, BtrfsError> {
        let output = self.run(&PrivilegedPlan::InspectLoopBacking {
            device: device.to_owned(),
        })?;
        let backing = parse_single_backing_path(&output.stdout)?;
        backing.canonicalize().map_err(BtrfsError::Io)
    }

    fn verify_loop_identity(&mut self, device: &str) -> Result<InspectedFilesystem, BtrfsError> {
        let output = self.run(&PrivilegedPlan::InspectFilesystem {
            device: device.to_owned(),
        })?;
        let inspected = parse_blkid_export_identity(&output.stdout)?;
        verify_instance_identity(
            &self.config.marker,
            inspected.filesystem_uuid,
            &inspected.label,
        )?;
        Ok(inspected)
    }
}

fn checked_mount_root(path: &Path) -> Result<PathBuf, BtrfsError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BtrfsError::InvalidMountRoot);
    }
    Ok(path.canonicalize()?)
}

fn parse_loop_device_listing(output: &[u8]) -> Result<Vec<String>, BtrfsError> {
    let output = std::str::from_utf8(output)
        .map_err(|_| BtrfsError::InvalidCommandOutput("losetup --all is not UTF-8"))?;
    let mut devices = Vec::new();
    for line in output.lines() {
        let (device, _) = line
            .split_once(':')
            .ok_or(BtrfsError::InvalidCommandOutput(
                "malformed losetup --all line",
            ))?;
        if !is_loop_device(device) || devices.iter().any(|known| known == device) {
            return Err(BtrfsError::InvalidCommandOutput(
                "invalid or duplicate loop device",
            ));
        }
        devices.push(device.to_owned());
    }
    Ok(devices)
}

fn parse_attached_loop_device(output: &[u8]) -> Result<String, BtrfsError> {
    let output = std::str::from_utf8(output)
        .map_err(|_| BtrfsError::InvalidCommandOutput("losetup device is not UTF-8"))?;
    let device = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    if !is_loop_device(device) || device.is_empty() {
        return Err(BtrfsError::InvalidCommandOutput(
            "invalid losetup --show device",
        ));
    }
    Ok(device.to_owned())
}

fn parse_single_backing_path(output: &[u8]) -> Result<PathBuf, BtrfsError> {
    let output = output
        .strip_suffix(b"\r\n")
        .or_else(|| output.strip_suffix(b"\n"))
        .unwrap_or(output);
    if output.is_empty() || output.contains(&b'\n') || output.contains(&b'\r') {
        return Err(BtrfsError::InvalidCommandOutput(
            "invalid loop backing path",
        ));
    }
    Ok(PathBuf::from(OsString::from_vec(output.to_vec())))
}

/// Parses the narrow `blkid --output export --match-token TYPE=btrfs` result.
/// Duplicate fields, a missing `TYPE=btrfs`, or noncanonical UUIDs are all
/// rejected before marker comparison.
pub fn parse_blkid_export_identity(output: &[u8]) -> Result<InspectedFilesystem, BtrfsError> {
    let output = std::str::from_utf8(output)
        .map_err(|_| BtrfsError::InvalidCommandOutput("blkid output is not UTF-8"))?;
    let mut uuid = None;
    let mut label = None;
    let mut btrfs = false;
    for line in output.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or(BtrfsError::InvalidCommandOutput(
                "malformed blkid export line",
            ))?;
        match key {
            "UUID" => {
                if uuid
                    .replace(
                        parse_filesystem_uuid(value)
                            .ok_or(BtrfsError::InvalidCommandOutput("invalid Btrfs UUID"))?,
                    )
                    .is_some()
                {
                    return Err(BtrfsError::InvalidCommandOutput("duplicate Btrfs UUID"));
                }
            }
            "LABEL" => {
                if label.replace(value.to_owned()).is_some() {
                    return Err(BtrfsError::InvalidCommandOutput("duplicate Btrfs label"));
                }
            }
            "TYPE" if value == "btrfs" => btrfs = true,
            "TYPE" => return Err(BtrfsError::InvalidCommandOutput("non-Btrfs blkid type")),
            _ => {}
        }
    }
    if !btrfs {
        return Err(BtrfsError::InvalidCommandOutput("missing Btrfs type"));
    }
    Ok(InspectedFilesystem {
        filesystem_uuid: uuid.ok_or(BtrfsError::InvalidCommandOutput("missing Btrfs UUID"))?,
        label: label.ok_or(BtrfsError::InvalidCommandOutput("missing Btrfs label"))?,
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

/// The result of a Btrfs capability diagnostic. Diagnostics are deliberately
/// three-valued: a failed query is not treated as either a disabled feature or
/// evidence that the feature is available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticOutcome<T> {
    /// The command completed and its narrowly specified output was parsed.
    Supported(T),
    /// The command reported a known, stable unsupported/disabled condition.
    Unsupported,
    /// Permission failures, I/O failures, malformed output, or an unfamiliar
    /// command failure. Operators must not make capacity decisions from this.
    Unknown,
}

impl<T> DiagnosticOutcome<T> {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

/// A kernel qgroup identifier in the `level/subvolume-id` representation used
/// by `btrfs qgroup show`. The daemon only reads these counters; it never
/// creates qgroups or changes quota limits as part of diagnosis.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QgroupId {
    pub level: u64,
    pub subvolume_id: u64,
}

/// Raw qgroup counters emitted by the constrained `btrfs qgroup show --raw`
/// plan. A `None` limit is the command's `none` value, not zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QgroupUsage {
    pub id: QgroupId,
    pub referenced_bytes: u64,
    pub exclusive_bytes: u64,
    pub max_referenced_bytes: Option<u64>,
    pub max_exclusive_bytes: Option<u64>,
}

/// The byte count estimated by `fstrim --dry-run --verbose`. It is an
/// advisory filesystem/device discard estimate, not a promise that deleting
/// cache entries has already returned backing-image allocation to the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrimDiagnostics {
    pub reclaimable_bytes: u64,
}

/// Parses the output of the fixed `btrfs qgroup show --raw <mount-root>`
/// diagnostic plan. It recognizes the command's stable "quotas disabled" and
/// "not supported" errors as `Unsupported`; permissions, I/O, and malformed
/// output remain explicitly `Unknown`.
///
/// The parser accepts the standard heading and separator lines but requires
/// every data line to contain precisely the five raw columns selected by the
/// fixed plan. This prevents a differently shaped invocation from being
/// silently interpreted as an authoritative quota report.
pub fn parse_qgroup_diagnostics(
    stdout: &[u8],
    stderr: &[u8],
    success: bool,
) -> DiagnosticOutcome<Vec<QgroupUsage>> {
    if !success {
        return diagnostic_failure_kind(stderr, stdout);
    }
    let Ok(output) = std::str::from_utf8(stdout) else {
        return DiagnosticOutcome::Unknown;
    };
    let mut qgroups = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("qgroupid") || is_qgroup_separator(line) {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let (
            Some(id),
            Some(referenced_bytes),
            Some(exclusive_bytes),
            Some(max_referenced_bytes),
            Some(max_exclusive_bytes),
            None,
        ) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        )
        else {
            return DiagnosticOutcome::Unknown;
        };
        let Some(id) = parse_qgroup_id(id) else {
            return DiagnosticOutcome::Unknown;
        };
        let (Ok(referenced_bytes), Ok(exclusive_bytes)) =
            (referenced_bytes.parse(), exclusive_bytes.parse())
        else {
            return DiagnosticOutcome::Unknown;
        };
        let (Some(max_referenced_bytes), Some(max_exclusive_bytes)) = (
            parse_qgroup_limit(max_referenced_bytes),
            parse_qgroup_limit(max_exclusive_bytes),
        ) else {
            return DiagnosticOutcome::Unknown;
        };
        qgroups.push(QgroupUsage {
            id,
            referenced_bytes,
            exclusive_bytes,
            max_referenced_bytes,
            max_exclusive_bytes,
        });
    }
    DiagnosticOutcome::Supported(qgroups)
}

/// Parses the output of the fixed `fstrim --dry-run --verbose <mount-root>`
/// plan. A parsed zero is still `Supported`: it means the filesystem accepted
/// the probe and reported no current discardable bytes. The parser does not
/// execute a trim and callers must never use the estimate as an accounting
/// substitute for host/guest free-space measurements.
pub fn parse_trim_diagnostics(
    stdout: &[u8],
    stderr: &[u8],
    success: bool,
) -> DiagnosticOutcome<TrimDiagnostics> {
    if !success {
        return diagnostic_failure_kind(stderr, stdout);
    }
    let Ok(output) = std::str::from_utf8(stdout) else {
        return DiagnosticOutcome::Unknown;
    };
    let mut estimate = None;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let Some(value) = parse_trim_line(line) else {
            return DiagnosticOutcome::Unknown;
        };
        if estimate.replace(value).is_some() {
            return DiagnosticOutcome::Unknown;
        }
    }
    estimate
        .map(|reclaimable_bytes| {
            DiagnosticOutcome::Supported(TrimDiagnostics { reclaimable_bytes })
        })
        .unwrap_or(DiagnosticOutcome::Unknown)
}

fn diagnostic_failure_kind<T>(stderr: &[u8], stdout: &[u8]) -> DiagnosticOutcome<T> {
    const UNSUPPORTED_MESSAGES: [&[u8]; 7] = [
        b"quota not enabled",
        b"quotas not enabled",
        b"qgroup not enabled",
        b"quotas are not enabled",
        b"operation not supported",
        b"discard operation is not supported",
        b"not supported",
    ];
    if UNSUPPORTED_MESSAGES.iter().any(|message| {
        contains_ascii_case_insensitive(stderr, message)
            || contains_ascii_case_insensitive(stdout, message)
    }) {
        DiagnosticOutcome::Unsupported
    } else {
        DiagnosticOutcome::Unknown
    }
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(actual, expected)| actual.to_ascii_lowercase() == *expected)
    })
}

fn parse_qgroup_id(value: &str) -> Option<QgroupId> {
    let (level, subvolume_id) = value.split_once('/')?;
    Some(QgroupId {
        level: level.parse().ok()?,
        subvolume_id: subvolume_id.parse().ok()?,
    })
}

fn parse_qgroup_limit(value: &str) -> Option<Option<u64>> {
    if value == "none" {
        Some(None)
    } else {
        value.parse().ok().map(Some)
    }
}

fn is_qgroup_separator(line: &str) -> bool {
    line.bytes()
        .all(|byte| byte == b'-' || byte.is_ascii_whitespace())
}

fn parse_trim_line(line: &str) -> Option<u64> {
    let (mount_root, estimate) = line.split_once(':')?;
    if mount_root.is_empty() {
        return None;
    }
    let estimate = estimate.trim();
    let estimate = estimate.strip_suffix("(dry run) trimmed")?.trim_end();
    let mut fields = estimate.split_ascii_whitespace();
    let number = fields.next()?;
    let unit = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    parse_trim_bytes(number, trim_unit_multiplier(unit)?)
}

fn parse_trim_bytes(number: &str, multiplier: u64) -> Option<u64> {
    let (whole, fractional) = match number.split_once('.') {
        Some((whole, fractional)) if !fractional.is_empty() && fractional.len() <= 6 => {
            (whole, Some(fractional))
        }
        Some(_) => return None,
        None => (number, None),
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let whole = whole.parse::<u64>().ok()?.checked_mul(multiplier)?;
    let Some(fractional) = fractional else {
        return Some(whole);
    };
    if !fractional.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let scale = 10_u64.checked_pow(fractional.len() as u32)?;
    let fractional = fractional.parse::<u64>().ok()?;
    let fraction = fractional.checked_mul(multiplier)?.checked_div(scale)?;
    whole.checked_add(fraction)
}

fn trim_unit_multiplier(unit: &str) -> Option<u64> {
    match unit {
        "B" => Some(1),
        "KiB" => Some(1 << 10),
        "MiB" => Some(1 << 20),
        "GiB" => Some(1 << 30),
        "TiB" => Some(1 << 40),
        "PiB" => Some(1 << 50),
        "EiB" => Some(1 << 60),
        _ => None,
    }
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
    use std::{
        collections::VecDeque,
        time::{SystemTime, UNIX_EPOCH},
    };
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
    fn qgroup_and_trim_plans_have_no_mutating_or_caller_selected_options() {
        let root = temp_path("reflink-forest-diagnostics-plan");
        fs::create_dir(&root).unwrap();

        let qgroups = PrivilegedPlan::show_qgroups(&root).unwrap().command();
        assert_eq!(qgroups.get_program(), OsStr::new("btrfs"));
        assert_eq!(
            qgroups
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["qgroup", "show", "--raw", root.to_str().unwrap()]
        );

        let trim = PrivilegedPlan::probe_trim(&root).unwrap().command();
        assert_eq!(trim.get_program(), OsStr::new("fstrim"));
        assert_eq!(
            trim.get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["--dry-run", "--verbose", root.to_str().unwrap()]
        );
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn qgroup_diagnostics_parse_raw_counters_and_distinguish_outcomes() {
        let output = b"qgroupid         rfer         excl     max_rfer     max_excl\n--------         ----         ----     --------     --------\n0/5              1048576       524288         none      2097152\n1/42             4096          2048           8192      none\n";
        assert_eq!(
            parse_qgroup_diagnostics(output, b"", true),
            DiagnosticOutcome::Supported(vec![
                QgroupUsage {
                    id: QgroupId {
                        level: 0,
                        subvolume_id: 5,
                    },
                    referenced_bytes: 1_048_576,
                    exclusive_bytes: 524_288,
                    max_referenced_bytes: None,
                    max_exclusive_bytes: Some(2_097_152),
                },
                QgroupUsage {
                    id: QgroupId {
                        level: 1,
                        subvolume_id: 42,
                    },
                    referenced_bytes: 4_096,
                    exclusive_bytes: 2_048,
                    max_referenced_bytes: Some(8_192),
                    max_exclusive_bytes: None,
                },
            ])
        );
        assert_eq!(
            parse_qgroup_diagnostics(b"", b"ERROR: quotas not enabled", false),
            DiagnosticOutcome::Unsupported
        );
        assert_eq!(
            parse_qgroup_diagnostics(
                b"",
                b"ERROR: can't list qgroups: Operation not permitted",
                false
            ),
            DiagnosticOutcome::Unknown
        );
        assert_eq!(
            parse_qgroup_diagnostics(b"0/5 1 2 none\n", b"", true),
            DiagnosticOutcome::Unknown
        );
    }

    #[test]
    fn trim_diagnostics_parse_byte_estimates_and_distinguish_outcomes() {
        assert_eq!(
            parse_trim_diagnostics(b"/mount: 0 B (dry run) trimmed\n", b"", true),
            DiagnosticOutcome::Supported(TrimDiagnostics {
                reclaimable_bytes: 0,
            })
        );
        assert_eq!(
            parse_trim_diagnostics(b"/mount: 1.5 MiB (dry run) trimmed\n", b"", true),
            DiagnosticOutcome::Supported(TrimDiagnostics {
                reclaimable_bytes: 1_572_864,
            })
        );
        assert_eq!(
            parse_trim_diagnostics(
                b"",
                b"fstrim: /mount: the discard operation is not supported",
                false,
            ),
            DiagnosticOutcome::Unsupported
        );
        assert_eq!(
            parse_trim_diagnostics(b"", b"fstrim: /mount: Input/output error", false),
            DiagnosticOutcome::Unknown
        );
        assert_eq!(
            parse_trim_diagnostics(b"not a trim result\n", b"", true),
            DiagnosticOutcome::Unknown
        );
    }

    #[derive(Default)]
    struct RecordedRunner {
        expected: VecDeque<(PrivilegedPlan, CommandOutput)>,
        seen: Vec<PrivilegedPlan>,
    }

    impl RecordedRunner {
        fn new(expected: impl IntoIterator<Item = (PrivilegedPlan, CommandOutput)>) -> Self {
            Self {
                expected: expected.into_iter().collect(),
                seen: Vec::new(),
            }
        }
    }

    impl CommandRunner for RecordedRunner {
        fn run(&mut self, plan: &PrivilegedPlan) -> Result<CommandOutput, BtrfsError> {
            let (expected, output) = self
                .expected
                .pop_front()
                .expect("unexpected fixed-purpose command");
            assert_eq!(&expected, plan);
            self.seen.push(plan.clone());
            Ok(output)
        }
    }

    fn executor_fixture(name: &str) -> (PathBuf, PathBuf, PrivilegedExecutorConfig) {
        let parent = temp_path(name);
        fs::create_dir(&parent).unwrap();
        let image =
            initialize_loopback_image(parent.join("hot.btrfs"), 4096, ImageAllocation::Sparse)
                .unwrap();
        let config = PrivilegedExecutorConfig::new(
            &image,
            &parent,
            &parent,
            InstanceMarker {
                instance_uuid: [4; 16],
                filesystem_uuid: [5; 16],
                label: "test-instance".into(),
            },
        )
        .unwrap();
        (parent, image, config)
    }

    fn btrfs_identity(label: &str) -> CommandOutput {
        CommandOutput::success(format!(
            "DEVNAME=/dev/loop7\nUUID=05050505-0505-0505-0505-050505050505\nTYPE=btrfs\nLABEL={label}\n"
        ))
    }

    fn backing_output(image: &Path) -> CommandOutput {
        let mut output = image.as_os_str().as_bytes().to_vec();
        output.push(b'\n');
        CommandOutput::success(output)
    }

    #[test]
    fn executor_reuses_reboot_style_association_after_canonical_verification() {
        let (parent, image, config) = executor_fixture("reflink-forest-reattach");
        let runner = RecordedRunner::new([
            (
                PrivilegedPlan::ListLoops,
                CommandOutput::success("/dev/loop7: [2065]:4 (old-path)\n"),
            ),
            (
                PrivilegedPlan::InspectLoopBacking {
                    device: "/dev/loop7".into(),
                },
                backing_output(&image),
            ),
            (
                PrivilegedPlan::InspectFilesystem {
                    device: "/dev/loop7".into(),
                },
                btrfs_identity("test-instance"),
            ),
            (
                PrivilegedPlan::Mount {
                    device: "/dev/loop7".into(),
                    mount_root: parent.clone(),
                },
                CommandOutput::success(Vec::new()),
            ),
        ]);
        let mut executor = PrivilegedExecutor::new(config, runner);
        assert_eq!(executor.mount().unwrap(), "/dev/loop7");
        let runner = executor.into_runner();
        assert!(runner
            .seen
            .iter()
            .all(|plan| !matches!(plan, PrivilegedPlan::AttachLoop { .. })));
        assert!(runner.expected.is_empty());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn executor_rejects_duplicate_canonical_loop_associations() {
        let (parent, image, config) = executor_fixture("reflink-forest-duplicate-loop");
        let runner = RecordedRunner::new([
            (
                PrivilegedPlan::ListLoops,
                CommandOutput::success("/dev/loop7: first\n/dev/loop8: second\n"),
            ),
            (
                PrivilegedPlan::InspectLoopBacking {
                    device: "/dev/loop7".into(),
                },
                backing_output(&image),
            ),
            (
                PrivilegedPlan::InspectLoopBacking {
                    device: "/dev/loop8".into(),
                },
                backing_output(&image),
            ),
        ]);
        let mut executor = PrivilegedExecutor::new(config, runner);
        assert!(matches!(
            executor.attach_or_reuse(),
            Err(BtrfsError::DuplicateLoopAssociation(device)) if device == "/dev/loop8"
        ));
        let runner = executor.into_runner();
        assert!(runner.expected.is_empty());
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn executor_rejects_wrong_inspected_identity_before_mount() {
        let (parent, image, config) = executor_fixture("reflink-forest-wrong-identity");
        let runner = RecordedRunner::new([
            (
                PrivilegedPlan::ListLoops,
                CommandOutput::success("/dev/loop7: existing\n"),
            ),
            (
                PrivilegedPlan::InspectLoopBacking {
                    device: "/dev/loop7".into(),
                },
                backing_output(&image),
            ),
            (
                PrivilegedPlan::InspectFilesystem {
                    device: "/dev/loop7".into(),
                },
                btrfs_identity("wrong-instance"),
            ),
        ]);
        let mut executor = PrivilegedExecutor::new(config, runner);
        assert!(matches!(
            executor.mount(),
            Err(BtrfsError::IdentityMismatch)
        ));
        let runner = executor.into_runner();
        assert!(runner.expected.is_empty());
        assert!(runner
            .seen
            .iter()
            .all(|plan| !matches!(plan, PrivilegedPlan::Mount { .. })));
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn executor_attaches_with_nooverlap_and_grows_in_required_order() {
        let (parent, image, config) = executor_fixture("reflink-forest-grow-sequence");
        let runner = RecordedRunner::new([
            (
                PrivilegedPlan::ListLoops,
                CommandOutput::success(Vec::new()),
            ),
            (
                PrivilegedPlan::AttachLoop {
                    image: image.clone(),
                },
                CommandOutput::success("/dev/loop7\n"),
            ),
            (
                PrivilegedPlan::InspectLoopBacking {
                    device: "/dev/loop7".into(),
                },
                backing_output(&image),
            ),
            (
                PrivilegedPlan::InspectFilesystem {
                    device: "/dev/loop7".into(),
                },
                btrfs_identity("test-instance"),
            ),
            (
                PrivilegedPlan::GrowImage {
                    image: image.clone(),
                    size: 8192,
                },
                CommandOutput::success(Vec::new()),
            ),
            (
                PrivilegedPlan::RefreshLoopCapacity {
                    device: "/dev/loop7".into(),
                },
                CommandOutput::success(Vec::new()),
            ),
            (
                PrivilegedPlan::ResizeFilesystem {
                    mount_root: parent.clone(),
                },
                CommandOutput::success(Vec::new()),
            ),
        ]);
        let mut executor = PrivilegedExecutor::new(config, runner);
        executor.grow(8192).unwrap();
        let runner = executor.into_runner();
        assert!(runner.expected.is_empty());
        let attach = runner
            .seen
            .iter()
            .find(|plan| matches!(plan, PrivilegedPlan::AttachLoop { .. }))
            .unwrap()
            .command();
        assert_eq!(
            attach
                .get_args()
                .map(|arg| arg.as_bytes().to_vec())
                .collect::<Vec<_>>(),
            vec![
                b"--find".to_vec(),
                b"--show".to_vec(),
                b"--nooverlap".to_vec(),
                image.as_os_str().as_bytes().to_vec(),
            ]
        );
        let operation_order = runner
            .seen
            .iter()
            .filter(|plan| {
                matches!(
                    plan,
                    PrivilegedPlan::GrowImage { .. }
                        | PrivilegedPlan::RefreshLoopCapacity { .. }
                        | PrivilegedPlan::ResizeFilesystem { .. }
                )
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            operation_order[0],
            PrivilegedPlan::GrowImage { .. }
        ));
        assert!(matches!(
            operation_order[1],
            PrivilegedPlan::RefreshLoopCapacity { .. }
        ));
        assert!(matches!(
            operation_order[2],
            PrivilegedPlan::ResizeFilesystem { .. }
        ));
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn doctor_parsers_do_not_invent_capacity() {
        assert_eq!(parse_available_bytes("Avail\n1048576\n"), Some(1_048_576));
        assert_eq!(parse_available_bytes("Avail\nunknown\n"), None);
    }
}

//! Byte-safe, side-effect-free planning for raw Git checkouts.
//!
//! Git tree names are bytes, not platform strings.  This crate retains that
//! property through validation and planning, so a later materializer can use
//! fd-relative byte APIs without first passing a path through UTF-8.  It does
//! not create files, follow symlinks, or apply Git worktree transforms.

use std::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File},
    io,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
};

const AT_FDCWD: std::ffi::c_int = -100;
const RENAME_EXCHANGE: u32 = 2;
const FICLONE: libc::c_ulong = 0x4004_9409;
unsafe extern "C" {
    fn renameat2(
        olddirfd: std::ffi::c_int,
        oldpath: *const std::ffi::c_char,
        newdirfd: std::ffi::c_int,
        newpath: *const std::ffi::c_char,
        flags: u32,
    ) -> std::ffi::c_int;
}

use reflink_forest_cache::{Cache, CacheError};
use reflink_forest_core::{ContentId, GitOid};

/// Conservative limits enforced before checkout planning allocates a large
/// amount of memory or constructs an impractical workspace tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckoutLimits {
    /// Maximum number of non-directory entries in one checkout plan.
    pub max_entries: usize,
    /// Maximum number of components in one relative path.
    pub max_components: usize,
    /// Maximum number of bytes in a single Git tree name.
    pub max_component_bytes: usize,
    /// Maximum encoded byte length of a path, including separators.
    pub max_path_bytes: usize,
}

/// Default limits for an untrusted Git tree checkout.
pub const DEFAULT_CHECKOUT_LIMITS: CheckoutLimits = CheckoutLimits {
    max_entries: 1_000_000,
    max_components: 128,
    max_component_bytes: 255,
    max_path_bytes: 4_096,
};

/// Error from validating a Git tree name or planning a checkout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckoutError {
    EmptyPath,
    AbsolutePath,
    EmptyComponent,
    NulByte,
    SlashInComponent,
    DotComponent,
    DotDotComponent,
    ComponentTooLong {
        actual: usize,
        limit: usize,
    },
    PathTooLong {
        actual: usize,
        limit: usize,
    },
    TooManyComponents {
        actual: usize,
        limit: usize,
    },
    TooManyEntries {
        actual: usize,
        limit: usize,
    },
    InvalidGitMode(u32),
    DuplicatePath(RelativePath),
    PathConflict {
        ancestor: RelativePath,
        descendant: RelativePath,
    },
}

impl fmt::Display for CheckoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => write!(f, "checkout path is empty"),
            Self::AbsolutePath => write!(f, "checkout path must be relative"),
            Self::EmptyComponent => write!(f, "checkout path has an empty component"),
            Self::NulByte => write!(f, "Git tree name contains a NUL byte"),
            Self::SlashInComponent => write!(f, "Git tree name contains a slash"),
            Self::DotComponent => write!(f, "Git tree name cannot be `.`"),
            Self::DotDotComponent => write!(f, "Git tree name cannot be `..`"),
            Self::ComponentTooLong { actual, limit } => {
                write!(f, "Git tree name is {actual} bytes; limit is {limit}")
            }
            Self::PathTooLong { actual, limit } => {
                write!(f, "checkout path is {actual} bytes; limit is {limit}")
            }
            Self::TooManyComponents { actual, limit } => {
                write!(f, "checkout path has {actual} components; limit is {limit}")
            }
            Self::TooManyEntries { actual, limit } => {
                write!(f, "checkout has {actual} entries; limit is {limit}")
            }
            Self::InvalidGitMode(mode) => write!(f, "unsupported Git tree mode {mode:o}"),
            Self::DuplicatePath(_) => write!(f, "checkout contains the same path twice"),
            Self::PathConflict { .. } => {
                write!(
                    f,
                    "checkout path collides with an existing non-directory entry"
                )
            }
        }
    }
}

impl std::error::Error for CheckoutError {}

/// The supported raw Git tree modes.
///
/// Modes are deliberately semantic rather than arbitrary Unix permissions:
/// raw checkout only writes the ordinary Git modes listed below.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TreeEntryMode {
    Regular,
    Executable,
    Symlink,
    Gitlink,
}

impl TreeEntryMode {
    pub const REGULAR_MODE: u32 = 0o100644;
    pub const EXECUTABLE_MODE: u32 = 0o100755;
    pub const SYMLINK_MODE: u32 = 0o120000;
    pub const GITLINK_MODE: u32 = 0o160000;

    /// Decodes the mode field from a raw Git tree entry.
    pub const fn from_git_mode(mode: u32) -> Result<Self, CheckoutError> {
        match mode {
            Self::REGULAR_MODE => Ok(Self::Regular),
            Self::EXECUTABLE_MODE => Ok(Self::Executable),
            Self::SYMLINK_MODE => Ok(Self::Symlink),
            Self::GITLINK_MODE => Ok(Self::Gitlink),
            _ => Err(CheckoutError::InvalidGitMode(mode)),
        }
    }

    /// Returns the canonical Git tree mode.
    pub const fn git_mode(self) -> u32 {
        match self {
            Self::Regular => Self::REGULAR_MODE,
            Self::Executable => Self::EXECUTABLE_MODE,
            Self::Symlink => Self::SYMLINK_MODE,
            Self::Gitlink => Self::GITLINK_MODE,
        }
    }
}

/// One validated, byte-oriented Git tree name.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TreeName(Vec<u8>);

impl TreeName {
    /// Validates a single Git tree component.  A tree name can never contain a
    /// path separator or a NUL byte, and special traversal components are not
    /// allowed.
    pub fn new(name: impl AsRef<[u8]>, limits: CheckoutLimits) -> Result<Self, CheckoutError> {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(CheckoutError::EmptyComponent);
        }
        if name.contains(&0) {
            return Err(CheckoutError::NulByte);
        }
        if name.contains(&b'/') {
            return Err(CheckoutError::SlashInComponent);
        }
        if name == b"." {
            return Err(CheckoutError::DotComponent);
        }
        if name == b".." {
            return Err(CheckoutError::DotDotComponent);
        }
        if name.len() > limits.max_component_bytes {
            return Err(CheckoutError::ComponentTooLong {
                actual: name.len(),
                limit: limits.max_component_bytes,
            });
        }
        Ok(Self(name.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A validated, non-empty relative path, represented as Git tree components.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RelativePath(Vec<TreeName>);

impl RelativePath {
    /// Parses a slash-separated relative path from an untrusted source.
    ///
    /// This method is for flattened tree walkers.  A raw Git tree entry must
    /// instead be passed through [`TreeName::new`], since its name is exactly
    /// one component.
    pub fn parse(path: impl AsRef<[u8]>, limits: CheckoutLimits) -> Result<Self, CheckoutError> {
        let path = path.as_ref();
        if path.is_empty() {
            return Err(CheckoutError::EmptyPath);
        }
        if path[0] == b'/' {
            return Err(CheckoutError::AbsolutePath);
        }
        if path.len() > limits.max_path_bytes {
            return Err(CheckoutError::PathTooLong {
                actual: path.len(),
                limit: limits.max_path_bytes,
            });
        }

        let raw_components: Vec<&[u8]> = path.split(|&byte| byte == b'/').collect();
        if raw_components.len() > limits.max_components {
            return Err(CheckoutError::TooManyComponents {
                actual: raw_components.len(),
                limit: limits.max_components,
            });
        }
        let mut components = Vec::with_capacity(raw_components.len());
        for component in raw_components {
            components.push(TreeName::new(component, limits)?);
        }
        Ok(Self(components))
    }

    /// Creates a path from already-separated tree names and rechecks the
    /// aggregate component-count and byte-length limits.
    pub fn from_components(
        components: impl IntoIterator<Item = TreeName>,
        limits: CheckoutLimits,
    ) -> Result<Self, CheckoutError> {
        let components: Vec<TreeName> = components.into_iter().collect();
        validate_path_shape(&components, limits)?;
        Ok(Self(components))
    }

    /// Appends one child tree name, checking the resulting full path limits.
    pub fn join(&self, child: TreeName, limits: CheckoutLimits) -> Result<Self, CheckoutError> {
        let mut components = self.0.clone();
        components.push(child);
        Self::from_components(components, limits)
    }

    /// Returns slash-separated raw path bytes.  This is for inspection and
    /// materializer handoff; it never attempts UTF-8 conversion.
    pub fn as_bytes(&self) -> Vec<u8> {
        let length = encoded_path_len(&self.0).expect("validated path length");
        let mut result = Vec::with_capacity(length);
        for (index, component) in self.0.iter().enumerate() {
            if index != 0 {
                result.push(b'/');
            }
            result.extend_from_slice(component.as_bytes());
        }
        result
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &TreeName> {
        self.0.iter()
    }

    fn parent_paths(&self) -> impl Iterator<Item = RelativePath> + '_ {
        (1..self.0.len()).map(|end| RelativePath(self.0[..end].to_vec()))
    }

    fn is_ancestor_of(&self, other: &Self) -> bool {
        self.0.len() < other.0.len() && other.0.starts_with(&self.0)
    }
}

fn validate_path_shape(
    components: &[TreeName],
    limits: CheckoutLimits,
) -> Result<(), CheckoutError> {
    if components.is_empty() {
        return Err(CheckoutError::EmptyPath);
    }
    if let Some(component) = components
        .iter()
        .find(|component| component.0.len() > limits.max_component_bytes)
    {
        return Err(CheckoutError::ComponentTooLong {
            actual: component.0.len(),
            limit: limits.max_component_bytes,
        });
    }
    if components.len() > limits.max_components {
        return Err(CheckoutError::TooManyComponents {
            actual: components.len(),
            limit: limits.max_components,
        });
    }
    let length = encoded_path_len(components).expect("component lengths cannot overflow usize");
    if length > limits.max_path_bytes {
        return Err(CheckoutError::PathTooLong {
            actual: length,
            limit: limits.max_path_bytes,
        });
    }
    Ok(())
}

fn encoded_path_len(components: &[TreeName]) -> Option<usize> {
    components
        .iter()
        .enumerate()
        .try_fold(0_usize, |length, (index, component)| {
            length
                .checked_add(component.0.len())?
                .checked_add(usize::from(index != 0))
        })
}

/// One validated entry taken from a Git tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    pub name: TreeName,
    pub mode: TreeEntryMode,
    pub oid: GitOid,
}

impl TreeEntry {
    /// Validates a raw Git tree entry's name and mode.
    pub fn from_raw(
        name: impl AsRef<[u8]>,
        mode: u32,
        oid: GitOid,
        limits: CheckoutLimits,
    ) -> Result<Self, CheckoutError> {
        Ok(Self {
            name: TreeName::new(name, limits)?,
            mode: TreeEntryMode::from_git_mode(mode)?,
            oid,
        })
    }
}

/// The requested object and semantic mode for one checkout destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedObject {
    pub mode: TreeEntryMode,
    pub oid: GitOid,
}

/// One non-directory item in a checkout plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedEntry {
    pub path: RelativePath,
    pub object: PlannedObject,
}

/// A deterministic raw checkout plan.
///
/// Directories contain every strict parent of a planned entry and are sorted
/// before use.  `entries` is byte-lexicographically sorted by its raw path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckoutPlan {
    directories: Vec<RelativePath>,
    entries: Vec<PlannedEntry>,
}

/// Resolves a planned native Git object ID to the data required by raw mode.
/// Implementations commonly read an object-location alias from the cold tier
/// and hydrate its `ContentId` into [`Cache`] before returning it.
pub trait RawCheckoutSource {
    type Error: std::error::Error + Send + Sync + 'static;

    fn blob_content_id(&self, oid: &GitOid) -> Result<ContentId, Self::Error>;
    fn blob_bytes(&self, oid: &GitOid) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitlinkPolicy {
    Reject,
    EmptyDirectory,
}

#[derive(Debug)]
pub enum MaterializeError<E: std::error::Error + Send + Sync + 'static> {
    Source(E),
    Cache(CacheError),
    Io(io::Error),
    StageNotEmpty,
    InvalidStage,
    Gitlink(GitOid),
    InvalidSymlinkTarget,
}

impl<E: std::error::Error + Send + Sync + 'static> fmt::Display for MaterializeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "checkout source error: {error}"),
            Self::Cache(error) => write!(f, "checkout cache error: {error}"),
            Self::Io(error) => write!(f, "checkout filesystem error: {error}"),
            Self::StageNotEmpty => write!(f, "staging workspace must be empty"),
            Self::InvalidStage => write!(f, "staging workspace must be an existing directory"),
            Self::Gitlink(oid) => write!(f, "raw checkout rejects gitlink {oid:?}"),
            Self::InvalidSymlinkTarget => write!(f, "symlink target contains a NUL byte"),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error for MaterializeError<E> {}
impl<E: std::error::Error + Send + Sync + 'static> From<io::Error> for MaterializeError<E> {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Materializes a plan only inside a private, empty staging directory. It
/// never performs publication or copy fallback. Source and staging must have
/// passed the exact FICLONE clone-domain probe before calling this function.
pub fn materialize_raw<S: RawCheckoutSource>(
    plan: &CheckoutPlan,
    source: &S,
    cache: &Cache,
    staging: impl AsRef<Path>,
    gitlink_policy: GitlinkPolicy,
) -> Result<(), MaterializeError<S::Error>> {
    let staging = staging.as_ref();
    let stage_metadata = fs::symlink_metadata(staging)?;
    if stage_metadata.file_type().is_symlink() || !stage_metadata.is_dir() {
        return Err(MaterializeError::InvalidStage);
    }
    if fs::read_dir(staging)?.next().is_some() {
        return Err(MaterializeError::StageNotEmpty);
    }
    let stage = open_directory_no_follow(staging)?;
    for directory in plan.directories() {
        create_directory_at(&stage, directory, 0o755)?;
    }
    for entry in plan.entries() {
        match entry.object.mode {
            TreeEntryMode::Regular | TreeEntryMode::Executable => {
                let id = source
                    .blob_content_id(&entry.object.oid)
                    .map_err(MaterializeError::Source)?;
                clone_blob_at(cache, id, &stage, &entry.path).map_err(MaterializeError::Cache)?;
                let mode = if entry.object.mode == TreeEntryMode::Executable {
                    0o755
                } else {
                    0o644
                };
                set_file_mode_at(&stage, &entry.path, mode)?;
            }
            TreeEntryMode::Symlink => {
                let target = source
                    .blob_bytes(&entry.object.oid)
                    .map_err(MaterializeError::Source)?;
                if target.contains(&0) {
                    return Err(MaterializeError::InvalidSymlinkTarget);
                }
                create_symlink_at(&stage, &entry.path, &target)?;
            }
            TreeEntryMode::Gitlink => match gitlink_policy {
                GitlinkPolicy::Reject => return Err(MaterializeError::Gitlink(entry.object.oid)),
                GitlinkPolicy::EmptyDirectory => create_directory_at(&stage, &entry.path, 0o755)?,
            },
        }
    }
    Ok(())
}

fn c_name(name: &[u8]) -> io::Result<CString> {
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in validated name"))
}
fn open_directory_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
fn duplicate_fd(file: &File) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_child_directory(parent: &File, name: &[u8]) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn parent_directory(stage: &File, relative: &RelativePath) -> io::Result<(File, Vec<u8>)> {
    let components: Vec<_> = relative.components().collect();
    let leaf = components
        .last()
        .expect("validated nonempty path")
        .as_bytes()
        .to_vec();
    let mut directory = duplicate_fd(stage)?;
    for component in &components[..components.len() - 1] {
        directory = open_child_directory(&directory, component.as_bytes())?;
    }
    Ok((directory, leaf))
}
fn create_directory_at(stage: &File, relative: &RelativePath, mode: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let (parent, name) = parent_directory(stage, relative)?;
    let name = c_name(&name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn create_file_at(stage: &File, relative: &RelativePath, mode: u32) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (parent, name) = parent_directory(stage, relative)?;
    let name = c_name(&name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn set_file_mode_at(stage: &File, relative: &RelativePath, mode: u32) -> io::Result<()> {
    let file = open_file_at(stage, relative)?;
    file.set_permissions(fs::Permissions::from_mode(mode))
}
fn open_file_at(stage: &File, relative: &RelativePath) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (parent, name) = parent_directory(stage, relative)?;
    let name = c_name(&name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn create_symlink_at(stage: &File, relative: &RelativePath, target: &[u8]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let (parent, name) = parent_directory(stage, relative)?;
    let name = c_name(&name)?;
    let target = c_name(target)?;
    if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn clone_blob_at(
    cache: &Cache,
    id: ContentId,
    stage: &File,
    relative: &RelativePath,
) -> Result<(), CacheError> {
    use std::os::fd::AsRawFd;
    let source = File::open(cache.verified_path(id)?)?;
    let destination = create_file_at(stage, relative, 0o644)?;
    if unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) } != 0 {
        return Err(CacheError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// A workspace directory name. It is intentionally narrower than an arbitrary
/// path so that publication never incorporates an unchecked user path.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct WorkspaceName(String);

impl WorkspaceName {
    pub fn new(name: impl Into<String>) -> Result<Self, WorkspacePublishError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(WorkspacePublishError::InvalidName);
        }
        Ok(Self(name))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacePolicy {
    Reject,
    ReplaceAtomically,
}

#[derive(Debug)]
pub enum WorkspacePublishError {
    Io(io::Error),
    InvalidName,
    InvalidStaging,
    DestinationExists,
    UnsupportedAtomicReplace,
}
impl fmt::Display for WorkspacePublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "workspace publication I/O error: {error}"),
            Self::InvalidName => write!(
                f,
                "workspace name must be 1–128 ASCII letters, digits, hyphens, or underscores"
            ),
            Self::InvalidStaging => write!(f, "staging workspace must be an existing directory"),
            Self::DestinationExists => write!(f, "workspace name is already published"),
            Self::UnsupportedAtomicReplace => write!(
                f,
                "kernel/filesystem does not support atomic workspace replacement"
            ),
        }
    }
}
impl std::error::Error for WorkspacePublishError {}
impl From<io::Error> for WorkspacePublishError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Atomically makes a complete private staging directory visible as a
/// workspace. `ReplaceAtomically` exchanges directories first, avoiding a
/// window in which the workspace name is absent, then moves the retired tree
/// into `trash` for asynchronous cleanup.
pub fn publish_workspace(
    staging: impl AsRef<Path>,
    workspaces: impl AsRef<Path>,
    trash: impl AsRef<Path>,
    name: &WorkspaceName,
    replace: ReplacePolicy,
) -> Result<PathBuf, WorkspacePublishError> {
    let staging = staging.as_ref();
    let workspaces = workspaces.as_ref();
    let trash = trash.as_ref();
    if !staging.is_dir() || !workspaces.is_dir() {
        return Err(WorkspacePublishError::InvalidStaging);
    }
    let destination = workspaces.join(name.as_str());
    if !destination.exists() {
        fs::rename(staging, &destination)?;
        File::open(workspaces)?.sync_all()?;
        return Ok(destination);
    }
    if replace == ReplacePolicy::Reject {
        return Err(WorkspacePublishError::DestinationExists);
    }
    fs::create_dir_all(trash)?;
    let staging_c = c_path(staging)?;
    let destination_c = c_path(&destination)?;
    // SAFETY: both C strings remain alive for the syscall and refer to paths
    // beneath caller-controlled service roots.
    if unsafe {
        renameat2(
            AT_FDCWD,
            staging_c.as_ptr(),
            AT_FDCWD,
            destination_c.as_ptr(),
            RENAME_EXCHANGE,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(38) | Some(95)) {
            return Err(WorkspacePublishError::UnsupportedAtomicReplace);
        }
        return Err(error.into());
    }
    let retired = trash.join(format!("{}-retired", name.as_str()));
    if retired.exists() {
        return Err(WorkspacePublishError::DestinationExists);
    }
    fs::rename(staging, retired)?;
    File::open(workspaces)?.sync_all()?;
    File::open(trash)?.sync_all()?;
    Ok(destination)
}

fn c_path(path: &Path) -> Result<CString, WorkspacePublishError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| WorkspacePublishError::InvalidStaging)
}

impl CheckoutPlan {
    pub fn directories(&self) -> &[RelativePath] {
        &self.directories
    }

    pub fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
}

/// Incrementally builds a validated raw checkout plan.
#[derive(Debug)]
pub struct CheckoutPlanBuilder {
    limits: CheckoutLimits,
    entries: BTreeMap<RelativePath, PlannedObject>,
}

impl CheckoutPlanBuilder {
    pub fn new(limits: CheckoutLimits) -> Self {
        Self {
            limits,
            entries: BTreeMap::new(),
        }
    }

    /// Adds a flattened path from a tree walk.
    pub fn add_raw(
        &mut self,
        path: impl AsRef<[u8]>,
        mode: u32,
        oid: GitOid,
    ) -> Result<(), CheckoutError> {
        let path = RelativePath::parse(path, self.limits)?;
        let mode = TreeEntryMode::from_git_mode(mode)?;
        self.add(path, PlannedObject { mode, oid })
    }

    /// Adds a previously validated tree entry below a validated parent path.
    pub fn add_tree_entry(
        &mut self,
        parent: Option<&RelativePath>,
        entry: TreeEntry,
    ) -> Result<(), CheckoutError> {
        let path = match parent {
            Some(parent) => parent.join(entry.name, self.limits)?,
            None => RelativePath::from_components([entry.name], self.limits)?,
        };
        self.add(
            path,
            PlannedObject {
                mode: entry.mode,
                oid: entry.oid,
            },
        )
    }

    /// Adds an entry at an already validated relative path.
    pub fn add(&mut self, path: RelativePath, object: PlannedObject) -> Result<(), CheckoutError> {
        validate_path_shape(&path.0, self.limits)?;
        if self.entries.contains_key(&path) {
            return Err(CheckoutError::DuplicatePath(path));
        }
        let next_count = self.entries.len().saturating_add(1);
        if next_count > self.limits.max_entries {
            return Err(CheckoutError::TooManyEntries {
                actual: next_count,
                limit: self.limits.max_entries,
            });
        }

        if let Some(ancestor) = path
            .parent_paths()
            .find(|ancestor| self.entries.contains_key(ancestor))
        {
            return Err(CheckoutError::PathConflict {
                ancestor,
                descendant: path.clone(),
            });
        }
        if let Some(descendant) = self
            .entries
            .keys()
            .find(|existing| path.is_ancestor_of(existing))
        {
            return Err(CheckoutError::PathConflict {
                ancestor: path.clone(),
                descendant: descendant.clone(),
            });
        }
        self.entries.insert(path, object);
        Ok(())
    }

    /// Finishes the plan without causing filesystem side effects.
    pub fn finish(self) -> CheckoutPlan {
        let mut directories = BTreeSet::new();
        for path in self.entries.keys() {
            directories.extend(path.parent_paths());
        }
        let entries = self
            .entries
            .into_iter()
            .map(|(path, object)| PlannedEntry { path, object })
            .collect();
        CheckoutPlan {
            directories: directories.into_iter().collect(),
            entries,
        }
    }
}

impl Default for CheckoutPlanBuilder {
    fn default() -> Self {
        Self::new(DEFAULT_CHECKOUT_LIMITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflink_forest_core::HashAlgorithm;

    fn oid(byte: u8) -> GitOid {
        GitOid::new(HashAlgorithm::Sha1, &[byte; 20]).unwrap()
    }

    #[test]
    fn tree_names_remain_raw_bytes_and_reject_escape_components() {
        let name = TreeName::new([0xff, b'a'], DEFAULT_CHECKOUT_LIMITS).unwrap();
        assert_eq!(name.as_bytes(), &[0xff, b'a']);
        for input in [
            b"".as_slice(),
            b".".as_slice(),
            b"..".as_slice(),
            b"a/b".as_slice(),
            b"a\0b".as_slice(),
        ] {
            assert!(
                TreeName::new(input, DEFAULT_CHECKOUT_LIMITS).is_err(),
                "{input:?}"
            );
        }
    }

    #[test]
    fn fd_relative_construction_rejects_symlinked_parent_and_cannot_escape() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};
        let base = std::env::temp_dir().join(format!(
            "rfs-checkout-fd-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let staging = base.join("staging");
        let outside = base.join("outside");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir(&outside).unwrap();
        let stage = open_directory_no_follow(&staging).unwrap();
        let directory = RelativePath::parse(b"safe", DEFAULT_CHECKOUT_LIMITS).unwrap();
        create_directory_at(&stage, &directory, 0o755).unwrap();
        fs::remove_dir(staging.join("safe")).unwrap();
        symlink(&outside, staging.join("safe")).unwrap();
        let hostile = RelativePath::parse(b"safe/escape", DEFAULT_CHECKOUT_LIMITS).unwrap();
        assert!(create_file_at(&stage, &hostile, 0o644).is_err());
        assert!(!outside.join("escape").exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn relative_paths_are_non_empty_relative_and_bounded() {
        assert_eq!(
            RelativePath::parse(b"src/\xffmain", DEFAULT_CHECKOUT_LIMITS)
                .unwrap()
                .as_bytes(),
            b"src/\xffmain"
        );
        for input in [
            b"".as_slice(),
            b"/etc/passwd".as_slice(),
            b"a//b".as_slice(),
            b"a/../b".as_slice(),
            b"a/./b".as_slice(),
        ] {
            assert!(
                RelativePath::parse(input, DEFAULT_CHECKOUT_LIMITS).is_err(),
                "{input:?}"
            );
        }
        let limits = CheckoutLimits {
            max_components: 2,
            max_path_bytes: 3,
            ..DEFAULT_CHECKOUT_LIMITS
        };
        assert!(matches!(
            RelativePath::parse(b"a/b/c", limits),
            Err(CheckoutError::PathTooLong { .. }) | Err(CheckoutError::TooManyComponents { .. })
        ));
    }

    #[test]
    fn tree_entry_accepts_only_the_four_raw_checkout_modes() {
        for (mode, expected) in [
            (0o100644, TreeEntryMode::Regular),
            (0o100755, TreeEntryMode::Executable),
            (0o120000, TreeEntryMode::Symlink),
            (0o160000, TreeEntryMode::Gitlink),
        ] {
            let entry =
                TreeEntry::from_raw(b"entry", mode, oid(1), DEFAULT_CHECKOUT_LIMITS).unwrap();
            assert_eq!(entry.mode, expected);
            assert_eq!(entry.mode.git_mode(), mode);
        }
        assert!(matches!(
            TreeEntry::from_raw(b"tree", 0o040000, oid(1), DEFAULT_CHECKOUT_LIMITS),
            Err(CheckoutError::InvalidGitMode(0o040000))
        ));
    }

    #[test]
    fn plan_is_deterministic_and_contains_implicit_directories() {
        let mut builder = CheckoutPlanBuilder::default();
        builder.add_raw(b"z", 0o160000, oid(1)).unwrap();
        builder.add_raw(b"a/c", 0o120000, oid(2)).unwrap();
        builder.add_raw(b"a/b", 0o100755, oid(3)).unwrap();
        let plan = builder.finish();

        assert_eq!(
            plan.directories()
                .iter()
                .map(RelativePath::as_bytes)
                .collect::<Vec<_>>(),
            vec![b"a".to_vec()]
        );
        assert_eq!(
            plan.entries()
                .iter()
                .map(|entry| entry.path.as_bytes())
                .collect::<Vec<_>>(),
            vec![b"a/b".to_vec(), b"a/c".to_vec(), b"z".to_vec()]
        );
        assert_eq!(plan.entries()[0].object.mode, TreeEntryMode::Executable);
        assert_eq!(plan.entries()[1].object.mode, TreeEntryMode::Symlink);
        assert_eq!(plan.entries()[2].object.mode, TreeEntryMode::Gitlink);
    }

    #[test]
    fn plan_rejects_duplicate_and_file_directory_collisions() {
        let mut builder = CheckoutPlanBuilder::default();
        builder.add_raw(b"node", 0o100644, oid(1)).unwrap();
        assert!(matches!(
            builder.add_raw(b"node", 0o100644, oid(2)),
            Err(CheckoutError::DuplicatePath(_))
        ));
        assert!(matches!(
            builder.add_raw(b"node/child", 0o100644, oid(2)),
            Err(CheckoutError::PathConflict { .. })
        ));

        let mut reverse = CheckoutPlanBuilder::default();
        reverse.add_raw(b"node/child", 0o100644, oid(1)).unwrap();
        assert!(matches!(
            reverse.add_raw(b"node", 0o100644, oid(2)),
            Err(CheckoutError::PathConflict { .. })
        ));
    }

    #[test]
    fn plan_enforces_entry_count_and_joined_path_limits() {
        let limits = CheckoutLimits {
            max_entries: 1,
            max_components: 2,
            max_component_bytes: 3,
            max_path_bytes: 5,
        };
        let mut builder = CheckoutPlanBuilder::new(limits);
        builder.add_raw(b"abc", 0o100644, oid(1)).unwrap();
        assert!(matches!(
            builder.add_raw(b"def", 0o100644, oid(2)),
            Err(CheckoutError::TooManyEntries {
                actual: 2,
                limit: 1
            })
        ));
        let parent = RelativePath::parse(b"abc", limits).unwrap();
        let entry = TreeEntry::from_raw(b"def", 0o100644, oid(3), limits).unwrap();
        assert!(matches!(
            builder.add_tree_entry(Some(&parent), entry),
            Err(CheckoutError::PathTooLong {
                actual: 7,
                limit: 5
            })
        ));
    }

    #[test]
    fn publication_is_invisible_until_the_staging_tree_is_renamed() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let root = std::env::temp_dir().join(format!(
            "reflink-forest-publication-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let staging = root.join("staging/workspace");
        let workspaces = root.join("workspaces");
        let trash = root.join("trash");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&workspaces).unwrap();
        fs::write(staging.join("ready"), b"complete").unwrap();
        let name = WorkspaceName::new("demo_workspace").unwrap();
        assert!(!workspaces.join(name.as_str()).exists());
        let published =
            publish_workspace(&staging, &workspaces, &trash, &name, ReplacePolicy::Reject).unwrap();
        assert_eq!(fs::read(published.join("ready")).unwrap(), b"complete");
        assert!(!staging.exists());
        fs::remove_dir_all(root).unwrap();
    }
}

//! Immutable local Git snapshots backed by the system `git` executable.
//!
//! The backend deliberately invokes `git` with [`std::process::Command`] and
//! never via a shell.  It snapshots only `refs/heads/*` and `refs/tags/*`;
//! remote-tracking refs are not an import root.  A caller can retain the
//! resulting object payloads in the cold store, then use the snapshot after
//! the original repository has disappeared.
//!
//! Object traversal starts from fixed native OIDs, rather than mutable ref
//! names.  It reads commits, trees, annotated tags, and blobs directly and
//! parses their Git object references, so an annotated-tag object itself is
//! retained in addition to its target.

use std::{
    collections::{HashSet, VecDeque},
    ffi::{OsStr, OsString},
    fmt, io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use reflink_forest_core::{GitOid, HashAlgorithm, InvalidGitOidLength, ObjectKind};

const HEADS_PREFIX: &[u8] = b"refs/heads/";
const TAGS_PREFIX: &[u8] = b"refs/tags/";

/// A byte-preserving local ref name.
///
/// Git ref names are not required to be UTF-8.  Keeping their bytes makes a
/// completed snapshot suitable for repositories that use non-UTF-8 names.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct RefName(Vec<u8>);

impl RefName {
    /// Returns the exact bytes emitted by Git.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a lossy display representation. Use [`Self::as_bytes`] for
    /// persistence and comparison.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

/// The two mutable ref namespaces that become import roots.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum LocalRefKind {
    Branch,
    Tag,
}

/// One ref captured as part of an immutable snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SnapshotRef {
    pub name: RefName,
    pub kind: LocalRefKind,
    /// The direct object ID stored by this ref. An annotated tag therefore
    /// retains the tag object's own ID, rather than immediately peeling it.
    pub target: GitOid,
}

/// The local branch/tag namespace at one point in time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefSnapshot {
    pub algorithm: HashAlgorithm,
    pub refs: Vec<SnapshotRef>,
}

impl RefSnapshot {
    /// Returns the direct object IDs that should seed a reachability walk.
    pub fn roots(&self) -> Vec<GitOid> {
        self.refs.iter().map(|reference| reference.target).collect()
    }
}

/// One raw Git object fetched from a repository.
///
/// `data` is the uncompressed Git object payload: it does not include Git's
/// `"kind length\\0"` header. It is ready for `ContentId::for_object` and the
/// cold-store record codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitObject {
    pub oid: GitOid,
    pub kind: ObjectKind,
    pub data: Vec<u8>,
}

/// Errors from invoking or parsing system Git.
#[derive(Debug)]
pub enum GitBackendError {
    Io {
        command: &'static str,
        source: io::Error,
    },
    CommandFailed {
        command: &'static str,
        status: Option<i32>,
        stderr: String,
    },
    UnsupportedHashAlgorithm(String),
    InvalidGitOutput(&'static str),
    InvalidGitOid(InvalidGitOidLength),
    InvalidHexOid,
    UnknownObjectKind(String),
    MalformedObject {
        oid: GitOid,
        reason: &'static str,
    },
}

impl fmt::Display for GitBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { command, source } => write!(f, "cannot run git {command}: {source}"),
            Self::CommandFailed {
                command,
                status,
                stderr,
            } => {
                let stderr = stderr.trim();
                if stderr.is_empty() {
                    write!(f, "git {command} failed with status {status:?}")
                } else {
                    write!(f, "git {command} failed with status {status:?}: {stderr}")
                }
            }
            Self::UnsupportedHashAlgorithm(value) => {
                write!(f, "repository uses unsupported Git object format {value:?}")
            }
            Self::InvalidGitOutput(reason) => write!(f, "invalid output from git: {reason}"),
            Self::InvalidGitOid(error) => write!(f, "invalid Git object ID: {error}"),
            Self::InvalidHexOid => write!(f, "Git emitted a non-hexadecimal object ID"),
            Self::UnknownObjectKind(kind) => write!(f, "Git reported unknown object kind {kind:?}"),
            Self::MalformedObject { oid, reason } => {
                write!(f, "object {} is malformed: {reason}", oid_to_hex(oid))
            }
        }
    }
}

impl std::error::Error for GitBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidGitOid(error) => Some(error),
            _ => None,
        }
    }
}

impl From<InvalidGitOidLength> for GitBackendError {
    fn from(value: InvalidGitOidLength) -> Self {
        Self::InvalidGitOid(value)
    }
}

/// Common operations needed by an importer, independently of the Git
/// implementation used underneath it.
pub trait GitBackend {
    /// Native object-ID algorithm of the opened repository.
    fn hash_algorithm(&self) -> HashAlgorithm;

    /// Captures direct local branch and tag tips.
    fn snapshot_local_refs(&self) -> Result<RefSnapshot, GitBackendError>;

    /// Resolves one Git revision expression to its direct object ID.
    fn resolve_revision(&self, revision: &str) -> Result<GitOid, GitBackendError>;

    /// Reads every object reachable from `roots`, including root tags and all
    /// objects needed by commits and trees.
    fn reachable_objects(&self, roots: &[GitOid]) -> Result<Vec<GitObject>, GitBackendError>;
}

/// A local repository accessed through the installed `git` executable.
#[derive(Clone, Debug)]
pub struct SystemGitBackend {
    repository: PathBuf,
    git_program: OsString,
    algorithm: HashAlgorithm,
}

impl SystemGitBackend {
    /// Opens `repository` using `git` found on `PATH` and records its native
    /// object format. This performs no mutation and never invokes a shell.
    pub fn open(repository: impl AsRef<Path>) -> Result<Self, GitBackendError> {
        Self::open_with_program(repository, "git")
    }

    /// Like [`Self::open`], but uses an explicitly selected Git executable.
    /// This is useful for controlled compatibility testing.
    pub fn open_with_program(
        repository: impl AsRef<Path>,
        git_program: impl AsRef<OsStr>,
    ) -> Result<Self, GitBackendError> {
        let mut backend = Self {
            repository: repository.as_ref().to_path_buf(),
            git_program: git_program.as_ref().to_os_string(),
            // Replaced immediately after Git has identified the repository.
            algorithm: HashAlgorithm::Sha1,
        };
        backend.algorithm = backend.query_hash_algorithm()?;
        Ok(backend)
    }

    /// Filesystem path supplied when the backend was opened.
    pub fn repository(&self) -> &Path {
        &self.repository
    }

    /// Reads one object by its immutable native object ID.
    pub fn read_object(&self, oid: GitOid) -> Result<GitObject, GitBackendError> {
        self.ensure_algorithm(oid)?;
        let oid_text = oid_to_hex(&oid);
        let kind_bytes = self.run("cat-file -t", ["cat-file", "-t", oid_text.as_str()])?;
        let kind = parse_object_kind(trim_ascii(&kind_bytes))?;
        let type_name = object_kind_name(kind);
        let data = self.run("cat-file", ["cat-file", type_name, oid_text.as_str()])?;
        Ok(GitObject { oid, kind, data })
    }

    fn query_hash_algorithm(&self) -> Result<HashAlgorithm, GitBackendError> {
        let output = self.run(
            "rev-parse --show-object-format",
            ["rev-parse", "--show-object-format"],
        )?;
        match trim_ascii(&output) {
            b"sha1" => Ok(HashAlgorithm::Sha1),
            b"sha256" => Ok(HashAlgorithm::Sha256),
            other => Err(GitBackendError::UnsupportedHashAlgorithm(
                String::from_utf8_lossy(other).into_owned(),
            )),
        }
    }

    fn ensure_algorithm(&self, oid: GitOid) -> Result<(), GitBackendError> {
        if oid.algorithm() != self.algorithm {
            return Err(GitBackendError::InvalidGitOutput(
                "object ID algorithm does not match repository format",
            ));
        }
        Ok(())
    }

    fn run<I, S>(&self, command_name: &'static str, args: I) -> Result<Vec<u8>, GitBackendError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self
            .command(args)
            .output()
            .map_err(|source| GitBackendError::Io {
                command: command_name,
                source,
            })?;
        self.checked_output(command_name, output)
    }

    fn command<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(&self.git_program);
        command
            .current_dir(&self.repository)
            // These are global Git options, not shell text. Avoiding replace
            // refs makes an import name the repository's actual objects.
            .arg("--no-pager")
            .arg("--no-optional-locks")
            .arg("--no-replace-objects")
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_PAGER", "cat")
            .env("GIT_TERMINAL_PROMPT", "0")
            // Ambient repository-selection variables must not make a caller's
            // supplied path point at some other repository.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_REPLACE_REF_BASE");
        command
    }

    fn checked_output(
        &self,
        command_name: &'static str,
        output: Output,
    ) -> Result<Vec<u8>, GitBackendError> {
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(GitBackendError::CommandFailed {
                command: command_name,
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }
}

impl GitBackend for SystemGitBackend {
    fn hash_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    fn snapshot_local_refs(&self) -> Result<RefSnapshot, GitBackendError> {
        // `%00` creates a byte delimiter that cannot appear in a ref name.
        // `for-each-ref` returns both loose and packed refs in byte-sorted
        // order. No remote-tracking namespace is requested.
        let output = self.run(
            "for-each-ref",
            [
                "for-each-ref",
                "--format=%(refname)%00%(objectname)%00",
                "refs/heads",
                "refs/tags",
            ],
        )?;
        let mut refs = Vec::new();
        // `for-each-ref` adds a newline after each formatted record. Git ref
        // names reject newlines, while `%00` protects the two field values.
        for record in output.split(|byte| *byte == b'\n') {
            if record.is_empty() {
                continue;
            }
            let mut fields: Vec<&[u8]> = record.split(|byte| *byte == 0).collect();
            if fields.last() == Some(&b"".as_slice()) {
                fields.pop();
            }
            if fields.len() != 2 {
                return Err(GitBackendError::InvalidGitOutput(
                    "for-each-ref fields are not a name/object pair",
                ));
            }
            let name = fields[0];
            let object_name = fields[1];
            let kind = if name.starts_with(HEADS_PREFIX) {
                LocalRefKind::Branch
            } else if name.starts_with(TAGS_PREFIX) {
                LocalRefKind::Tag
            } else {
                return Err(GitBackendError::InvalidGitOutput(
                    "for-each-ref returned a ref outside requested namespaces",
                ));
            };
            refs.push(SnapshotRef {
                name: RefName(name.to_vec()),
                kind,
                target: parse_hex_oid(self.algorithm, object_name)?,
            });
        }
        Ok(RefSnapshot {
            algorithm: self.algorithm,
            refs,
        })
    }

    fn resolve_revision(&self, revision: &str) -> Result<GitOid, GitBackendError> {
        if revision.as_bytes().contains(&0) {
            return Err(GitBackendError::InvalidGitOutput(
                "revision contains a NUL byte",
            ));
        }
        // `--end-of-options` prevents a revision such as `--help` from being
        // interpreted as a Git CLI option. The argument is still parsed as a
        // Git revision expression, but is never interpreted by a shell.
        let output = self.run(
            "rev-parse --verify",
            ["rev-parse", "--verify", "--end-of-options", revision],
        )?;
        parse_single_oid(self.algorithm, &output)
    }

    fn reachable_objects(&self, roots: &[GitOid]) -> Result<Vec<GitObject>, GitBackendError> {
        let mut pending = VecDeque::with_capacity(roots.len());
        for &root in roots {
            self.ensure_algorithm(root)?;
            pending.push_back(root);
        }

        let mut seen = HashSet::new();
        let mut result = Vec::new();
        while let Some(oid) = pending.pop_front() {
            if !seen.insert(oid) {
                continue;
            }
            let object = self.read_object(oid)?;
            for child in referenced_oids(&object)? {
                pending.push_back(child);
            }
            result.push(object);
        }
        Ok(result)
    }
}

fn parse_single_oid(algorithm: HashAlgorithm, output: &[u8]) -> Result<GitOid, GitBackendError> {
    let output = trim_ascii(output);
    if output.is_empty() || output.contains(&b'\n') || output.contains(&b'\r') {
        return Err(GitBackendError::InvalidGitOutput(
            "expected exactly one object ID",
        ));
    }
    parse_hex_oid(algorithm, output)
}

fn parse_hex_oid(algorithm: HashAlgorithm, hex: &[u8]) -> Result<GitOid, GitBackendError> {
    if hex.len() != usize::from(algorithm.oid_len()) * 2 {
        return Err(GitBackendError::InvalidGitOutput(
            "object ID has an unexpected length",
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in hex.chunks_exact(2).enumerate() {
        bytes[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    GitOid::new(algorithm, &bytes[..usize::from(algorithm.oid_len())]).map_err(Into::into)
}

fn hex_digit(byte: u8) -> Result<u8, GitBackendError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(GitBackendError::InvalidHexOid),
    }
}

fn oid_to_hex(oid: &GitOid) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(usize::from(oid.len()) * 2);
    for byte in oid.as_bytes() {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn parse_object_kind(raw: &[u8]) -> Result<ObjectKind, GitBackendError> {
    match raw {
        b"commit" => Ok(ObjectKind::Commit),
        b"tree" => Ok(ObjectKind::Tree),
        b"blob" => Ok(ObjectKind::Blob),
        b"tag" => Ok(ObjectKind::Tag),
        other => Err(GitBackendError::UnknownObjectKind(
            String::from_utf8_lossy(other).into_owned(),
        )),
    }
}

fn object_kind_name(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Commit => "commit",
        ObjectKind::Tree => "tree",
        ObjectKind::Blob => "blob",
        ObjectKind::Tag => "tag",
    }
}

fn referenced_oids(object: &GitObject) -> Result<Vec<GitOid>, GitBackendError> {
    match object.kind {
        ObjectKind::Blob => Ok(Vec::new()),
        ObjectKind::Commit => parse_commit_references(object),
        ObjectKind::Tag => parse_tag_references(object),
        ObjectKind::Tree => parse_tree_references(object),
    }
}

fn parse_commit_references(object: &GitObject) -> Result<Vec<GitOid>, GitBackendError> {
    let header = object_header(&object.data);
    let mut tree = None;
    let mut parents = Vec::new();
    for line in header.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"tree ") {
            if tree.is_some() {
                return Err(malformed(object, "commit has more than one tree header"));
            }
            tree = Some(parse_hex_oid(object.oid.algorithm(), value)?);
        } else if let Some(value) = line.strip_prefix(b"parent ") {
            parents.push(parse_hex_oid(object.oid.algorithm(), value)?);
        }
    }
    let tree = tree.ok_or_else(|| malformed(object, "commit has no tree header"))?;
    let mut references = Vec::with_capacity(1 + parents.len());
    references.push(tree);
    references.extend(parents);
    Ok(references)
}

fn parse_tag_references(object: &GitObject) -> Result<Vec<GitOid>, GitBackendError> {
    let header = object_header(&object.data);
    let mut target = None;
    for line in header.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"object ") {
            if target.is_some() {
                return Err(malformed(object, "tag has more than one object header"));
            }
            target = Some(parse_hex_oid(object.oid.algorithm(), value)?);
        }
    }
    target
        .map(|oid| vec![oid])
        .ok_or_else(|| malformed(object, "tag has no object header"))
}

fn parse_tree_references(object: &GitObject) -> Result<Vec<GitOid>, GitBackendError> {
    let oid_len = usize::from(object.oid.algorithm().oid_len());
    let mut remaining = object.data.as_slice();
    let mut references = Vec::new();
    while !remaining.is_empty() {
        let nul = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| malformed(object, "tree entry is missing its NUL separator"))?;
        let header = &remaining[..nul];
        if !header.contains(&b' ') {
            return Err(malformed(
                object,
                "tree entry is missing mode/name separator",
            ));
        }
        let after_name = nul
            .checked_add(1)
            .ok_or_else(|| malformed(object, "tree entry length overflow"))?;
        let after_oid = after_name
            .checked_add(oid_len)
            .ok_or_else(|| malformed(object, "tree entry length overflow"))?;
        if remaining.len() < after_oid {
            return Err(malformed(object, "tree entry is missing object ID bytes"));
        }
        references.push(GitOid::new(
            object.oid.algorithm(),
            &remaining[after_name..after_oid],
        )?);
        remaining = &remaining[after_oid..];
    }
    Ok(references)
}

fn object_header(data: &[u8]) -> &[u8] {
    match data.windows(2).position(|window| window == b"\n\n") {
        Some(end) => &data[..end],
        None => data,
    }
}

fn malformed(object: &GitObject, reason: &'static str) -> GitBackendError {
    GitBackendError::MalformedObject {
        oid: object.oid,
        reason,
    }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TempRepository {
        path: PathBuf,
    }

    impl TempRepository {
        fn new() -> Self {
            let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "reflink-forest-git-test-{}-{nanos}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary repository directory");
            run_git(&path, ["init", "-b", "main"]);
            Self { path }
        }

        fn git<I, S>(&self, args: I)
        where
            I: IntoIterator<Item = S>,
            S: AsRef<OsStr>,
        {
            run_git(&self.path, args);
        }
    }

    impl Drop for TempRepository {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).expect("remove temporary repository directory");
        }
    }

    fn run_git<I, S>(repository: &Path, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = Command::new("git")
            .current_dir(repository)
            .args(args)
            .output()
            .expect("run test git command");
        assert!(
            output.status.success(),
            "test git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn make_repository() -> TempRepository {
        let repository = TempRepository::new();
        fs::create_dir(repository.path.join("dir")).expect("create nested directory");
        fs::write(repository.path.join("top.txt"), b"top-level blob\n").expect("write blob");
        fs::write(repository.path.join("dir/nested.txt"), b"nested blob\n")
            .expect("write nested blob");
        repository.git(["add", "."]);
        repository.git([
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "initial",
        ]);
        repository.git([
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.invalid",
            "tag",
            "-a",
            "v1",
            "-m",
            "annotated release",
        ]);
        // A remote-tracking ref must never become a snapshot root.
        repository.git(["update-ref", "refs/remotes/origin/main", "HEAD"]);
        repository
    }

    #[test]
    fn detects_hash_format_and_snapshots_only_local_refs() {
        let repository = make_repository();
        let backend = SystemGitBackend::open(&repository.path).expect("open backend");
        assert_eq!(backend.hash_algorithm(), HashAlgorithm::Sha1);

        let snapshot = backend.snapshot_local_refs().expect("snapshot refs");
        assert_eq!(snapshot.algorithm, HashAlgorithm::Sha1);
        assert_eq!(snapshot.refs.len(), 2);
        assert!(snapshot.refs.iter().any(|reference| {
            reference.kind == LocalRefKind::Branch
                && reference.name.as_bytes() == b"refs/heads/main"
        }));
        assert!(snapshot.refs.iter().any(|reference| {
            reference.kind == LocalRefKind::Tag && reference.name.as_bytes() == b"refs/tags/v1"
        }));
        assert!(snapshot
            .refs
            .iter()
            .all(|reference| !reference.name.as_bytes().starts_with(b"refs/remotes/")));
    }

    #[test]
    fn resolves_an_annotated_tag_without_peeling_it() {
        let repository = make_repository();
        let backend = SystemGitBackend::open(&repository.path).expect("open backend");
        let tag = backend.resolve_revision("v1").expect("resolve tag");
        assert_eq!(
            backend.read_object(tag).expect("read tag").kind,
            ObjectKind::Tag
        );

        let commit = backend.resolve_revision("main").expect("resolve branch");
        assert_eq!(
            backend.read_object(commit).expect("read commit").kind,
            ObjectKind::Commit
        );
        assert_ne!(tag, commit);
    }

    #[test]
    fn reachability_from_tag_includes_every_git_object_kind() {
        let repository = make_repository();
        let backend = SystemGitBackend::open(&repository.path).expect("open backend");
        let root = backend.resolve_revision("v1").expect("resolve tag");
        let objects = backend.reachable_objects(&[root]).expect("walk objects");

        let kinds: HashSet<ObjectKind> = objects.iter().map(|object| object.kind).collect();
        assert!(kinds.contains(&ObjectKind::Tag));
        assert!(kinds.contains(&ObjectKind::Commit));
        assert!(kinds.contains(&ObjectKind::Tree));
        assert!(kinds.contains(&ObjectKind::Blob));
        assert!(objects
            .iter()
            .any(|object| object.data == b"top-level blob\n"));
        assert!(objects.iter().any(|object| object.data == b"nested blob\n"));
        assert_eq!(
            objects.iter().filter(|object| object.oid == root).count(),
            1
        );
    }

    #[test]
    fn invalid_revision_is_not_treated_as_a_command_option() {
        let repository = make_repository();
        let backend = SystemGitBackend::open(&repository.path).expect("open backend");
        let error = backend
            .resolve_revision("--help")
            .expect_err("--help must be a revision, not an option");
        assert!(matches!(error, GitBackendError::CommandFailed { .. }));
    }

    #[test]
    fn hex_oid_parser_rejects_wrong_length_and_non_hex_data() {
        assert!(matches!(
            parse_hex_oid(HashAlgorithm::Sha1, b"abcd"),
            Err(GitBackendError::InvalidGitOutput(_))
        ));
        let invalid = [b'g'; 40];
        assert!(matches!(
            parse_hex_oid(HashAlgorithm::Sha1, &invalid),
            Err(GitBackendError::InvalidHexOid)
        ));
    }
}

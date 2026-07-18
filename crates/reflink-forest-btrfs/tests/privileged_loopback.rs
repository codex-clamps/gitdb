#![cfg(target_os = "linux")]

//! Tests that require a disposable loop device and `CAP_SYS_ADMIN`.
//!
//! This test is deliberately ignored in ordinary development and hosted CI.
//! Run it only on a dedicated VM where the caller has explicitly enabled it:
//!
//! ```text
//! REFLINK_FOREST_RUN_PRIVILEGED_BTRFS_TESTS=1 \
//!   cargo test -p reflink-forest-btrfs --test privileged_loopback -- --ignored
//! ```

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_btrfs::{
    initialize_loopback_image, initialize_native, native_layout, probe_clone_domain,
    read_instance_marker, verify_btrfs_mount, BtrfsError, ImageAllocation,
    LoopbackInitializationConfig, PrivilegedExecutor, PrivilegedExecutorConfig,
    SystemCommandRunner,
};

const OPT_IN_ENV: &str = "REFLINK_FOREST_RUN_PRIVILEGED_BTRFS_TESTS";
const CAP_SYS_ADMIN: u64 = 1 << 21;
const IMAGE_SIZE: u64 = 256 * 1024 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
#[ignore = "requires an isolated VM, loop devices, root, CAP_SYS_ADMIN, and REFLINK_FOREST_RUN_PRIVILEGED_BTRFS_TESTS=1"]
fn loopback_initialization_survives_reattach_and_refuses_overwrite() {
    require_explicit_opt_in();
    require_privileged_loopback_environment();

    let mut fixture = LoopbackFixture::new();
    let label = format!("rfs-privileged-{}", std::process::id());
    let marker_path = fixture.root().join("instance.marker");
    let initialization = LoopbackInitializationConfig::new(
        fixture.image_path(),
        fixture.root(),
        &marker_path,
        IMAGE_SIZE,
        ImageAllocation::Sparse,
        label,
        [0x51; 16],
    )
    .expect("configure a create-new fixed-purpose loopback initialization");
    let mut runner = SystemCommandRunner;
    let initialized = PrivilegedExecutor::initialize_new_loopback(&initialization, &mut runner)
        .expect("create, verify, and mark only the disposable Btrfs image");
    let image = initialized.image().to_path_buf();
    let marker = initialized.marker().clone();
    assert_eq!(
        read_instance_marker(&marker_path).expect("read back instance marker"),
        marker
    );

    // An ordinary pre-existing file is never a candidate for image creation
    // or formatting. Keep the bytes so this assertion also detects truncation.
    let unmarked = fixture.root().join("unmarked-existing-image");
    let mut sentinel = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&unmarked)
        .expect("create an unmarked sentinel file");
    sentinel
        .write_all(b"do not overwrite this unmarked path")
        .expect("write sentinel");
    sentinel.sync_all().expect("sync sentinel");
    assert!(matches!(
        initialize_loopback_image(&unmarked, IMAGE_SIZE, ImageAllocation::Sparse),
        Err(BtrfsError::ExistingPath(path)) if path == unmarked
    ));
    assert_eq!(
        fs::read(&unmarked).expect("read unchanged sentinel"),
        b"do not overwrite this unmarked path"
    );

    let config =
        PrivilegedExecutorConfig::new(&image, fixture.root(), fixture.mount_root(), marker)
            .expect("create fixed-purpose executor configuration");

    let first_device = mount_with_executor(config.clone());
    fixture.set_attached_device(&first_device);
    verify_btrfs_mount(fixture.mount_root()).expect("mounted image is Btrfs");
    let layout = native_layout(fixture.mount_root()).expect("derive native layout");
    initialize_native(&layout).expect("initialize Btrfs subvolume layout once");
    let probe = probe_clone_domain(&layout.cache, &layout.staging)
        .expect("cache and staging paths share a working clone domain");
    assert!(probe.reflink_succeeded && probe.mutation_isolated);

    // Simulate a reboot: remove the transient loop attachment and mount, then
    // create a fresh executor. Its image+marker identity is the only state it
    // may use to find the loop device again.
    fixture.unmount_and_detach(&first_device);
    let reattached_device = mount_with_executor(config.clone());
    fixture.set_attached_device(&reattached_device);
    verify_btrfs_mount(fixture.mount_root()).expect("reattached image is Btrfs");

    let mut reuse = PrivilegedExecutor::new(config, SystemCommandRunner);
    assert_eq!(
        reuse
            .attach_or_reuse()
            .expect("reuse exactly one existing loop association"),
        reattached_device
    );
    assert_eq!(
        associated_loop_count(&image),
        1,
        "a second executor must not create a duplicate loop association"
    );

    // Reinitializing on the mounted instance is also refused because the
    // layout's target subvolumes already exist.
    assert!(matches!(
        initialize_native(&layout),
        Err(BtrfsError::NonEmptyTarget(_))
    ));
}

#[test]
#[ignore = "requires an isolated VM, loop devices, root, CAP_SYS_ADMIN, and REFLINK_FOREST_RUN_PRIVILEGED_BTRFS_TESTS=1"]
fn loopback_mount_rejects_uuid_label_and_corrupt_marker_before_mount() {
    require_explicit_opt_in();
    require_privileged_loopback_environment();

    let fixture = LoopbackFixture::new();
    let marker_path = fixture.root().join("instance.marker");
    let initialization = LoopbackInitializationConfig::new(
        fixture.image_path(),
        fixture.root(),
        &marker_path,
        IMAGE_SIZE,
        ImageAllocation::Sparse,
        format!("rfs-identity-{}", std::process::id()),
        [0x52; 16],
    )
    .expect("configure a disposable fixed-purpose initializer");
    let mut runner = SystemCommandRunner;
    let initialized = PrivilegedExecutor::initialize_new_loopback(&initialization, &mut runner)
        .expect("format and mark only the disposable image");
    let image = initialized.image().to_path_buf();
    assert_eq!(associated_loop_count(&image), 1);
    assert_not_mounted(fixture.mount_root());

    let mut wrong_uuid = initialized.marker().clone();
    wrong_uuid.filesystem_uuid[0] ^= 0xff;
    let uuid_config =
        PrivilegedExecutorConfig::new(&image, fixture.root(), fixture.mount_root(), wrong_uuid)
            .expect("a syntactically valid but wrong marker can reach identity verification");
    assert!(matches!(
        PrivilegedExecutor::new(uuid_config, SystemCommandRunner).mount(),
        Err(BtrfsError::IdentityMismatch)
    ));
    assert_not_mounted(fixture.mount_root());
    assert_eq!(associated_loop_count(&image), 1);

    let mut wrong_label = initialized.marker().clone();
    wrong_label.label.push_str("-wrong");
    let label_config =
        PrivilegedExecutorConfig::new(&image, fixture.root(), fixture.mount_root(), wrong_label)
            .expect("a syntactically valid but wrong label can reach identity verification");
    assert!(matches!(
        PrivilegedExecutor::new(label_config, SystemCommandRunner).mount(),
        Err(BtrfsError::IdentityMismatch)
    ));
    assert_not_mounted(fixture.mount_root());
    assert_eq!(associated_loop_count(&image), 1);

    // A damaged persisted marker fails before an executor can be constructed;
    // in particular, it cannot cause a fresh attach, mount, or format attempt.
    fs::write(&marker_path, b"corrupt marker must not select an image")
        .expect("corrupt only the disposable marker");
    assert!(matches!(
        read_instance_marker(&marker_path),
        Err(BtrfsError::InvalidMarker)
    ));
    assert_not_mounted(fixture.mount_root());
    assert_eq!(associated_loop_count(&image), 1);
    assert_eq!(
        fs::metadata(&image).expect("read image metadata").len(),
        IMAGE_SIZE
    );
}

#[test]
#[ignore = "requires an isolated VM, loop devices, root, CAP_SYS_ADMIN, and REFLINK_FOREST_RUN_PRIVILEGED_BTRFS_TESTS=1"]
fn loopback_growth_refreshes_capacity_resizes_btrfs_and_never_shrinks() {
    require_explicit_opt_in();
    require_privileged_loopback_environment();

    let mut fixture = LoopbackFixture::new();
    let marker_path = fixture.root().join("instance.marker");
    let initialization = LoopbackInitializationConfig::new(
        fixture.image_path(),
        fixture.root(),
        &marker_path,
        IMAGE_SIZE,
        ImageAllocation::Sparse,
        format!("rfs-grow-{}", std::process::id()),
        [0x53; 16],
    )
    .expect("configure a disposable fixed-purpose initializer");
    let mut runner = SystemCommandRunner;
    let initialized = PrivilegedExecutor::initialize_new_loopback(&initialization, &mut runner)
        .expect("format and mark only the disposable image");
    let image = initialized.image().to_path_buf();
    let marker = initialized.marker().clone();
    let config =
        PrivilegedExecutorConfig::new(&image, fixture.root(), fixture.mount_root(), marker)
            .expect("create the fixed-purpose grow executor");

    let mounted_device = mount_with_executor(config.clone());
    fixture.set_attached_device(&mounted_device);
    verify_btrfs_mount(fixture.mount_root()).expect("mount disposable Btrfs before growth");
    let initial_size = fs::metadata(&image)
        .expect("read initialized image length")
        .len();
    assert_eq!(initial_size, IMAGE_SIZE);
    assert_eq!(loop_capacity_bytes(&mounted_device), initial_size);

    // A successful call proves the production ordering reached all three
    // external operations: grow file, refresh loop capacity, then resize the
    // mounted Btrfs filesystem. Each later assertion observes the prior step.
    let requested_size = initial_size + 64 * 1024 * 1024;
    let mut executor = PrivilegedExecutor::new(config, SystemCommandRunner);
    executor
        .grow(requested_size)
        .expect("grow image, refresh its loop capacity, and resize mounted Btrfs");
    assert_eq!(
        fs::metadata(&image).expect("read grown image length").len(),
        requested_size
    );
    assert_eq!(loop_capacity_bytes(&mounted_device), requested_size);
    verify_btrfs_mount(fixture.mount_root()).expect("grown filesystem remains mounted as Btrfs");

    // The refused shrink path must run before any destructive operation. The
    // backing file and loop capacity remain at the known grown value.
    assert!(matches!(
        executor.grow(initial_size),
        Err(BtrfsError::ShrinkNotSupported { current, requested })
            if current == requested_size && requested == initial_size
    ));
    assert_eq!(
        fs::metadata(&image)
            .expect("read image after refused shrink")
            .len(),
        requested_size
    );
    assert_eq!(loop_capacity_bytes(&mounted_device), requested_size);
}

fn mount_with_executor(config: PrivilegedExecutorConfig) -> String {
    let mut executor = PrivilegedExecutor::new(config, SystemCommandRunner);
    executor
        .mount()
        .expect("attach verified image and mount it at the fixed mount root")
}

fn associated_loop_count(image: &Path) -> usize {
    let mut list = Command::new("losetup");
    list.arg("--associated").arg(image);
    let output = run_checked(&mut list, "list associations for disposable image");
    String::from_utf8(output.stdout)
        .expect("losetup output is UTF-8")
        .lines()
        .filter(|line| line.starts_with("/dev/loop") && line.contains(':'))
        .count()
}

fn loop_capacity_bytes(device: &str) -> u64 {
    let mut capacity = Command::new("losetup");
    capacity.args(["--getsize64", device]);
    let output = run_checked(&mut capacity, "read disposable loop capacity");
    String::from_utf8(output.stdout)
        .expect("losetup capacity output is UTF-8")
        .trim()
        .parse()
        .expect("losetup capacity is an unsigned byte count")
}

fn assert_not_mounted(path: &Path) {
    let status = Command::new("mountpoint")
        .args(["--quiet", path.to_str().expect("temporary path is UTF-8")])
        .status()
        .expect("run mountpoint for disposable directory");
    assert_eq!(
        status.code(),
        Some(1),
        "identity failure must leave {} unmounted",
        path.display()
    );
}

fn require_explicit_opt_in() {
    assert_eq!(
        env::var(OPT_IN_ENV).ok().as_deref(),
        Some("1"),
        "set {OPT_IN_ENV}=1 before running this ignored destructive-capability test"
    );
}

fn require_privileged_loopback_environment() {
    let mut id = Command::new("id");
    id.arg("--user");
    let output = run_checked(&mut id, "determine effective user");
    assert_eq!(
        String::from_utf8(output.stdout)
            .expect("id output is UTF-8")
            .trim(),
        "0",
        "the privileged loopback test must run as root in its dedicated VM"
    );

    let cap_eff = fs::read_to_string("/proc/self/status")
        .expect("read Linux process capabilities")
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .expect("parse effective Linux capabilities");
    assert_ne!(
        cap_eff & CAP_SYS_ADMIN,
        0,
        "the privileged loopback test requires CAP_SYS_ADMIN; root in a restricted container is insufficient"
    );
    assert!(
        Path::new("/dev/loop-control").exists(),
        "the privileged loopback test requires /dev/loop-control"
    );
    for command in ["losetup", "mkfs.btrfs", "blkid", "mount", "umount", "btrfs"] {
        let mut check = Command::new(command);
        check.arg("--version");
        run_checked(&mut check, "check required privileged Btrfs command");
    }
}

fn run_checked(command: &mut Command, context: &str) -> Output {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{context}: could not start {command:?}: {error}"));
    assert!(
        output.status.success(),
        "{context}: {command:?} exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn detach_loop_device(device: &str) {
    let mut detach = Command::new("losetup");
    detach.args(["--detach", device]);
    run_checked(&mut detach, "detach disposable loop device");
}

struct LoopbackFixture {
    root: PathBuf,
    mount_root: PathBuf,
    image: PathBuf,
    attached_device: Option<String>,
}

impl LoopbackFixture {
    fn new() -> Self {
        let root = create_unique_temp_root();
        let mount_root = root.join("mount");
        fs::create_dir(&mount_root).expect("create disposable mount root");
        let image = root.join("forest.btrfs");
        Self {
            root,
            mount_root,
            image,
            attached_device: None,
        }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn mount_root(&self) -> &Path {
        &self.mount_root
    }

    fn image_path(&self) -> &Path {
        &self.image
    }

    fn set_attached_device(&mut self, device: &str) {
        self.attached_device = Some(device.to_owned());
    }

    fn unmount_and_detach(&mut self, device: &str) {
        let mut unmount = Command::new("umount");
        unmount.arg(&self.mount_root);
        run_checked(
            &mut unmount,
            "unmount disposable Btrfs image for reboot simulation",
        );
        detach_loop_device(device);
        self.attached_device = None;
    }
}

impl Drop for LoopbackFixture {
    fn drop(&mut self) {
        if self.attached_device.is_some() {
            let _ = Command::new("umount").arg(&self.mount_root).output();
        }
        // Query by the exact image path so cleanup never touches an unrelated
        // loop device. It also covers failures before `attached_device` was
        // recorded by the test body.
        if let Ok(output) = Command::new("losetup")
            .arg("--associated")
            .arg(&self.image)
            .output()
        {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines() {
                    if let Some((device, _)) = line.split_once(':') {
                        if device.starts_with("/dev/loop") {
                            let _ = Command::new("losetup").args(["--detach", device]).output();
                        }
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn create_unique_temp_root() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_nanos();
    let base = env::temp_dir();
    for attempt in 0..128 {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "reflink-forest-privileged-btrfs-{}-{timestamp}-{nonce}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!(
                "create unique disposable test root {}: {error}",
                path.display()
            ),
        }
    }
    panic!("could not create a unique disposable privileged Btrfs test root")
}

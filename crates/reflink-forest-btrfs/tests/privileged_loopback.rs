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
    initialize_loopback_image, initialize_native, native_layout, parse_blkid_export_identity,
    probe_clone_domain, read_instance_marker, verify_btrfs_mount, BtrfsError, ImageAllocation,
    InstanceMarker, PrivilegedExecutor, PrivilegedExecutorConfig, SystemCommandRunner,
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
    let image =
        initialize_loopback_image(fixture.image_path(), IMAGE_SIZE, ImageAllocation::Sparse)
            .expect("create the unique disposable backing image");

    let label = format!("rfs-privileged-{}", std::process::id());
    let mut mkfs = Command::new("mkfs.btrfs");
    mkfs.args(["--force", "--label"]).arg(&label).arg(&image);
    run_checked(&mut mkfs, "format only the disposable Btrfs image");

    let inspected = inspect_image_identity(&image);
    assert_eq!(inspected.label, label);
    let marker = InstanceMarker {
        instance_uuid: [0x51; 16],
        filesystem_uuid: inspected.filesystem_uuid,
        label,
    };
    let marker_path = fixture.root().join("instance.marker");
    reflink_forest_btrfs::write_instance_marker(&marker_path, &marker)
        .expect("write a create-new instance marker");
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

fn mount_with_executor(config: PrivilegedExecutorConfig) -> String {
    let mut executor = PrivilegedExecutor::new(config, SystemCommandRunner);
    executor
        .mount()
        .expect("attach verified image and mount it at the fixed mount root")
}

fn inspect_image_identity(image: &Path) -> reflink_forest_btrfs::InspectedFilesystem {
    let device = attach_for_inspection(image);
    let result = {
        let mut blkid = Command::new("blkid");
        blkid
            .args(["--output", "export", "--match-token", "TYPE=btrfs"])
            .arg(&device);
        let output = run_checked(&mut blkid, "inspect the newly formatted disposable image");
        parse_blkid_export_identity(&output.stdout).expect("parse Btrfs UUID and label")
    };
    detach_loop_device(&device);
    result
}

fn attach_for_inspection(image: &Path) -> String {
    let mut attach = Command::new("losetup");
    attach.args(["--find", "--show", "--nooverlap"]).arg(image);
    let output = run_checked(
        &mut attach,
        "attach disposable image for identity inspection",
    );
    String::from_utf8(output.stdout)
        .expect("losetup device name is UTF-8")
        .trim()
        .to_owned()
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

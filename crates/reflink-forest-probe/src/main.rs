//! A deliberately small, runtime FICLONE probe.
//!
//! Filesystem type, mount names, and configuration do not prove that the cache
//! and workspace roots can reflink. This executable tests the exact pair of
//! directories used by an instance.

#[cfg(not(target_os = "linux"))]
compile_error!("reflink-forest-probe requires Linux FICLONE support");

use std::{
    env,
    ffi::{c_int, c_ulong},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

// linux/fs.h: #define FICLONE _IOW(0x94, 9, int)
// This constant is stable in the Linux UAPI. Keeping the syscall boundary here
// avoids treating mount metadata as a proxy for actual clone capability.
const FICLONE: c_ulong = 0x4004_9409;

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

fn unique_path(directory: &Path, role: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_nanos();
    directory.join(format!(".reflink-forest-{role}-{}-{nanos}", process::id()))
}

fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

fn usage() -> ! {
    eprintln!("usage: reflink-forest-probe <cache-directory> <workspace-directory>");
    process::exit(2)
}

fn main() -> io::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let Some(cache_directory) = arguments.next() else {
        usage()
    };
    let Some(workspace_directory) = arguments.next() else {
        usage()
    };
    if arguments.next().is_some() {
        usage();
    }

    let cache_directory = PathBuf::from(cache_directory);
    let workspace_directory = PathBuf::from(workspace_directory);
    let source_path = unique_path(&cache_directory, "source");
    let destination_path = unique_path(&workspace_directory, "destination");

    let result = (|| -> io::Result<()> {
        let mut source = create_new(&source_path)?;
        source.write_all(b"reflink-forest clone probe: source bytes\n")?;
        source.sync_all()?;
        let mut destination = create_new(&destination_path)?;

        // SAFETY: both descriptors are open regular files. FICLONE takes the
        // source fd as an integer argument and does not retain it.
        let clone_result = unsafe { ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) };
        if clone_result != 0 {
            return Err(io::Error::last_os_error());
        }

        destination.write_all(b"destination mutation\n")?;
        destination.sync_all()?;
        drop(destination);
        drop(source);

        let source_bytes = fs::read(&source_path)?;
        if source_bytes != b"reflink-forest clone probe: source bytes\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "FICLONE probe source changed after destination mutation",
            ));
        }
        Ok(())
    })();

    let _ = fs::remove_file(&source_path);
    let _ = fs::remove_file(&destination_path);
    result?;
    println!("ficlone: supported");
    Ok(())
}

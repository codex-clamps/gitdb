//! Per-user Unix-socket daemon foundations.
//!
//! The daemon has one owner per instance and accepts requests only from that
//! Unix UID. It intentionally exposes no mount or ownership-changing action;
//! those remain a fixed-purpose privileged-helper concern.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
};

const LOCK_EX: std::ffi::c_int = 2;
const LOCK_NB: std::ffi::c_int = 4;
const LOCK_UN: std::ffi::c_int = 8;
const SOL_SOCKET: std::ffi::c_int = 1;
const SO_PEERCRED: std::ffi::c_int = 17;
#[repr(C)]
struct UCred {
    pid: i32,
    uid: u32,
    gid: u32,
}
unsafe extern "C" {
    fn flock(fd: std::ffi::c_int, operation: std::ffi::c_int) -> std::ffi::c_int;
    fn getsockopt(
        fd: std::ffi::c_int,
        level: std::ffi::c_int,
        option_name: std::ffi::c_int,
        option_value: *mut std::ffi::c_void,
        option_len: *mut u32,
    ) -> std::ffi::c_int;
    fn getuid() -> u32;
}

#[derive(Debug)]
pub enum DaemonError {
    Io(io::Error),
    AlreadyRunning,
    UnauthorizedPeer,
    InvalidSocketPath,
}
impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "daemon I/O error: {error}"),
            Self::AlreadyRunning => write!(f, "daemon instance is already running"),
            Self::UnauthorizedPeer => write!(f, "socket peer has a different Unix UID"),
            Self::InvalidSocketPath => write!(f, "refusing to remove non-socket runtime path"),
        }
    }
}
impl std::error::Error for DaemonError {}
impl From<io::Error> for DaemonError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub struct InstanceLock {
    file: File,
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        unsafe {
            flock(self.file.as_raw_fd(), LOCK_UN);
        }
    }
}
pub fn acquire_lock(path: impl AsRef<Path>) -> Result<InstanceLock, DaemonError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(DaemonError::AlreadyRunning);
        }
        return Err(error.into());
    }
    Ok(InstanceLock { file })
}

pub struct Daemon {
    listener: UnixListener,
    _lock: InstanceLock,
    socket: PathBuf,
}
impl Daemon {
    pub fn bind(runtime_dir: impl AsRef<Path>) -> Result<Self, DaemonError> {
        let runtime_dir = runtime_dir.as_ref();
        fs::create_dir_all(runtime_dir)?;
        fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o700))?;
        let lock = acquire_lock(runtime_dir.join("daemon.lock"))?;
        let socket = runtime_dir.join("daemon.sock");
        if socket.exists() {
            if !fs::symlink_metadata(&socket)?.file_type().is_socket() {
                return Err(DaemonError::InvalidSocketPath);
            }
            fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            _lock: lock,
            socket,
        })
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }
    /// Handles one line-oriented diagnostic request. Protocol commands are
    /// deliberately small until an authenticated typed protocol replaces it.
    pub fn serve_one(&self) -> Result<(), DaemonError> {
        let (stream, _) = self.listener.accept()?;
        ensure_same_uid(&stream)?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request = String::new();
        reader.read_line(&mut request)?;
        let mut stream = stream;
        match request.trim_end() {
            "status" => stream.write_all(b"ok\n")?,
            _ => stream.write_all(b"error unsupported-request\n")?,
        }
        stream.flush()?;
        Ok(())
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}
fn ensure_same_uid(stream: &UnixStream) -> Result<(), DaemonError> {
    let mut credential = UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<UCred>() as u32;
    if unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credential as *mut UCred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if length != std::mem::size_of::<UCred>() as u32 || credential.uid != unsafe { getuid() } {
        return Err(DaemonError::UnauthorizedPeer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };
    fn dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "reflink-forest-daemon-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    #[test]
    fn per_user_socket_and_lock_serve_status() {
        let dir = dir();
        let daemon = Daemon::bind(&dir).unwrap();
        assert!(matches!(
            Daemon::bind(&dir),
            Err(DaemonError::AlreadyRunning)
        ));
        let socket = daemon.socket_path().to_path_buf();
        let server = thread::spawn(move || daemon.serve_one().unwrap());
        let mut client = UnixStream::connect(socket).unwrap();
        client.write_all(b"status\n").unwrap();
        let mut result = String::new();
        BufReader::new(client).read_line(&mut result).unwrap();
        assert_eq!(result, "ok\n");
        server.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}

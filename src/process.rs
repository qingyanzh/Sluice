//! Finds which process owns a local socket, for `PROCESS-NAME` rules.
//!
//! On macOS every process's socket descriptors are walked with libproc
//! (`proc_listallpids` / `proc_pidinfo(PROC_PIDLISTFDS)` / `proc_pidfdinfo`). One walk
//! snapshots all sockets, and lookups share that snapshot for a short while, so a burst of
//! new connections costs one walk (a miss rescans). Other users' processes are only visible as root.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a snapshot answers lookups that it can answer.
const FRESH: Duration = Duration::from_secs(2);

/// (udp, local port) -> [(remote port, pid)].
type Sockets = HashMap<(bool, u16), Vec<(u16, i32)>>;

struct Snapshot {
    taken: Instant,
    sockets: Sockets,
    names: HashMap<i32, Option<String>>,
}

static SNAPSHOT: Mutex<Option<Snapshot>> = Mutex::new(None);

fn find(sockets: &Sockets, udp: bool, lport: u16, rport: u16) -> Option<i32> {
    let v = sockets.get(&(udp, lport))?;
    // Unconnected UDP sockets have no remote port.
    v.iter().find(|(r, _)| *r == rport).or_else(|| v.iter().find(|(r, _)| udp && *r == 0)).map(|(_, pid)| *pid)
}

/// Name of the process owning the TCP (or UDP) socket bound to local port `lport` and
/// connected to remote port `rport`. Blocking; call off the async runtime.
pub fn lookup(udp: bool, lport: u16, rport: u16) -> Option<String> {
    let mut guard = SNAPSHOT.lock().unwrap();
    let mut pid = guard.as_ref().filter(|s| s.taken.elapsed() < FRESH).and_then(|s| find(&s.sockets, udp, lport, rport));
    // A miss always rescans: the socket may be newer than the snapshot. Lookups queue on
    // the lock, so a burst of new connections still shares about one scan.
    if pid.is_none() {
        let sockets = sys::scan();
        pid = find(&sockets, udp, lport, rport);
        *guard = Some(Snapshot { taken: Instant::now(), sockets, names: HashMap::new() });
    }
    let pid = pid?;
    let snap = guard.as_mut()?;
    snap.names.entry(pid).or_insert_with(|| sys::name(pid)).clone()
}

#[cfg(target_os = "macos")]
mod sys {
    use super::Sockets;
    use std::ffi::c_void;
    use std::mem::size_of;

    const PROC_PIDFDSOCKETINFO: i32 = 3;
    // Offsets into `struct socket_fdinfo` (sys/proc_info.h): `proc_fileinfo` is 24 bytes,
    // then `socket_info`, whose `soi_proto` union starts at 240.
    const PSI: usize = 24;
    const SOI_PROTOCOL: usize = PSI + 156;
    const SOI_FAMILY: usize = PSI + 160;
    const SOI_KIND: usize = PSI + 232;
    const INSI_FPORT: usize = PSI + 240;
    const INSI_LPORT: usize = PSI + 244;
    /// sizeof(struct socket_fdinfo).
    const FDINFO_SIZE: usize = 792;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;

    fn i32_at(b: &[u8], off: usize) -> i32 {
        i32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
    }

    /// Ports are stored as ints holding a network-order u16.
    fn port_at(b: &[u8], off: usize) -> u16 {
        u16::from_be(i32_at(b, off) as u16)
    }

    fn pids() -> Vec<i32> {
        unsafe {
            let n = libc::proc_listallpids(std::ptr::null_mut(), 0);
            if n <= 0 {
                return Vec::new();
            }
            let mut v = vec![0i32; n as usize + 64];
            let n = libc::proc_listallpids(v.as_mut_ptr() as *mut c_void, (v.len() * size_of::<i32>()) as i32);
            v.truncate(n.max(0) as usize);
            v
        }
    }

    fn socket_fds(pid: i32) -> Vec<i32> {
        unsafe {
            let bytes = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
            if bytes <= 0 {
                return Vec::new();
            }
            let mut v: Vec<libc::proc_fdinfo> = Vec::with_capacity(bytes as usize / size_of::<libc::proc_fdinfo>() + 16);
            let cap = (v.capacity() * size_of::<libc::proc_fdinfo>()) as i32;
            let got = libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, v.as_mut_ptr() as *mut c_void, cap);
            if got <= 0 {
                return Vec::new();
            }
            v.set_len(got as usize / size_of::<libc::proc_fdinfo>());
            v.iter().filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32).map(|f| f.proc_fd).collect()
        }
    }

    pub fn scan() -> Sockets {
        let mut out = Sockets::new();
        let mut buf = [0u64; 128];
        for pid in pids() {
            for fd in socket_fds(pid) {
                let n = unsafe {
                    libc::proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, buf.as_mut_ptr() as *mut c_void, size_of::<[u64; 128]>() as i32)
                };
                if (n as usize) < FDINFO_SIZE {
                    continue;
                }
                let b = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, FDINFO_SIZE) };
                let family = i32_at(b, SOI_FAMILY);
                let kind = i32_at(b, SOI_KIND);
                if !(family == libc::AF_INET || family == libc::AF_INET6) || !(kind == SOCKINFO_IN || kind == SOCKINFO_TCP) {
                    continue;
                }
                let udp = match i32_at(b, SOI_PROTOCOL) {
                    libc::IPPROTO_TCP => false,
                    libc::IPPROTO_UDP => true,
                    _ => continue,
                };
                out.entry((udp, port_at(b, INSI_LPORT))).or_default().push((port_at(b, INSI_FPORT), pid));
            }
        }
        out
    }

    /// Executable file name (not truncated like `proc_name`).
    pub fn name(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
        if n > 0 {
            let path = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
            return path.rsplit('/').next().map(str::to_string).filter(|s| !s.is_empty());
        }
        let n = unsafe { libc::proc_name(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }
}

#[cfg(not(target_os = "macos"))]
mod sys {
    pub fn scan() -> super::Sockets {
        Default::default()
    }

    pub fn name(_pid: i32) -> Option<String> {
        None
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    fn me() -> String {
        std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn finds_own_tcp_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", server_port)).unwrap();
        let _accepted = listener.accept().unwrap();
        let client_port = client.local_addr().unwrap().port();
        assert_eq!(lookup(false, client_port, server_port), Some(me()));
        // Wrong remote port: not this socket.
        assert_eq!(find(&sys::scan(), false, client_port, server_port.wrapping_add(1)), None);
    }

    #[test]
    fn finds_own_udp_socket() {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        assert_eq!(lookup(true, port, 53), Some(me()));
    }
}

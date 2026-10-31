//! Finds which process owns a local socket, for connection records and `PROCESS-NAME` rules.
//!
//! On macOS every process's socket descriptors are walked with libproc
//! (`proc_listallpids` / `proc_pidinfo(PROC_PIDLISTFDS)` / `proc_pidfdinfo`). One walk
//! snapshots all sockets, and lookups share that snapshot for a short while, so a burst of
//! new connections costs one walk (a miss rescans). Other users' processes are only visible as root.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a snapshot answers lookups that it can answer.
const FRESH: Duration = Duration::from_secs(2);

struct SocketOwner {
    local_ip: IpAddr,
    remote_port: u16,
    pid: i32,
}

/// (udp, local port) -> socket owners, including wildcard-bound UDP sockets.
type Sockets = HashMap<(bool, u16), Vec<SocketOwner>>;

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

struct Snapshot {
    taken: Instant,
    sockets: Sockets,
    names: HashMap<i32, Option<String>>,
}

static SNAPSHOT: Mutex<Option<Snapshot>> = Mutex::new(None);

fn find(sockets: &Sockets, udp: bool, local: SocketAddr, rport: u16) -> Option<i32> {
    let v = sockets.get(&(udp, local.port()))?;
    let ip = canonical(local.ip());
    let matches = |s: &&SocketOwner| s.remote_port == rport || (udp && s.remote_port == 0);
    // Prefer the address-specific socket over a wildcard UDP binding on the same port.
    v.iter().filter(matches).find(|s| s.local_ip == ip)
        .or_else(|| v.iter().filter(matches).find(|s| udp && s.local_ip.is_unspecified()))
        .map(|s| s.pid)
}

/// Name of the process owning the TCP (or UDP) socket bound to `local` and
/// connected to remote port `rport`. Blocking; call off the async runtime.
pub fn lookup(udp: bool, local: SocketAddr, rport: u16) -> Option<String> {
    let mut guard = SNAPSHOT.lock().unwrap();
    let mut pid = guard.as_ref().filter(|s| s.taken.elapsed() < FRESH).and_then(|s| find(&s.sockets, udp, local, rport));
    // A miss always rescans: the socket may be newer than the snapshot. Lookups queue on
    // the lock, so a burst of new connections still shares about one scan.
    if pid.is_none() {
        let sockets = sys::scan();
        pid = find(&sockets, udp, local, rport);
        *guard = Some(Snapshot { taken: Instant::now(), sockets, names: HashMap::new() });
    }
    let pid = pid?;
    let snap = guard.as_mut()?;
    snap.names.entry(pid).or_insert_with(|| sys::name(pid)).clone()
}

#[cfg(target_os = "macos")]
mod sys {
    use super::{canonical, SocketOwner, Sockets};
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const PROC_PIDFDSOCKETINFO: i32 = 3;
    // Offsets into `struct socket_fdinfo` (sys/proc_info.h): `proc_fileinfo` is 24 bytes,
    // then `socket_info`, whose `soi_proto` union starts at 240.
    const PSI: usize = 24;
    const SOI_PROTOCOL: usize = PSI + 156;
    const SOI_FAMILY: usize = PSI + 160;
    const SOI_KIND: usize = PSI + 232;
    const INSI_FPORT: usize = PSI + 240;
    const INSI_LPORT: usize = PSI + 244;
    const INSI_VFLAG: usize = PSI + 264;
    const INSI_LADDR: usize = PSI + 288;
    /// sizeof(struct socket_fdinfo).
    // Verified against sizeof/offsetof in the macOS SDK's sys/proc_info.h.
    // TCP's tcpsi_ini is the first member of pri_tcp, so both kinds use these ports.
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
        let mut buf = [0u64; FDINFO_SIZE / 8];
        for pid in pids() {
            for fd in socket_fds(pid) {
                let n = unsafe {
                    libc::proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, buf.as_mut_ptr() as *mut c_void, FDINFO_SIZE as i32)
                };
                if n != FDINFO_SIZE as i32 {
                    continue;
                }
                let b = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, FDINFO_SIZE) };
                if let Some((udp, port, owner)) = socket_owner(b, pid) {
                    out.entry((udp, port)).or_default().push(owner);
                }
            }
        }
        out
    }

    fn socket_owner(b: &[u8], pid: i32) -> Option<(bool, u16, SocketOwner)> {
        let family = i32_at(b, SOI_FAMILY);
        let kind = i32_at(b, SOI_KIND);
        if !(family == libc::AF_INET || family == libc::AF_INET6) || !(kind == SOCKINFO_IN || kind == SOCKINFO_TCP) {
            return None;
        }
        let udp = match (i32_at(b, SOI_PROTOCOL), kind) {
            (libc::IPPROTO_TCP, SOCKINFO_TCP) => false,
            (libc::IPPROTO_UDP, SOCKINFO_IN) => true,
            _ => return None,
        };
        // INI_IPV4 uses in4in6_addr: twelve padding bytes, then the IPv4 address.
        // AF_INET6 sockets can carry IPv4, so use insi_vflag rather than family.
        let local_ip = if b[INSI_VFLAG] & 1 != 0 {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&b[INSI_LADDR + 12..INSI_LADDR + 16]).unwrap()))
        } else {
            canonical(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[INSI_LADDR..INSI_LADDR + 16]).unwrap())))
        };
        Some((udp, port_at(b, INSI_LPORT), SocketOwner { local_ip, remote_port: port_at(b, INSI_FPORT), pid }))
    }

    /// Executable file name (not truncated like `proc_name`).
    pub fn name(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
        if n > 0 {
            let path = String::from_utf8_lossy(&buf[..n as usize]).trim_end_matches('\0').to_string();
            return path.rsplit('/').next().map(str::to_string).filter(|s| !s.is_empty());
        }
        let n = unsafe { libc::proc_name(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn socket_layout_ports_and_kinds() {
            let mut b = [0u8; FDINFO_SIZE];
            let put = |b: &mut [u8], offset, value: i32| b[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            put(&mut b, SOI_FAMILY, libc::AF_INET6);
            put(&mut b, SOI_PROTOCOL, libc::IPPROTO_TCP);
            put(&mut b, SOI_KIND, SOCKINFO_TCP);
            put(&mut b, INSI_LPORT, 6252u16.to_be() as i32);
            put(&mut b, INSI_FPORT, 443u16.to_be() as i32);
            b[INSI_VFLAG] = 1;
            b[INSI_LADDR + 12..INSI_LADDR + 16].copy_from_slice(&[127, 0, 0, 1]);
            let (udp, port, owner) = socket_owner(&b, 42).unwrap();
            assert!(!udp);
            assert_eq!(port, 6252);
            assert_eq!(owner.remote_port, 443);
            assert_eq!(owner.local_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
            assert_eq!(owner.pid, 42);
            put(&mut b, SOI_KIND, SOCKINFO_IN);
            assert!(socket_owner(&b, 42).is_none());
            put(&mut b, SOI_PROTOCOL, libc::IPPROTO_UDP);
            put(&mut b, INSI_FPORT, 0);
            b[INSI_VFLAG] = 2;
            b[INSI_LADDR..INSI_LADDR + 16].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            let (udp, port, owner) = socket_owner(&b, 42).unwrap();
            assert!(udp);
            assert_eq!(port, 6252);
            assert_eq!(owner.remote_port, 0);
            assert_eq!(owner.local_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
            put(&mut b, SOI_FAMILY, libc::AF_UNIX);
            assert!(socket_owner(&b, 42).is_none());
        }
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
        let local = client.local_addr().unwrap();
        assert_eq!(find(&sys::scan(), false, local, server_port), Some(std::process::id() as i32));
        assert_eq!(lookup(false, local, server_port), Some(me()));
        assert_eq!(lookup(false, local, server_port), Some(me()));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let cfg = crate::config::Config::parse("[Rule]\nFINAL,DIRECT\n").unwrap();
            let router = crate::router::Router::new(&cfg).unwrap();
            let target = crate::util::Target::parse_authority("process-test.example:443", 443).unwrap();
            for mode in [crate::router::Mode::Rule, crate::router::Mode::Direct, crate::router::Mode::Global] {
                router.set_mode(mode);
                let ctx = crate::rule::ConnInfo::new(crate::rule::Proto::Tcp, Some(local), Some(server_port), server_port);
                let decision = router.decide_logged(&target, &ctx).await.unwrap();
                assert_eq!(decision.process, Some(me()));
                assert!(crate::conns::recent().iter().any(|c| c.target == target.to_string() && c.process == Some(me())));
            }
        });
        // Wrong remote port: not this socket.
        assert_eq!(find(&sys::scan(), false, local, server_port.wrapping_add(1)), None);
    }

    #[test]
    fn finds_own_ipv6_sockets() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client = TcpStream::connect(server).unwrap();
        let _accepted = listener.accept().unwrap();
        assert_eq!(lookup(false, client.local_addr().unwrap(), server.port()), Some(me()));
        let udp = UdpSocket::bind("[::]:0").unwrap();
        assert_eq!(lookup(true, udp.local_addr().unwrap(), 53), Some(me()));
    }

    #[test]
    fn finds_own_udp_socket() {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = s.local_addr().unwrap();
        assert_eq!(find(&sys::scan(), true, local, 53), Some(std::process::id() as i32));
        assert_eq!(lookup(true, local, 53), Some(me()));
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect(peer.local_addr().unwrap()).unwrap();
        let remote = peer.local_addr().unwrap().port();
        assert_eq!(lookup(true, local, remote), Some(me()));
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;

    #[test]
    fn matches_addresses_mapped_ipv4_and_udp_wildcards() {
        let mut sockets = Sockets::new();
        sockets.insert((false, 12345), vec![
            SocketOwner { local_ip: "127.0.0.2".parse().unwrap(), remote_port: 6252, pid: 1 },
            SocketOwner { local_ip: "127.0.0.1".parse().unwrap(), remote_port: 6252, pid: 2 },
        ]);
        assert_eq!(find(&sockets, false, "[::ffff:127.0.0.1]:12345".parse().unwrap(), 6252), Some(2));
        assert_eq!(find(&sockets, false, "127.0.0.1:12345".parse().unwrap(), 6253), None);
        sockets.insert((true, 12345), vec![SocketOwner { local_ip: "::".parse().unwrap(), remote_port: 0, pid: 3 }]);
        assert_eq!(find(&sockets, true, "[::1]:12345".parse().unwrap(), 53), Some(3));
    }
}

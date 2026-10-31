//! Finds which process owns a local socket, for connection records and `PROCESS-NAME` rules.
//!
//! On macOS every process's socket descriptors are walked with libproc
//! (`proc_listallpids` / `proc_pidinfo(PROC_PIDLISTFDS)` / `proc_pidfdinfo`). One walk
//! snapshots all sockets, and lookups share that snapshot for a short while, so a burst of
//! new connections can share one walk (misses and wildcard matches rescan).
//! Other users' processes are only visible as root.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a snapshot answers exact socket lookups.
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

impl Snapshot {
    fn cached_pid(&self, udp: bool, local: SocketAddr, rport: u16) -> Option<i32> {
        if self.taken.elapsed() >= FRESH {
            return None;
        }
        let owner = find(&self.sockets, udp, local, rport)?;
        // A cached wildcard may hide a more specific socket opened since the scan.
        (!owner.local_ip.is_unspecified() && owner.local_ip == canonical(local.ip()) && owner.remote_port == rport)
            .then_some(owner.pid)
    }
}

static SNAPSHOT: Mutex<Option<Snapshot>> = Mutex::new(None);

fn find(sockets: &Sockets, udp: bool, local: SocketAddr, rport: u16) -> Option<&SocketOwner> {
    let v = sockets.get(&(udp, local.port()))?;
    let ip = canonical(local.ip());
    let own_pid = std::process::id() as i32;
    // Rank by local address, then connected peer. For equally specific sockets
    // (e.g. a descriptor shared across processes), prefer our own process.
    v.iter()
        .filter(|s| {
            (s.local_ip == ip || (udp && s.local_ip.is_unspecified()))
                && (s.remote_port == rport || (udp && s.remote_port == 0))
        })
        .max_by_key(|s| (s.local_ip == ip, s.remote_port == rport, s.pid == own_pid))
}

/// Name of the process owning the TCP (or UDP) socket bound to `local` and
/// connected to remote port `rport`. Blocking; call off the async runtime.
pub fn lookup(udp: bool, local: SocketAddr, rport: u16) -> Option<String> {
    let mut guard = SNAPSHOT.lock().unwrap();
    let mut pid = guard.as_ref().and_then(|s| s.cached_pid(udp, local, rport));
    // Misses and wildcard matches rescan: a more specific socket may be newer than
    // the snapshot. Exact matches share the scan while it is fresh.
    if pid.is_none() {
        let sockets = sys::scan();
        pid = find(&sockets, udp, local, rport).map(|s| s.pid);
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
        assert_eq!(find(&sys::scan(), false, local, server_port).map(|s| s.pid), Some(std::process::id() as i32));
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
        assert!(find(&sys::scan(), false, local, server_port.wrapping_add(1)).is_none());
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
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect(peer.local_addr().unwrap()).unwrap();
        let local = s.local_addr().unwrap();
        let remote = peer.local_addr().unwrap().port();
        assert_eq!(find(&sys::scan(), true, local, remote).map(|s| s.pid), Some(std::process::id() as i32));
        assert_eq!(lookup(true, local, remote), Some(me()));
        assert_eq!(lookup(true, local, remote), Some(me()));
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;

    #[test]
    fn udp_matches_are_ranked_by_address_then_peer_regardless_of_scan_order() {
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let own_pid = std::process::id() as i32;
        for reverse in [false, true] {
            let mut owners = vec![
                SocketOwner { local_ip: "::".parse().unwrap(), remote_port: 0, pid: own_pid },
                SocketOwner { local_ip: "0.0.0.0".parse().unwrap(), remote_port: 53, pid: -44 },
                SocketOwner { local_ip: local.ip(), remote_port: 0, pid: -43 },
                SocketOwner { local_ip: local.ip(), remote_port: 53, pid: -42 },
                SocketOwner { local_ip: "127.0.0.2".parse().unwrap(), remote_port: 53, pid: -41 },
                SocketOwner { local_ip: local.ip(), remote_port: 54, pid: -40 },
            ];
            if reverse {
                owners.reverse();
            }
            let mut sockets = Sockets::from([((true, local.port()), owners)]);
            for expected in [-42, -43, -44, own_pid] {
                assert_eq!(find(&sockets, true, local, 53).map(|s| s.pid), Some(expected));
                sockets.get_mut(&(true, local.port())).unwrap().retain(|s| s.pid != expected);
            }
            assert!(find(&sockets, true, local, 53).is_none());
        }
    }

    #[test]
    fn equally_specific_sockets_prefer_own_pid() {
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let own_pid = std::process::id() as i32;
        for udp in [false, true] {
            for pids in [[own_pid, -1], [-1, own_pid]] {
                let owners = pids.into_iter().map(|pid| SocketOwner { local_ip: local.ip(), remote_port: 53, pid }).collect();
                let sockets = Sockets::from([((udp, local.port()), owners)]);
                assert_eq!(find(&sockets, udp, local, 53).map(|s| s.pid), Some(own_pid));
            }
        }
    }

    #[test]
    fn cached_wildcards_require_a_rescan_before_returning_an_owner() {
        let local: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut snapshot = Snapshot {
            taken: Instant::now(),
            sockets: Sockets::from([((true, local.port()), vec![
                SocketOwner { local_ip: "0.0.0.0".parse().unwrap(), remote_port: 53, pid: -1 },
            ])]),
            names: HashMap::new(),
        };
        assert_eq!(find(&snapshot.sockets, true, local, 53).map(|s| s.pid), Some(-1));
        assert_eq!(snapshot.cached_pid(true, local, 53), None);
        snapshot.sockets.get_mut(&(true, local.port())).unwrap().push(
            SocketOwner { local_ip: local.ip(), remote_port: 0, pid: -2 },
        );
        assert_eq!(snapshot.cached_pid(true, local, 53), None);
        snapshot.sockets.get_mut(&(true, local.port())).unwrap().push(
            SocketOwner { local_ip: local.ip(), remote_port: 53, pid: -3 },
        );
        assert_eq!(snapshot.cached_pid(true, local, 53), Some(-3));
        snapshot.taken = Instant::now() - FRESH;
        assert_eq!(snapshot.cached_pid(true, local, 53), None);
    }

    #[test]
    fn matches_addresses_mapped_ipv4_and_udp_wildcards() {
        let mut sockets = Sockets::new();
        sockets.insert((false, 12345), vec![
            SocketOwner { local_ip: "127.0.0.2".parse().unwrap(), remote_port: 6252, pid: 1 },
            SocketOwner { local_ip: "127.0.0.1".parse().unwrap(), remote_port: 6252, pid: 2 },
        ]);
        assert_eq!(find(&sockets, false, "[::ffff:127.0.0.1]:12345".parse().unwrap(), 6252).map(|s| s.pid), Some(2));
        assert!(find(&sockets, false, "127.0.0.1:12345".parse().unwrap(), 6253).is_none());
        sockets.insert((true, 12345), vec![SocketOwner { local_ip: "::".parse().unwrap(), remote_port: 0, pid: 3 }]);
        assert_eq!(find(&sockets, true, "[::1]:12345".parse().unwrap(), 53).map(|s| s.pid), Some(3));
    }
}

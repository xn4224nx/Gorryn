/*
 * Scanning functions that utalise a variety of methods to investigate domains.
 */

const SCAN_DELAY_SEC: u64 = 3;

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Determine via a simple tcp connect scan if a port is open.
fn tcp_connect_port_scan(domain_port: &SocketAddr) -> bool {
    return if let Ok(_) =
        TcpStream::connect_timeout(domain_port, Duration::from_secs(SCAN_DELAY_SEC))
    {
        true
    } else {
        false
    };
}

/// Test all the ports on a domain and find the open ones.
fn find_open_ports(domain: &String, ports: &Vec<u16>) -> Vec<u16> {
    let mut open_ports = Vec::new();

    /* Resolve the Domain. */
    let mut addr: Vec<SocketAddr> = format!("{}:1042", domain)
        .to_socket_addrs()
        .unwrap_or("localhost:443".to_socket_addrs().unwrap())
        .collect();

    /* Catch a failure to resolve the supplied domain. */
    if addr[0] == SocketAddr::from(([127, 0, 0, 1], 443)) {
        return Vec::new();
    }

    /* Construct the socket connections and see if they are open.  */
    for prt_num in ports.iter() {
        addr[0].set_port(*prt_num);

        if tcp_connect_port_scan(&addr[0]) {
            open_ports.push(*prt_num);
        }
    }
    return open_ports;
}

/// Scan some of the most commonly used ports
pub fn common_ports(domain: &String) -> Vec<u16> {
    return find_open_ports(domain, &vec![7, 20, 21, 22, 80, 88]);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tcp_connect_port_scan_exp01() {
        let sock: Vec<_> = "bbc.co.uk:80".to_socket_addrs().unwrap().collect();
        assert_eq!(tcp_connect_port_scan(&sock[0]), true);
    }

    #[test]
    fn tcp_connect_port_scan_exp02() {
        let sock: Vec<_> = "cnn.com:80".to_socket_addrs().unwrap().collect();
        assert_eq!(tcp_connect_port_scan(&sock[0]), true);
    }

    #[test]
    fn find_open_ports_exp01() {
        assert_eq!(
            find_open_ports(&"bbc.co.uk".to_string(), &vec![80]),
            vec![80]
        );
    }

    #[test]
    fn find_open_ports_exp02() {
        assert_eq!(find_open_ports(&"cnn.com".to_string(), &vec![80]), vec![80]);
    }
}

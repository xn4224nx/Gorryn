/*
 * Scanning functions that utalise a variety of methods to investigate domains.
 */

const SCAN_DELAY_SEC: u64 = 3;

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Determine via a simple tcp connect scan if a port is open.
pub fn tcp_connect_port_scan(domain_port: &SocketAddr) -> bool {
    return if let Ok(_) =
        TcpStream::connect_timeout(domain_port, Duration::from_secs(SCAN_DELAY_SEC))
    {
        true
    } else {
        false
    };
}

/// Test all the ports on a domain and find the open ones.
pub fn find_open_ports(domain: &String, ports: &Vec<u16>) -> Vec<u16> {
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

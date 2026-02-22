/*
 * Scanning functions that utalise a variety of methods to investigate domains.
 */

const SCAN_DELAY_SEC: u64 = 3;

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// An asyncronous port scanner
pub fn domain_port_scan(sub_dom_url: &str, ports: &Vec<u16>) -> Vec<u16> {
    let mut socket_addresses: Vec<SocketAddr> = format!("{}:1024", sub_dom_url)
        .to_socket_addrs()
        .unwrap_or("localhost:443".to_socket_addrs().unwrap())
        .collect();

    /* Catch a failure to resolve the supplied domain. */
    if socket_addresses[0] == SocketAddr::from(([127, 0, 0, 1], 443)) {
        return Vec::new();
    }

    /* Ensure that there is scanning to do. */
    if socket_addresses.is_empty() {
        return Vec::new();
    }

    return ports
        .into_iter()
        .filter_map(|x| tcp_connect_port_scan(&mut socket_addresses[0], *x))
        .collect();
}

/// Determine via a simple tcp connect scan if a port is open.
pub fn tcp_connect_port_scan(soc: &mut SocketAddr, port: u16) -> Option<u16> {
    soc.set_port(port);
    return if let Ok(_) = TcpStream::connect_timeout(soc, Duration::from_secs(SCAN_DELAY_SEC)) {
        Some(port)
    } else {
        None
    };
}

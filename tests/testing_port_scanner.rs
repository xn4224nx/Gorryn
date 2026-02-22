#[allow(dead_code)]
#[allow(unused_variables)]
#[path = "../src/port_scanner.rs"]
mod main;
use main::*;
use std::net::ToSocketAddrs;

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

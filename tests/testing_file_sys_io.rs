#[allow(dead_code)]
#[allow(unused_variables)]
#[path = "../src/file_sys_io.rs"]
mod main;
use main::*;
use std::path::PathBuf;

#[test]
fn generate_file_nm_exp_00() {
    assert_eq!(
        generate_file_nm("bbc.co.uk"),
        PathBuf::from("bbc_co_uk.txt")
    );
}

#[test]
fn generate_file_nm_exp_01() {
    assert_eq!(generate_file_nm("cnn.com"), PathBuf::from("cnn_com.txt"));
}

#[test]
fn generate_file_nm_exp_02() {
    assert_eq!(generate_file_nm("FT.COM"), PathBuf::from("ft_com.txt"));
}

#[test]
#[should_panic]
fn load_dom_txt_file_exp00() {
    load_dom_txt_file("DOES_NOT_EXIST.txt").unwrap();
}

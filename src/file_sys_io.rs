/*
 * Functions associated with interacting with files and folder and other
 * operating system tasks.
 */

use std::fs::{File, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

/// See if this subdomain has data already saved on disk. If so read it and
/// return it.
pub fn load_dom_txt_file(root_domain: &str) -> Option<Vec<String>> {
    let mut buffer = String::new();
    let mut prev_domains = Vec::new();

    /* Try and open the data file */
    let data_file_pth = generate_file_nm(root_domain);
    let file_ent = File::open(data_file_pth).ok()?;
    let mut f_ptr = BufReader::new(file_ent);

    /* Try and read the previous subdomain data. */
    while f_ptr.read_line(&mut buffer).ok()? > 0 {
        prev_domains.push(buffer.trim_end().to_string());
        buffer.clear();
    }
    return Some(prev_domains);
}

/// Save subdomain data to disk in a text file.
pub fn save_dom_txt_file(root_domain: &str, sub_doms: &Vec<String>) -> Option<()> {
    let data_file_pth = generate_file_nm(root_domain);

    /* Does the data file exist, if so delete it. */
    if data_file_pth.exists() {
        remove_file(&data_file_pth).ok()?;
    }

    /* Create the file and open it. */
    let data_file = File::create(&data_file_pth).ok()?;
    let mut f_ptr = BufWriter::new(data_file);

    /* Write the data to it. */
    for sd_idx in 0..sub_doms.len() {
        writeln!(f_ptr, "{}", sub_doms[sd_idx]).ok()?;
    }
    return Some(());
}

/// Generate the file name of the domain data file.
pub fn generate_file_nm(root_domain: &str) -> PathBuf {
    let mut filepath = PathBuf::from(&root_domain.replace(".", "_").to_lowercase());
    filepath.set_extension("txt");
    return filepath;
}

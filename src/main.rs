/*
 * Chapter 2 - Tricorder
 */

mod crt_sh_scrape;
mod file_sys_io;
mod parse_args;
mod port_scanner;

fn main() {
    let root_domain = parse_args::get();

    println!(
        "\nDOMAIN: {}\n{}",
        root_domain.to_ascii_uppercase(),
        "=".repeat(root_domain.len() + 8)
    );

    /* Get the sub-domain URLs. */
    let sub_domains = if let Some(res) = file_sys_io::load_dom_txt_file(&root_domain) {
        println!("\tSubdomains loaded from disk: {}", res.len());
        res
    } else {
        println!("\tNo data on disk, consulting api.");
        let sdoms = crt_sh_scrape::cont_get(&root_domain);
        println!("\tSubdomains loaded from the api: {}", sdoms.len());
        println!(
            "\tData {} saved to disk.",
            if file_sys_io::save_dom_txt_file(&root_domain, &sdoms).is_some() {
                "sucessfully"
            } else {
                "NOT"
            }
        );
        sdoms
    };

    /* Scan all the sub-domains. */
    for sdom in sub_domains.into_iter() {
        print!("\t{: <50} - ", sdom.to_ascii_uppercase());
        let open_ports = port_scanner::common_ports(&sdom);
        print!("{}", open_ports.len());
        if !open_ports.is_empty() {
            println!(" - {:?}", open_ports);
        } else {
            println!();
        }
    }
}

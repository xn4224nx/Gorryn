/*
 * Chapter 2 - Tricorder
 */

mod parse_args;
mod scanner;
mod subdomains;

fn main() {
    let root_domain = parse_args::get();
    println!(
        "\nDOMAIN: {}\n{}",
        root_domain.to_ascii_uppercase(),
        "=".repeat(root_domain.len() + 8)
    );

    /* Consult the API and try and get the related sub-domains. */
    let sub_domains = subdomains::lookup(&root_domain);
    println!("\tSUBDOMAINS = {}", sub_domains.len());

    /* Scan all the sub-domains. */
    for sdom in sub_domains.into_iter() {
        print!("\t{: <50} - ", sdom.to_ascii_uppercase());
        let open_ports = scanner::common_ports(&sdom);
        print!("{}", open_ports.len());
        if !open_ports.is_empty() {
            println!(" - {:?}", open_ports);
        } else {
            println!();
        }
    }
}

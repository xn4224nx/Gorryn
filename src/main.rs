/*
 * Chapter 2 - Tricorder
 */

mod crt_sh_scrape;
mod file_sys_io;
mod parse_args;
mod port_scanner;
use rayon::prelude::*;

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

    /* Create the thread pool. */
    let thread_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(256)
        .build()
        .unwrap();

    /* Scan all the sub-domains. */
    thread_pool.install(|| {
        let results: Vec<(String, Vec<u16>)> = sub_domains
            .into_par_iter()
            .map(|url| {
                (
                    url.clone(),
                    port_scanner::domain_port_scan(&url, &vec![7, 20, 21, 22, 80, 88]),
                )
            })
            .collect();

        /* Show the results. */
        for r_idx in 0..results.len() {
            if !results[r_idx].1.is_empty() {
                println!("\t{}:{:?}", results[r_idx].0, results[r_idx].1);
            }
        }
    });
}

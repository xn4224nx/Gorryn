/*
 * Make a blocking web request to the `crt.sh` certificate search site, to list
 * related subdomains to an overarching domain.
 */

use std::collections::HashSet;

/// The interface function to the module that returns the subdomain urls
pub fn cont_get(root_domain: &str) -> Vec<String> {
    let mut scan_delay: u64 = 1;

    /* Keep trying until a response is recieved. */
    loop {
        let Some(sub_doms) = make_api_request(root_domain) else {
            std::thread::sleep(std::time::Duration::from_secs(scan_delay));
            scan_delay = scan_delay.wrapping_mul(2);
            continue;
        };
        return sub_doms;
    }
}

/// Use the site to get a distinct list of sub-domains
pub fn make_api_request(root_domain: &str) -> Option<Vec<String>> {
    return extract_subdomains(
        &reqwest::blocking::get(format!("https://crt.sh/?q=%25.{}&output=json", root_domain))
            .ok()?
            .text()
            .ok()?,
    );
}

/// Take the raw body result and extract the subdomains
pub fn extract_subdomains(raw_body: &String) -> Option<Vec<String>> {
    let mut sub_domains = HashSet::new();

    /* Parse the raw text into a Json. */
    let all_dom_info: serde_json::Value = serde_json::from_str(raw_body).ok()?;

    /* From the parsed data extract the subdomains. */
    for dom_info in all_dom_info.as_array()?.into_iter() {
        for pote_key_nm in vec!["common_name", "name_value"] {
            let Some(s_dom) = dom_info.get(pote_key_nm).and_then(|x| x.as_str()) else {
                continue;
            };

            /* Ignore wild card and invalid domains */
            if s_dom.contains("*") || s_dom.contains("\n") {
                continue;
            }
            sub_domains.insert(s_dom.trim().to_string());
        }
    }

    /* Ensure sub-domains have been found. */
    return if sub_domains.is_empty() {
        None
    } else {
        Some(sub_domains.into_iter().collect())
    };
}

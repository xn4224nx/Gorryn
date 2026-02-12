/*
 * Using the `crt.sh` certificate search site, look up related subdomains.
 */

use std::collections::HashSet;
use std::fs::{File, create_dir_all, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

const SUB_DOM_DIR: &str = "./subdirs/";

/// An overall function to handle saving and reading the subdoamins from disk.
pub fn lookup(root_domain: &str) -> Vec<String> {
    /* Is there valid subdomin data saved on disk */
    if let Some(data) = read_saved_data(root_domain) {
        return data;
    };

    /* Otherwise consult the API. */
    let api_doms = cont_get(root_domain);

    /* Save the API data to disk. */
    save_api_data(root_domain, &api_doms);

    return api_doms;
}

/// Read the pre-saved domain lookup if it exists.
fn read_saved_data(root_domain: &str) -> Option<Vec<String>> {
    let does_dir_exist = Path::new(SUB_DOM_DIR).try_exists();

    /* Does the subdomain folder exist? If not create it */
    if does_dir_exist.is_err() || does_dir_exist.unwrap() == false {
        create_dir_all(SUB_DOM_DIR).ok()?;
        return None;
    }

    /* Try and open the data file */
    let data_file_pth = Path::new(SUB_DOM_DIR).join(root_domain.replace(".", "_").to_lowercase());
    let file_ent = File::open(data_file_pth).ok()?;
    let mut f_ptr = BufReader::new(file_ent);
    let mut buffer = String::new();
    let mut prev_domains = Vec::new();

    /* Try and read the previous subdomain data. */
    while f_ptr.read_line(&mut buffer).ok()? > 0 {
        prev_domains.push(buffer.trim_end().to_string());
        buffer.clear();
    }

    return Some(prev_domains);
}

/// Save the api data to disk
fn save_api_data(root_domain: &str, sub_doms: &Vec<String>) -> Option<()> {
    let data_file_pth = Path::new(SUB_DOM_DIR).join(root_domain.replace(".", "_").to_lowercase());
    let does_dir_exist = Path::new(SUB_DOM_DIR).try_exists();

    /* Does the subdomain folder exist? If not create it */
    if does_dir_exist.is_err() || does_dir_exist.unwrap() == false {
        create_dir_all(SUB_DOM_DIR).ok()?;
    }

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

/// Keep attempting to get the subdomains.
fn cont_get(root_domain: &str) -> Vec<String> {
    let mut scan_delay: u64 = 1;

    /* Keep trying until a response is recieved. */
    loop {
        let Some(sub_doms) = get(root_domain) else {
            std::thread::sleep(std::time::Duration::from_secs(scan_delay));
            scan_delay = scan_delay.wrapping_mul(2);
            continue;
        };
        return sub_doms;
    }
}

/// Use the site to get a distint list of sub-domains
fn get(root_domain: &str) -> Option<Vec<String>> {
    return extract_subdomains(
        &reqwest::blocking::get(format!("https://crt.sh/?q=%25.{}&output=json", root_domain))
            .ok()?
            .text()
            .ok()?,
    );
}

/// Take the raw body result and extract the subdomains
fn extract_subdomains(raw_body: &String) -> Option<Vec<String>> {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn extract_subdomains_exp01() {
        assert_eq!(
            extract_subdomains(&String::from(
                r###"[{
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "common_name": "training.test.appsec.tools.bbc.co.uk",
    "name_value": "training.test.appsec.tools.bbc.co.uk",
    "id": 2140472224,
    "entry_timestamp": "2019-11-22T08:21:05.796",
    "not_before": "2019-11-22T08:21:04",
    "not_after": "2020-11-22T08:21:04",
    "serial_number": "46dce252667042c43e9b5c37",
    "result_count": 2
  }]"###
            ))
            .unwrap(),
            vec!["training.test.appsec.tools.bbc.co.uk".to_string()]
        );
    }

    #[test]
    fn extract_subdomains_exp02() {
        assert_eq!(
            extract_subdomains(&String::from(
                r###"[{
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "common_name": "training.test.appsec.tools.bbc.co.uk",
    "name_value": "training.test.appsec.tools.bbc.co.uk",
    "id": 2140472224,
    "entry_timestamp": "2019-11-22T08:21:05.796",
    "not_before": "2019-11-22T08:21:04",
    "not_after": "2020-11-22T08:21:04",
    "serial_number": "46dce252667042c43e9b5c37",
    "result_count": 2
  },
  {
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "common_name": "training.appsec.tools.bbc.co.uk",
    "name_value": "training.appsec.tools.bbc.co.uk",
    "id": 2140460592,
    "entry_timestamp": "2019-11-22T08:16:16.804",
    "not_before": "2019-11-22T08:16:14",
    "not_after": "2020-11-22T08:16:14",
    "serial_number": "4ed82742e2267f3e5f61d19b",
    "result_count": 2
  }]"###
            ))
            .unwrap()
            .into_iter()
            .collect::<HashSet<String>>(),
            HashSet::from([
                "training.appsec.tools.bbc.co.uk".to_string(),
                "training.test.appsec.tools.bbc.co.uk".to_string()
            ])
        );
    }

    #[test]
    fn extract_subdomains_exp03() {
        assert_eq!(
            extract_subdomains(&String::from(
                r###"[{
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "name_value": "training.test.appsec.tools.bbc.co.uk",
    "id": 2140472224,
    "entry_timestamp": "2019-11-22T08:21:05.796",
    "not_before": "2019-11-22T08:21:04",
    "not_after": "2020-11-22T08:21:04",
    "serial_number": "46dce252667042c43e9b5c37",
    "result_count": 2
  },
  {
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "name_value": "training.appsec.tools.bbc.co.uk",
    "id": 2140460592,
    "entry_timestamp": "2019-11-22T08:16:16.804",
    "not_before": "2019-11-22T08:16:14",
    "not_after": "2020-11-22T08:16:14",
    "serial_number": "4ed82742e2267f3e5f61d19b",
    "result_count": 2
  }]"###
            ))
            .unwrap()
            .into_iter()
            .collect::<HashSet<String>>(),
            HashSet::from([
                "training.appsec.tools.bbc.co.uk".to_string(),
                "training.test.appsec.tools.bbc.co.uk".to_string()
            ])
        );
    }

    #[test]
    fn extract_subdomains_exp04() {
        assert_eq!(
            extract_subdomains(&String::from(
                r###"[{
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "common_name": "training.test.appsec.tools.bbc.co.uk",
    "id": 2140472224,
    "entry_timestamp": "2019-11-22T08:21:05.796",
    "not_before": "2019-11-22T08:21:04",
    "not_after": "2020-11-22T08:21:04",
    "serial_number": "46dce252667042c43e9b5c37",
    "result_count": 2
  },
  {
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "common_name": "training.appsec.tools.bbc.co.uk",
    "id": 2140460592,
    "entry_timestamp": "2019-11-22T08:16:16.804",
    "not_before": "2019-11-22T08:16:14",
    "not_after": "2020-11-22T08:16:14",
    "serial_number": "4ed82742e2267f3e5f61d19b",
    "result_count": 2
  }]"###
            ))
            .unwrap()
            .into_iter()
            .collect::<HashSet<String>>(),
            HashSet::from([
                "training.appsec.tools.bbc.co.uk".to_string(),
                "training.test.appsec.tools.bbc.co.uk".to_string()
            ])
        );
    }

    #[test]
    #[should_panic]
    fn extract_subdomains_exp05() {
        extract_subdomains(&String::from(
            r###"[{
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "id": 2140472224,
    "entry_timestamp": "2019-11-22T08:21:05.796",
    "not_before": "2019-11-22T08:21:04",
    "not_after": "2020-11-22T08:21:04",
    "serial_number": "46dce252667042c43e9b5c37",
    "result_count": 2
  },
  {
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "id": 2140460592,
    "entry_timestamp": "2019-11-22T08:16:16.804",
    "not_before": "2019-11-22T08:16:14",
    "not_after": "2020-11-22T08:16:14",
    "serial_number": "4ed82742e2267f3e5f61d19b",
    "result_count": 2
  }]"###,
        ))
        .unwrap();
    }

    #[test]
    fn extract_subdomains_exp06() {
        assert_eq!(
            extract_subdomains(&String::from(
                r###"[  {
    "issuer_ca_id": 107462,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018",
    "common_name": "*.myconnect.bbc.co.uk",
    "name_value": "*.myconnect.bbc.co.uk\nmyconnect.bbc.co.uk",
    "id": 2147644388,
    "entry_timestamp": "2019-11-27T10:46:08.404",
    "not_before": "2019-11-27T10:46:06",
    "not_after": "2021-01-01T12:21:03",
    "serial_number": "02fc19b7f8806c9d900854bd",
    "result_count": 3
  },  {
    "issuer_ca_id": 9324,
    "issuer_name": "C=US, O=Amazon, OU=Server CA 1B, CN=Amazon",
    "common_name": "bobcat.sammg.cfp.ch.bbc.co.uk",
    "name_value": "bobcat.sammg.cfp.ch.bbc.co.uk",
    "id": 2150147737,
    "entry_timestamp": "2019-11-27T11:42:38.081",
    "not_before": "2019-11-27T00:00:00",
    "not_after": "2020-12-27T12:00:00",
    "serial_number": "0787c0dafc8b8f006be5480140f53a87",
    "result_count": 2
  }]"###
            ))
            .unwrap()
            .into_iter()
            .collect::<HashSet<String>>(),
            HashSet::from(["bobcat.sammg.cfp.ch.bbc.co.uk".to_string()])
        );
    }

    #[test]
    fn extract_subdomains_exp07() {
        assert_eq!(
            extract_subdomains(&String::from(
                r###"[  {
    "issuer_ca_id": 9324,
    "issuer_name": "C=US, O=Amazon, OU=Server CA 1B, CN=Amazon",
    "common_name": "bobcat.pdn.cfp.ch.bbc.co.uk",
    "name_value": "bobcat.pdn.cfp.ch.bbc.co.uk",
    "id": 2140738312,
    "entry_timestamp": "2019-11-22T10:13:20.319",
    "not_before": "2019-11-22T00:00:00",
    "not_after": "2020-12-22T12:00:00",
    "serial_number": "0e93aeaac7deda50139b5f6013f094e5",
    "result_count": 2
  },
  {
    "issuer_ca_id": 107694,
    "issuer_name": "C=BE, O=GlobalSign nv-sa, CN=GlobalSign ECC OV SSL CA 2018",
    "common_name": "*.bidi.net.uk",
    "name_value": "*.bidi.live.bbc.co.uk\n*.sp.bidi.live.bbc.co.uk",
    "id": 2140482913,
    "entry_timestamp": "2019-11-22T08:26:05.384",
    "not_before": "2019-11-22T08:26:03",
    "not_after": "2020-11-22T08:26:03",
    "serial_number": "60ef5ba1a3372300de6ba4de",
    "result_count": 2
  }]"###
            ))
            .unwrap()
            .into_iter()
            .collect::<HashSet<String>>(),
            HashSet::from(["bobcat.pdn.cfp.ch.bbc.co.uk".to_string(),])
        );
    }
}

#[allow(dead_code)]
#[allow(unused_variables)]
#[path = "../src/crt_sh_scrape.rs"]
mod main;
use main::*;
use std::collections::HashSet;

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

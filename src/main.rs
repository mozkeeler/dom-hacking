#[macro_use]
extern crate clap;
extern crate rand;
extern crate whois_rust;

use clap::App;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use whois_rust::{WhoIs, WhoIsLookupOptions};

use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() -> std::io::Result<()> {
    let yaml = load_yaml!("cli.yaml");
    let matches = App::from_yaml(yaml).get_matches();
    let verbose = matches.is_present("verbose");

    let words = File::open("words_alpha.txt")?;
    let words_reader = BufReader::new(words);
    let mut words_list = Vec::with_capacity(400_000);
    for word in words_reader.lines() {
        if let Ok(word) = word {
            words_list.push(word);
        }
    }
    let gtlds = File::open("tlds-alpha-by-domain.txt")?;
    let gtlds_reader = BufReader::new(gtlds);
    let mut gtlds_list = Vec::with_capacity(1600);
    for gtld in gtlds_reader.lines() {
        if let Ok(gtld) = gtld {
            if !gtld.starts_with('#') {
                gtlds_list.push(gtld.to_lowercase());
            }
        }
    }

    match do_it(&words_list, &gtlds_list, verbose) {
        Ok(()) => Ok(()),
        Err(()) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "something went wrong",
        )),
    }
}

fn do_it(words_list: &[String], gtlds_list: &[String], verbose: bool) -> Result<(), ()> {
    let whois = WhoIs::from_path("node-whois/servers.json").map_err(|_| ())?;

    if let Some((word, gtld)) = find_word_and_suffix(words_list, gtlds_list) {
        assert!(word.len() > gtld.len());
        let (word_trimmed, _) = word.split_at(word.len() - gtld.len());
        let (parts, domain_to_check) = if word_trimmed.len() > 1 {
            let mut rng = thread_rng();
            let index = rng.gen_range(1, word_trimmed.len());
            let (subdomain, domain) = word_trimmed.split_at(index);
            (
                vec![subdomain, domain, gtld],
                format!("{}.{}", domain, gtld),
            )
        } else {
            (
                vec![word_trimmed, gtld],
                format!("{}.{}", word_trimmed, gtld),
            )
        };
        if is_domain_unregistered(&whois, &domain_to_check, verbose)? {
            println!("Your neato domain hack is '{}'", parts.join("."));
        }
    }
    Ok(())
}

fn is_domain_unregistered(whois: &WhoIs, domain: &str, verbose: bool) -> Result<bool, ()> {
    let lookup = WhoIsLookupOptions::from_domain(domain).map_err(|_| ())?;
    let result = whois.lookup(lookup).map_err(|_| ())?;
    if verbose {
        eprintln!("{}", result);
    }
    let lowercase = result.to_lowercase();
    Ok(lowercase.contains("no entries found")
        || lowercase.contains("not found")
        || lowercase.contains("no match for"))
}

fn find_word_and_suffix<'a>(
    words_list: &'a [String],
    suffix_list: &'a [String],
) -> Option<(&'a String, &'a String)> {
    let mut rng = thread_rng();
    for _ in 0..100 {
        if let Some(word) = words_list.choose(&mut rng) {
            for suffix in suffix_list.iter() {
                if word.ends_with(suffix) {
                    return Some((word, suffix));
                }
            }
        }
    }
    None
}

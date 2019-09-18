extern crate rand;

use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() -> std::io::Result<()> {
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

    if let Some((word, gtld)) = find_word_and_suffix(&words_list, &gtlds_list) {
        assert!(word.len() > gtld.len());
        let (word_trimmed, _) = word.split_at(word.len() - gtld.len());
        let parts = if word_trimmed.len() > 1 {
            let mut rng = thread_rng();
            let index = rng.gen_range(1, word_trimmed.len());
            let (subdomain, domain) = word_trimmed.split_at(index);
            vec![subdomain, domain, gtld]
        } else {
            vec![word_trimmed, gtld]
        };
        println!("{}", parts.join("."));
    }
    Ok(())
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

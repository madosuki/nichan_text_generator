use std::collections::HashMap;
use chrono::{NaiveDateTime, Datelike};
use hex;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::md5::Md5;
use pwhash::unix::crypt;
use base64::prelude::*;
use regex::Regex;

use rand::Rng;

use encoding::{Encoding, EncoderTrap};
use encoding::all::WINDOWS_31J;

mod error;
use error::{NichanTextGeneratorError, NichanTextGeneratorResult};

pub enum OldTripDigit {
    Ten,
    Eight,
    None
}

pub fn create_trip(key: &str, digit: OldTripDigit) -> Option<String> {
    let old_trip = |bytes: Vec<u8>| -> Option<String> {

        let mut salt_base: Vec<char> = vec!();
        let mut key_base: Vec<u8> = vec!();
    
        let mut count = 0;
        for i in &bytes {

            key_base.push(i.to_owned());

            if count == 1 || count == 2 {
                salt_base.push(i.to_owned() as char);
            }

            if count == 8 {
                break;
            }
            
            count = count + 1;
        }


        let salt_base_string: String = salt_base.iter().collect();

        let salt_base = 
            if salt_base_string.len() == 2 {
                salt_base_string
            } else { format!("{}H.", salt_base_string) };

        let re = Regex::new(r"[^.-z]").unwrap();

        let my_tr = |a: &str| -> String {
            let convert_table_dictionary: HashMap<char, char> =
                [(':', 'A'),
                 (';', 'B'),
                 ('<', 'C'),
                 ('=', 'D'),
                 ('>', 'E'),
                 ('?', 'F'),
                 ('@', 'G'),
                 ('[', 'a'),
                 ('\\', 'b'),
                 (']', 'c'),
                 ('^', 'd'),
                 ('_', 'e'),
                 ('`', 'f')].iter().cloned().collect();
        
            let find = |x: char| -> char {

                match convert_table_dictionary.get_key_value(&x) {
                    Some((_, v)) => { v.to_owned() }
                    None => x
                }
            };
        
            a.to_owned().chars().map(|x| find(x)).collect::<String>()
        };
    
        let tmp_salt = re.replace_all(&salt_base, ".");
        let final_salt = my_tr(&tmp_salt);

        let crypted = crypt(&key_base, &final_salt);
    
        let get_result = |a: &str| -> Option<String> {
            let start = a.len() - 
                match digit {
                    OldTripDigit::Ten => 10,
                    OldTripDigit::Eight => 8,
                    OldTripDigit::None => 10,
                };
            let end = a.len();

            let data = a[start..end].to_owned();

            let result = format!("◆{}", data);
            Some(result)
        };

        match crypted {
            Ok(v) => { get_result(&v) }
            Err(_e) => {
                None
            }
        }
    };

    let base = &key[1..];
    if let Ok(bytes) = WINDOWS_31J.encode(base, EncoderTrap::Strict) {

        if bytes.len() < 12  {
            old_trip(bytes)
        } else {
            let mut hasher = Sha1::new();
            hasher.input(&bytes);
        
            let sha1_str = hasher.result_str();
            let hex_bytes = hex::decode(sha1_str);
            if hex_bytes.is_err() {
                return None;
            }
            let sha1_base64_str = BASE64_STANDARD.encode(hex_bytes.unwrap());
            
            let result = format!("◆{}", sha1_base64_str[..12].to_string());
        
            Some(result)
        }
    } else {
        None
    }
}

pub fn create_id(naive_date_time: NaiveDateTime, bbs_key: &str, ip_addr: &str, secret_key: &str) -> Option<String> {
    let a_day_tmp = naive_date_time.day();
    let a_day = if a_day_tmp < 10 { format!("0{}", a_day_tmp)} else { a_day_tmp.to_string() };

    let target = format!("{}{}{}{}", a_day, bbs_key, ip_addr, secret_key);
    
    let mut hasher = Md5::new();
    hasher.input(target.as_bytes());
    let md5_str = hasher.result_str();
    if let Ok(hex_bytes) = hex::decode(md5_str) {
        let md5_base64_str = BASE64_STANDARD.encode(hex_bytes);

        Some(format!("ID:{}", md5_base64_str[..8].to_string()))
    } else {
        None
    }
}

pub fn apply_dice(text: &str) -> NichanTextGeneratorResult<String> {
    let re = Regex::new(r"!([0-9]{1,3})[dD]([0-9]{1,4})").unwrap();

    let tmp = text.to_owned();

    let replace_result = re.replace_all(&tmp, |cap: &regex::Captures| -> String {
        let left_str = cap[1].to_owned();
        let right_str = cap[2].to_owned();

        let target: Result<i32, _> = cap[2].parse();
        if target.is_err() {
            return "".to_string();
        }
        let real_target = target.unwrap();
        let parsed_roll_max: Result<i32, _> = cap[1].parse();
        if parsed_roll_max.is_err() {
            return "".to_string();
        }
        let mut roll_max = parsed_roll_max.unwrap();
        let mut result_number: i32 = 0;
        while roll_max != 0 {
            result_number += rand::thread_rng().gen_range(0..(real_target + 1));
            roll_max -= 1;
        }

        let final_replace_string = format!("【{}D{}: {}】", left_str, right_str, result_number).to_owned();

        final_replace_string.to_string()
    });

    if replace_result == "" {
        Err(NichanTextGeneratorError::NotApplyDiceCommand)
    } else {
        let result = replace_result.into_owned();
        Ok(result)
    }
}

pub fn create_date(_naive_date_time: NaiveDateTime) -> String  {
    _naive_date_time.format("%Y/%m/%d(%a) %H:%M:%S.%f").to_string()
}

pub fn detect_tripkey_from_name(name: &str) -> Option<(String, String)> {

    let mut splitter = name.splitn(2, "#");

    let first = splitter.next();
    
    let second =
        match splitter.next() {
            Some(v) => Some(format!("#{}", v)),
            None => None
        };

    match (first, second) {
        (Some(x), Some(y)) => Some((x.to_string(), y)),
        _ => None
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_trip() {
        let first_result = "◆/WG5qp963c".to_owned();
        assert_eq!(create_trip("#istrip", OldTripDigit::Ten), Some(first_result));

        let second_result = "◆pA8Bpf.Qvk".to_owned();
        assert_eq!(create_trip("#ニコニコ", OldTripDigit::Ten), Some(second_result));

        let third_result = "◆MtEMe4z5ZXDK".to_owned();
        assert_eq!(create_trip("#abcdefghijklmnopqrstuvwxyz", OldTripDigit::None), Some(third_result));
    }

    #[test]
    fn test_create_id() {
        let date_format = "%Y/%m/%d %H:%M:%S";
        let date_str = "2021/02/17 18:01:23";
        let date = NaiveDateTime::parse_from_str(date_str, date_format).unwrap();

        assert_eq!(create_id(date, "key", "127.0.0.1", "test_secret_key"), Some("ID:JBs13t0r".to_owned()));
    }

    #[test]
    fn test_apply_dice() {
        let re = Regex::new(r"!([0-9]{1,3})[dD]([0-9]{1,4})").unwrap();
        let result = apply_dice("!1d100");
        assert_eq!(result.is_ok(), true);
        assert_eq!(re.is_match(&result.unwrap()), false);
    }

    #[test]
    fn test_create_date() {
        let date_format = "%Y/%m/%d %H:%M:%S";
        let date_str = "2021/02/17 18:01:23";
        let date = NaiveDateTime::parse_from_str(date_str, date_format).unwrap();

        assert_eq!(create_date(date), "2021/02/17(Wed) 18:01:23.000000000");
    }

    #[test]
    fn test_detect_tripkey_from_name() {
        let trip_key = "#ニコニコ".to_owned();
        let separated_name = "あいうえお".to_owned();
        let source = "あいうえお#ニコニコ";
        assert_eq!(detect_tripkey_from_name(source), Some((separated_name, trip_key)));
    }
}

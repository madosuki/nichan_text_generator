use std::collections::HashMap;
use pwhash::unix::crypt;
use regex::Regex;

use encoding::{Encoding, EncoderTrap};
use encoding::all::WINDOWS_31J;

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

        let prepare1 = 
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
    
        let prepare2 = re.replace_all(&prepare1, ".");
        let salt = my_tr(&prepare2);

        let _crypted = crypt(&key_base, &salt);
    
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

        match _crypted {
            Ok(v) => { get_result(&v) }
            Err(_e) => {
                println!("crypt error: {}", _e);
                None
            }
        }
    };

    let base = key[1..].to_owned();
    let bytes = WINDOWS_31J.encode(&base, EncoderTrap::Strict).unwrap();

    if bytes.len() < 12  {
        old_trip(bytes)
    } else {
        None
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
    }
}

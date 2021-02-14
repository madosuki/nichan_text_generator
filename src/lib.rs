use std::collections::HashMap;
use pwhash::unix::crypt;
use regex::Regex;

use encoding::{Encoding, EncoderTrap};
use encoding::all::WINDOWS_31J;

pub fn create_trip(key: &str) -> String {
    let bytes = WINDOWS_31J.encode(key, EncoderTrap::Strict);
    let mut tmp: Vec<u8> = vec!();
    let mut salt_base: Vec<u8> = vec!();
    let mut is_first = true;
    let mut count = 0;
    for i in bytes {
        for j in i {
            if !is_first {
                tmp.push(j.to_owned());

                if count == 1 || count == 2 {
                    salt_base.push(j.to_owned());
                }

                count = count + 1;
            } else {
                is_first = false;
            }

            if tmp.len() == 8 {
                break;
            }
        }
    }

    let key_test_decode = String::from_utf8_lossy(&tmp);
    let owned_key = key_test_decode.as_ref().to_owned();

    let salt_base_test_decode = String::from_utf8_lossy(&salt_base);
    let salt_base_string = salt_base_test_decode.as_ref().to_owned();
    
    println!("salt: {}", salt_base_string);
    println!("key: {}", owned_key);
    
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

    let _crypted = crypt(&owned_key, &salt);
    
    let get_result = |a: &str| -> String {
        let start = a.len() - 10;
        let end = a.len();

        let data = a[start..end].to_owned();

        format!("◆{}", data)
    };

    match _crypted {
        Ok(v) => { get_result(&v) }
        Err(_e) => "".to_owned()
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_create_trip() {
        assert_eq!(create_trip("#istrip"), "◆/WG5qp963c");
        assert_eq!(create_trip("#ニコニコ"), "◆pA8Bpf.Qvk");
    }
}

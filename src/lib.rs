use std::collections::HashMap;
use pwhash::unix::crypt;
use regex::Regex;

use encoding::{Encoding, EncoderTrap, DecoderTrap};
use encoding::all::WINDOWS_31J;

pub fn create_trip(key: &str) -> String {
    let key_base = key[1..].to_owned();
    let bytes = WINDOWS_31J.encode(&key_base, EncoderTrap::Strict).unwrap();

    let mut salt_base: Vec<char> = vec!();
    let mut key_bytes: Vec<char> = vec!();
    
    let mut count = 0;
    for i in &bytes {

        key_bytes.push(i.to_owned() as char);
        
        if count == 1 || count == 2 {
            salt_base.push(i.to_owned() as char);
        }

        if count == 8 {
            break;
        }

        count = count + 1;
    }

    // let key_test_decode = String::from_utf8_lossy(&key_bytes);
    // let trip_key = key_test_decode.as_ref().to_owned();
    let trip_key: String = key_bytes.iter().collect();

    // let salt_base_test_decode = String::from_utf8_lossy(&salt_base);
    // let salt_base_string = salt_base_test_decode.as_ref().to_owned();

    let salt_base_string: String = salt_base.iter().collect();

    println!("salt_base size: {}", salt_base.len());
    println!("salt: {}, size: {}", salt_base_string, salt_base_string.len());
    println!("tripe key: {}", trip_key);
    
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

    println!("final salt: {}", salt);
    println!("final salt size: {}", salt.len());

    let _crypted = crypt(&trip_key, &salt);
    
    let get_result = |a: &str| -> String {
        let start = a.len() - 10;
        let end = a.len();

        let data = a[start..end].to_owned();

        format!("◆{}", data)
    };

    match _crypted {
        Ok(v) => { get_result(&v) }
        Err(_e) => {
            println!("crypt error: {}", _e);
            "".to_owned()
        }
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

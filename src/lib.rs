use pwhash::unix::crypt;

pub fn create_trip(key: &str) -> String {
    let owned_key = key[1..].to_owned();
    let salt = if owned_key.len() > 3 { owned_key[1..3].to_owned() } else { format!("{}H.", key) };
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
    }
}

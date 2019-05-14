use CryptoError;

pub fn bin2hex(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

pub fn hex2bin(s: &str) -> Result<Vec<u8>, CryptoError> {
    if s.len() % 2 != 0 {
        return Err(CryptoError::ParseError("Invalid string".to_string()));
    }
    for (i, ch) in s.chars().enumerate() {
        if !ch.is_digit(16) {
            return Err(CryptoError::ParseError(format!(
                "Invalid character position {}",
                i
            )));
        }
    }

    let input: Vec<_> = s.chars().collect();

    let decoded: Vec<u8> = input
        .chunks(2)
        .map(|chunk| {
            ((chunk[0].to_digit(16).unwrap() << 4) | (chunk[1].to_digit(16).unwrap())) as u8
        })
        .collect();

    Ok(decoded)
}

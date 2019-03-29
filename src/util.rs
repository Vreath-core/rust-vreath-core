pub fn num2vec(num:u64) -> Vec<u8> {
    num.to_string().chars()
        .map(|c| c.to_digit(10).unwrap() as u8)
        .collect()
}

pub fn hex2vec(hex: String) -> Vec<u8> {
    hex.chars()
        .map(|c| c.to_digit(16).unwrap() as u8)
        .collect()
}

pub fn vec2hex(vec: Vec<u8>) -> String {
    vec.into_iter()
       .map(|num| format!("{:x}",num))
       .fold("".to_string(),|sum,st| sum+&st)
}

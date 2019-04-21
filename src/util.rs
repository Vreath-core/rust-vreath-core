pub fn hex2vec(hex: String) -> Vec<u8> {
   let len = hex.len();
   (0..len).fold(Vec::new(),|mut res,i|{
        if i%2==0{
                let string = hex.chars().nth(i).unwrap().to_string()+&hex.chars().nth(i+1).unwrap().to_string();
                res.push(u8::from_str_radix(&string,16).unwrap());
                res
        }
        else{res}
   })
}

pub fn vec2hex(vec: Vec<u8>) -> String {
    vec.into_iter()
       .map(|num|{
                format!("{:02x}",num)
        })
       .fold("".to_string(),|sum,st| sum+&st)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate rand;
    use self::rand::Rng;

    #[test]
    fn hex_vec_test(){
        let mut rng = rand::thread_rng();
        let data:[u8;32] = rng.gen();
        let hex = vec2hex(data.to_vec());
        let vec = hex2vec(hex);
        assert!(data.to_vec().eq(&vec));
    }
}
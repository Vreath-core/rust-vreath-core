extern crate  secp256k1;
use secp256k1::{Secp256k1,key,Signature,RecoverableSignature,RecoveryId,Message};
use secp256k1::ecdh::SharedSecret;
use sha2::{Sha256,Digest};

extern crate rand;
use self::rand::Rng;

pub fn get_sha256(data:&[u8])->[u8;32]{
    let mut hasher:Sha256 = Digest::new();
    hasher.input(&data);
    let mut array:[u8;32] = [0;32];
    let result = hasher.result();
    let result_array = result.as_slice();
    (0..32).for_each(|i|{
        array[i] = result_array[i]
    });
    array
}

pub fn generate_key()->[u8;32]{
    let mut rng = rand::thread_rng();
    let random:[u8;32] = rng.gen();
    let secret = key::SecretKey::from_slice(&random).unwrap();
    let mut return_slice:[u8;32] = [0;32];
    (0..32).for_each(|i|{
        return_slice[i] = secret[i];
    });
    return_slice
}

pub fn private2public(private_key:&[u8;32])->[u8;33]{
    let secp = Secp256k1::new();
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    key::PublicKey::from_secret_key(&secp,&secret).serialize()
}


pub fn get_shared_secret(private_key:&[u8;32],public_key:&[u8;33])->[u8;32]{
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    let public = key::PublicKey::from_slice(public_key).unwrap();
    let shared_secret = SharedSecret::new(&public,&secret);
    let mut return_slice:[u8;32] = [0;32];
    (0..32).for_each(|i|{
        return_slice[i] = shared_secret[i];
    });
    return_slice
}

pub fn recoverable_sign(private_key:&[u8;32],data:&[u8])->(i32,[u8;64]){
    let secp = Secp256k1::new();
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    let message = Message::from_slice(&data).unwrap();
    let sign = secp.sign_recoverable(&message,&secret);
    let (recover_id,sign_array) = sign.serialize_compact();
    (recover_id.to_i32(),sign_array)
}

pub fn recover_public_key(data:&[u8],sign:&[u8;64],recover_id:i32)->[u8;33]{
    let secp = Secp256k1::new();
    let rid = RecoveryId::from_i32(recover_id).unwrap();
    let rec = RecoverableSignature::from_compact(sign, rid).unwrap();
    let key = secp.recover(&Message::from_slice(data).unwrap(),&rec).unwrap();
    key.serialize()
}

pub fn verify_sign(data:&[u8],sign:&[u8;64],public_key:&[u8;33])->bool{
    let secp = Secp256k1::new();
    let message = Message::from_slice(&data).unwrap();
    let sign = Signature::from_compact(&sign[..]).unwrap();
    let public = key::PublicKey::from_slice(&public_key[..]).unwrap();
    let verify = secp.verify(&message,&sign,&public);
    match verify{
        Ok(_verify)=>true,
        Err(_e)=>false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate rand;
    use self::rand::Rng;

    #[test]
    fn hash_test() {
        let mut rng = rand::thread_rng();
        let random:[u8;32] = rng.gen();
        get_sha256(&random);
    }

    #[test]
    fn sign_test() {
        let private = generate_key();
        let public =  private2public(&private.clone());
        let mut rng = rand::thread_rng();
        let data:[u8;32] = rng.gen();
        let sign = recoverable_sign(&private,&data[..]);
        let recovered = recover_public_key(&data[..],&sign.1,sign.0);
        assert!(public.eq(&recovered[..]));
        assert!(verify_sign(&data,&sign.1,&recovered));
    }
}
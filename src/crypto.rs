extern crate  secp256k1;
use secp256k1::{Secp256k1,key,Signature,RecoverableSignature,RecoveryId,Message};
use secp256k1::ecdh::SharedSecret;
use sha2::{Sha256,Digest};
extern crate rand;
use rand::{OsRng, Rng};

use super::util;

extern crate wasm_bindgen;
use wasm_bindgen::prelude::*;

pub fn get_sha256(data:&[u8])->[u8;32]{
    let mut hasher:Sha256 = Digest::new();
    hasher.input(&data);
    let mut array:[u8;32] = [0;32];
    let result = hasher.result();
    let result_array = result.as_slice();
    (0..32).for_each(|i|{
        array[i] = result_array[i].clone();
    });
    array.clone()
}

pub fn generate_key()->[u8;32]{
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let rng_slice:[u8;32] = rng.gen();
    let secret = key::SecretKey::from_slice(&rng_slice).unwrap();
    let mut return_slice:[u8;32] = [0;32];
    for i in (0..32){
        return_slice[i] = secret[i];
    }
    return_slice.clone()
}

pub fn private2public(private_key:&[u8;32])->[u8;33]{
    let secp = Secp256k1::new();
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    key::PublicKey::from_secret_key(&secp,&secret).serialize()
}


pub fn get_shared_secret(private_key:&[u8;32],public_key:&[u8;32])->[u8;32]{
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    let public = key::PublicKey::from_slice(public_key).unwrap();
    let shared_secret = SharedSecret::new(&public,&secret);
    let mut return_slice:[u8;32] = [0;32];
    for i in (0..32){
        return_slice[i] = shared_secret[i];
    }
    return_slice.clone()
}
/*
#[wasm_bindgen]
pub fn encrypt(data:&Vec<u8>,secret:&[u8;32])->(Vec<u8>,Vec<u8>){
    let key = secretbox::xsalsa20poly1305::Key::from_slice(secret).unwrap();
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(&data[..], &nonce, &key);
    (ciphertext,nonce.as_ref().clone().to_vec())
}

#[wasm_bindgen]
pub fn decrypt(ciphertext:&Vec<u8>,nonce:&Vec<u8>,secret:&[u8;32])->Result<Vec<u8>,()>{
    let key = secretbox::xsalsa20poly1305::Key::from_slice(secret).unwrap();
    let nonce = secretbox::xsalsa20poly1305::Nonce::from_slice(&nonce[..]).unwrap();
    let data = secretbox::open(&ciphertext[..],&nonce,&key);
    data
}*/

pub fn recoverable_sign(private_key:&[u8;32],data:&[u8])->(i32,[u8;64]){
    let secp = Secp256k1::new();
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    let message = Message::from_slice(&data).unwrap();
    let sign = secp.sign_recoverable(&message,&secret);
    let (recover_id,sign_array) = sign.serialize_compact();
    (recover_id.to_i32(),sign_array)
}

pub fn recover_public_key(data:&[u8],sign:&[u8],recover_id:i32)->[u8;33]{
    let secp = Secp256k1::new();
    let rid = RecoveryId::from_i32(recover_id).unwrap();
    let rec = RecoverableSignature::from_compact(sign, rid).unwrap();
    let key = secp.recover(&Message::from_slice(data).unwrap(),&rec).unwrap();
    key.serialize()
}

pub fn verify_sign(data:&[u8],sign:&[u8],public_key:&[u8])->bool{
    let secp = Secp256k1::new();
    let message = Message::from_slice(&data).unwrap();
    let sign = Signature::from_compact(&sign).unwrap();
    let public = key::PublicKey::from_slice(&public_key).unwrap();
    let verify = secp.verify(&message,&sign,&public);
    match verify{
        Ok(verify)=>true,
        Err(e)=>false
    }
}

//for wasm
#[wasm_bindgen]
pub fn wasm_get_sha256(data:&[u8])->String{
    let mut hasher:Sha256 = Digest::new();
    hasher.input(&data);
    let mut array:[u8;32] = [0;32];
    let result = hasher.result();
    let result_array = result.as_slice();
    (0..32).for_each(|i|{
        array[i] = result_array[i].clone();
    });
    util::vec2hex(array.to_vec())
}

#[wasm_bindgen]
pub fn wasm_generate_key()->String{
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let rng_slice:[u8;32] = rng.gen();
    let secret = key::SecretKey::from_slice(&rng_slice).unwrap();
    let mut return_slice:[u8;32] = [0;32];
    for i in (0..32){
        return_slice[i] = secret[i];
    }
    util::vec2hex(return_slice.to_vec())
}

#[wasm_bindgen]
pub fn wasm_private2public(private_key:&[u8])->String{
    let secp = Secp256k1::new();
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    let public = key::PublicKey::from_secret_key(&secp,&secret).serialize();
    util::vec2hex(public.to_vec())
}

#[wasm_bindgen]
pub fn wasm_get_shared_secret(private_key:&[u8],public_key:&[u8])->String{
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    let public = key::PublicKey::from_slice(public_key).unwrap();
    let shared_secret = SharedSecret::new(&public,&secret);
    let mut return_slice:[u8;32] = [0;32];
    for i in (0..32){
        return_slice[i] = shared_secret[i];
    }
    util::vec2hex(return_slice.to_vec())
}
/*
#[wasm_bindgen]
pub fn encrypt(data:&Vec<u8>,secret:&[u8;32])->(Vec<u8>,Vec<u8>){
    let key = secretbox::xsalsa20poly1305::Key::from_slice(secret).unwrap();
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(&data[..], &nonce, &key);
    (ciphertext,nonce.as_ref().clone().to_vec())
}

#[wasm_bindgen]
pub fn decrypt(ciphertext:&Vec<u8>,nonce:&Vec<u8>,secret:&[u8;32])->Result<Vec<u8>,()>{
    let key = secretbox::xsalsa20poly1305::Key::from_slice(secret).unwrap();
    let nonce = secretbox::xsalsa20poly1305::Nonce::from_slice(&nonce[..]).unwrap();
    let data = secretbox::open(&ciphertext[..],&nonce,&key);
    data
}*/

//return (hex of recoverid)_(hex of signature)
#[wasm_bindgen]
pub fn wasm_recoverable_sign(private_key:&[u8],data:&[u8])->String{
    let secp = Secp256k1::new();
    let secret = key::SecretKey::from_slice(private_key).unwrap();
    let message = Message::from_slice(&data).unwrap();
    let sign = secp.sign_recoverable(&message,&secret);
    let (recover_id,sign_array) = sign.serialize_compact();
    format!("{:x}",recover_id.to_i32())+"_"+&util::vec2hex(sign_array.to_vec())
}

#[wasm_bindgen]
pub fn wasm_recover_public_key(data:&[u8],sign:&[u8],recover_id:i32)->String{
    let secp = Secp256k1::new();
    let rid = RecoveryId::from_i32(recover_id).unwrap();
    let rec = RecoverableSignature::from_compact(sign, rid).unwrap();
    let key = secp.recover(&Message::from_slice(data).unwrap(),&rec).unwrap();
    util::vec2hex(key.serialize().to_vec())
}

#[wasm_bindgen]
pub fn wasm_verify_sign(data:&[u8],sign:&[u8],public_key:&[u8])->bool{
    let secp = Secp256k1::new();
    let message = Message::from_slice(&data).unwrap();
    let sign = Signature::from_compact(&sign).unwrap();
    let public = key::PublicKey::from_slice(&public_key).unwrap();
    let verify = secp.verify(&message,&sign,&public);
    match verify{
        Ok(verify)=>true,
        Err(e)=>false
    }
}
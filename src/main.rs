/*
/*#[wasm_bindgen]
pub fn zkvm_test(){
    let privkey = Scalar::random(&mut rand::thread_rng());
    let verify_key = zkvm::VerificationKey::from_secret(&privkey);
    let bp_gens = BulletproofGens::new(64, 1);
    let pc_gens = PedersenGens::default();
    let key_pred = zkvm::Predicate::Key(verify_key);
    println!("{:?}",key_pred.to_point());
    let a_commitment = zkvm::Commitment::blinded_with_factor(Scalar::from_bits([10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),Scalar::hash_from_bytes::<Sha512>(&[60 as u8]));
    let b_commitment = zkvm::Commitment::blinded_with_factor(Scalar::from_bits([10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),Scalar::hash_from_bytes::<Sha512>(&[43 as u8]));
    println!("{:?}",a_commitment.to_point());
    println!("{:?}",b_commitment.to_point());

    let a_pred = zkvm::Predicate::Opaque(a_commitment.to_point());
    let b_pred = zkvm::Predicate::Opaque(b_commitment.to_point());
    let one_pred = zkvm::Predicate::disjunction(vec![a_pred.clone(),b_pred.clone()]).unwrap();
    println!("{:?}",a_pred.clone());
    println!("{:?}",b_pred.clone());
    println!("{:?}",one_pred.clone());

    let mut program = zkvm::Program::new();
    program.push(key_pred).push(0).nonce().push(one_pred.clone()).select(2,0).drop().sign_tx();
    let tx_header = zkvm::TxHeader{version:0,mintime:0,maxtime:9999999999};
    let sign_fn = |transcript:&mut Transcript, verification_keys:&Vec<zkvm::VerificationKey>|{
        let mut trans = transcript;
        zkvm::Signature::sign_single(&mut trans, privkey)
    };
    let (tx,_,log) = zkvm::Prover::build_tx(program,tx_header,&bp_gens,sign_fn).unwrap();
    println!("prove!");
    println!("{:?}",tx.program);
    let verified = zkvm::Verifier::verify_tx(tx,&bp_gens).unwrap();
    println!("verify!");
    /*let base_state = types::State {
        nonce:"0".to_string(),
        token:"0".to_string(),
        owner:"0".to_string(),
        amount:"0".to_string(),
        data:vec!["0".to_string(),"0".to_string()]
    };

    let output_state = types::State {
        nonce:"1".to_string(),
        token:"0".to_string(),
        owner:"0".to_string(),
        amount:"0".to_string(),
        data:vec!["0".to_string(),"0".to_string()]
    };

    let proof_info = types::ProofInfo {
        addresses:vec!["0".to_string()],
        base_state:vec![base_state],
        input_data:vec![hex::encode("remit"),"0".to_string()],
        output_state:vec![output_state]
    };

    let proof = prove::native_remit(proof_info,&privkey.to_bytes()).unwrap();*/
    //println!("{:?}",proof);
}*/

fn crypto_test(){
    /*let private = crypto::generate_key();
    println!("{}",util::vec2hex(private.to_vec()));
    let public = crypto::private2public(&private.clone());
    println!("{}",util::vec2hex(public.to_vec()));
    let rng_slice2:[u8;32] = rng.gen();
    let private2 = crypto::generate_key(&rng_slice2);
    let shared = crypto::get_shared_secret(&private2,&public);*/
    //let test_data = "0982723627128129874732da".to_string();
    //let (crypted,nonce) = crypto::encrypt(&test_data,&private);
    //let decrypted = crypto::decrypt(&crypted,&nonce,&private);
    //let hash = crypto::get_sha256(&util::hex2vec("0982723627128129874732da".to_string()));
    //println!("{:?}",hash);
    //println!("{}",util::vec2hex(hash.to_vec()));
    //let sign = crypto::recoverable_sign(&private.clone(),&hash);
    //println!("{}",sign.0);
    //println!("{:?}",sign.1.to_vec());
    //let recover = crypto::recover_public_key(&hash,&sign.1,sign.0);
    //println!("{}",util::vec2hex(recover.to_vec()));
    //let verify = crypto::verify_sign(&hash,&sign.1,&public);
    //println!("{}",verify);
}

fn main(){
    //crypto_test();
}*/
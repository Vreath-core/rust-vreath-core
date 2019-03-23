use zkvm;
use spacesuit::{BitRange,SignedInteger};
use rand;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;

extern crate hex;
extern crate sha2;
use sha2::Sha512;


use super::super::types;
use super::util;
use super::build;


pub fn native_remit(info:types::ProofInfo,private_key:&[u8; 64])->Result<types::Proof,&str> {
    let verify_key = util::generate_verification_key(&private_key);

    let addresses = &info.addresses;
    let base_states_len = info.base_state.len();
    let input_data_len = info.input_data.len();
    let output_states_len = info.output_state.len();
    let base_state_preds:Vec<zkvm::Predicate> = (0..base_states_len-1).into_iter().map(|i| util::state_commit(&info.base_state[i],"base_state".to_string()+&i.to_string())).collect();
    let input_preds:Vec<zkvm::Predicate> = (0..input_data_len-1).into_iter().map(|i| util::commitment2pred(&util::hex_commit(&info.input_data[i]),"input_data".to_string()+&i.to_string())).collect();
    let output_state_preds:Vec<zkvm::Predicate> = (0..output_states_len-1).into_iter().map(|i| util::state_commit(&info.output_state[i],"output_state".to_string()+&i.to_string())).collect();
    if(addresses.len()!=base_states_len || base_states_len!=output_states_len||base_states_len!=input_data_len-1){ return Err("invalid data"); }

    let program = build::native_remit(verify_key,base_state_preds.clone(),input_preds.clone(),output_state_preds.clone(),addresses.clone());

    let tx = program2tx(program,private_key);
    let base_one_pred = util::batch_predicate(&base_state_preds);
    let input_one_pred = util::batch_predicate(&input_preds);
    let output_one_pred = util::batch_predicate(&output_state_preds);

    let proof = util::tx2proof(tx,base_one_pred,input_one_pred,output_one_pred);
    Ok(proof)
}

pub fn key_block_proof(info:types::ProofInfo,private_key:&[u8; 64],height_sub:u64,issue:u64,unit_rate:u64,first_fee_rate:u64)->Result<types::Proof,&str> {
    let verify_key = util::generate_verification_key(&private_key);
    let key_pred = zkvm::Predicate::Key(verify_key);
    let mut program = zkvm::Program::new();
    program.push(key_pred).push(0).nonce();

    let addresses = &info.addresses;
    let base_states_len = info.base_state.len();
    let output_states_len = info.output_state.len();
    let base_state_preds:Vec<zkvm::Predicate> = (0..base_states_len-1).into_iter().map(|i| util::state_commit(&info.base_state[i],"base_state".to_string()+&i.to_string())).collect();
    let output_state_preds:Vec<zkvm::Predicate> = (0..output_states_len-1).into_iter().map(|i| util::state_commit(&info.output_state[i],"output_state".to_string()+&i.to_string())).collect();
    if(addresses.len()!=base_states_len || base_states_len!=output_states_len){ return Err("invalid data"); }

    if(unit_rate<0 || unit_rate>10 || first_fee_rate<0 || first_fee_rate>10){
        return Err("invalid rate");
    }

    let program = build::key_block_proof(verify_key,base_state_preds.clone(),output_state_preds.clone(),addresses.clone(),height_sub,issue,unit_rate,first_fee_rate);

    let tx = program2tx(program,private_key);
    let base_one_pred = util::batch_predicate(&base_state_preds);
    let input_one_pred = util::batch_predicate(&vec![]);
    let output_one_pred = util::batch_predicate(&output_state_preds);

    let proof = util::tx2proof(tx,base_one_pred,input_one_pred,output_one_pred);
    Ok(proof)
}


pub fn micro_block_proof(info:types::ProofInfo,private_key:&[u8; 64],fees:Vec<String>)->Result<types::Proof,&str> {
    let verify_key = util::generate_verification_key(&private_key);

    let addresses = &info.addresses;
    let base_states_len = info.base_state.len();
    let output_states_len = info.output_state.len();
    let base_state_preds:Vec<zkvm::Predicate> = (0..base_states_len-1).into_iter().map(|i| util::state_commit(&info.base_state[i],"base_state".to_string()+&i.to_string())).collect();
    let output_state_preds:Vec<zkvm::Predicate> = (0..output_states_len-1).into_iter().map(|i| util::state_commit(&info.output_state[i],"output_state".to_string()+&i.to_string())).collect();
    if(addresses.len()!=base_states_len || base_states_len!=output_states_len || base_states_len!=fees.len()){ return Err("invalid data"); }

    let program = build::micro_block_proof(verify_key,base_state_preds.clone(),output_state_preds.clone(),addresses.clone(),fees);

    let tx = program2tx(program,private_key);
    let base_one_pred = util::batch_predicate(&base_state_preds);
    let input_one_pred = util::batch_predicate(&vec![]);
    let output_one_pred = util::batch_predicate(&output_state_preds);

    let proof = util::tx2proof(tx,base_one_pred,input_one_pred,output_one_pred);
    Ok(proof)
}


fn program2tx(program:zkvm::Program,private_key:&[u8; 64])->zkvm::Tx {
    let tx_header = zkvm::TxHeader{version:0,mintime:0,maxtime:9999999999};
    let private_scalar = Scalar::from_bytes_mod_order_wide(private_key);
    let sign_fn = |transcript:&mut Transcript, verification_keys:&Vec<zkvm::VerificationKey>|{
        let mut trans = transcript;
        zkvm::Signature::sign_single(&mut trans, private_scalar)
    };
    let bp_gens = BulletproofGens::new(64, 1);
    let (tx,_,_) = zkvm::Prover::build_tx(program,tx_header,&bp_gens,sign_fn).unwrap();
    tx
}
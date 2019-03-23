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


pub fn native_remit(proof:types::Proof,addresses:Vec<String>,verify_key:zkvm::VerificationKey,base_addresses:Vec<String>,base_hashes:Vec<String>)->Result<bool,&'static str>{
    let base_state_preds:Vec<zkvm::Predicate> = proof.base_state.clone().to_disjunction().unwrap();
    let input_preds:Vec<zkvm::Predicate> = proof.input_data.clone().to_disjunction().unwrap();
    let output_state_preds:Vec<zkvm::Predicate> = proof.output_state.clone().to_disjunction().unwrap();

    let base_states_len = base_state_preds.clone().len();
    let input_data_len = input_preds.clone().len();
    let output_states_len = output_state_preds.clone().len();
    let base_hashes_len = output_state_preds.clone().len();

    if(base_states_len!=output_states_len||base_states_len!=base_hashes_len||base_states_len!=input_data_len-1){
        return Err("invalid length");
    }

    for i in (0..base_hashes_len){
        if(util::hex2vec(base_hashes[i].clone())[0..31]!=base_state_preds[i].clone().to_point().to_bytes()){
            return Err("invalid base states");
        }
    }

    let program = build::native_remit(verify_key,base_state_preds.clone(),input_preds.clone(),output_state_preds.clone(),base_addresses.clone());

    let tx = program2tx(program,proof);

    let bp_gens = BulletproofGens::new(64, 1);
    let verify = zkvm::Verifier::verify_tx(tx,&bp_gens);

    match verify {
        Err(verify) => Err("invalid proof"),
        _ => Ok(true)
    }
}

pub fn key_block_proof(proof:types::Proof,addresses:Vec<String>,verify_key:zkvm::VerificationKey,base_addresses:Vec<String>,base_hashes:Vec<String>,height_sub:u64,issue:u64,unit_rate:u64,first_fee_rate:u64)->Result<bool,&'static str>{
    let base_state_preds:Vec<zkvm::Predicate> = proof.base_state.clone().to_disjunction().unwrap();
    let output_state_preds:Vec<zkvm::Predicate> = proof.output_state.clone().to_disjunction().unwrap();

    let base_states_len = base_state_preds.clone().len();
    let output_states_len = output_state_preds.clone().len();
    let base_hashes_len = output_state_preds.clone().len();

    if(base_states_len!=output_states_len||base_states_len!=base_hashes_len){
        return Err("invalid length");
    }

    for i in (0..base_hashes_len){
        if(util::hex2vec(base_hashes[i].clone())[0..31]!=base_state_preds[i].clone().to_point().to_bytes()){
            return Err("invalid base states");
        }
    }

    if(unit_rate<0 || unit_rate>10 || first_fee_rate<0 || first_fee_rate>10){
        return Err("invalid rate");
    }

    let program = build::key_block_proof(verify_key,base_state_preds.clone(),output_state_preds.clone(),base_addresses.clone(),height_sub,issue,unit_rate,first_fee_rate);

    let tx = program2tx(program,proof);

    let bp_gens = BulletproofGens::new(64, 1);
    let verify = zkvm::Verifier::verify_tx(tx,&bp_gens);

    match verify {
        Err(verify) => Err("invalid proof"),
        _ => Ok(true)
    }
}

pub fn micro_block_proof(proof:types::Proof,addresses:Vec<String>,verify_key:zkvm::VerificationKey,base_addresses:Vec<String>,base_hashes:Vec<String>,fees:Vec<String>)->Result<bool,&'static str>{
    let base_state_preds:Vec<zkvm::Predicate> = proof.base_state.clone().to_disjunction().unwrap();
    let output_state_preds:Vec<zkvm::Predicate> = proof.output_state.clone().to_disjunction().unwrap();

    let base_states_len = base_state_preds.clone().len();
    let output_states_len = output_state_preds.clone().len();
    let base_hashes_len = output_state_preds.clone().len();

    if(base_states_len!=output_states_len || base_states_len!=base_hashes_len || base_states_len!=fees.len()){
        return Err("invalid length");
    }

    for i in (0..base_hashes_len){
        if(util::hex2vec(base_hashes[i].clone())[0..31]!=base_state_preds[i].clone().to_point().to_bytes()){
            return Err("invalid base states");
        }
    }

    let program = build::micro_block_proof(verify_key,base_state_preds.clone(),output_state_preds.clone(),base_addresses.clone(),fees);

    let tx = program2tx(program,proof);

    let bp_gens = BulletproofGens::new(64, 1);
    let verify = zkvm::Verifier::verify_tx(tx,&bp_gens);

    match verify {
        Err(verify) => Err("invalid proof"),
        _ => Ok(true)
    }
}


fn program2tx(program:zkvm::Program,proof:types::Proof)->zkvm::Tx {
    let tx_header = zkvm::TxHeader{version:0,mintime:0,maxtime:9999999999};
    let mut program_bytes:Vec<u8> = Vec::new();
    program.encode(&mut program_bytes);
    let tx = zkvm::Tx {
        header:tx_header,
        program:program_bytes.clone(),
        signature:proof.signature,
        proof:proof.proof
    };
    tx
}
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


pub fn native_remit(verify_key:zkvm::VerificationKey,base_state_preds:Vec<zkvm::Predicate>,input_preds:Vec<zkvm::Predicate>,output_state_preds:Vec<zkvm::Predicate>,addresses:Vec<String>)->zkvm::Program{
    let mut program = zkvm::Program::new();

    let key_pred = zkvm::Predicate::Key(verify_key);
    program.push(key_pred).push(0).nonce();

    let remit_commitment = util::hex_commit(&hex::encode("remit"));
    util::call_commitment(&mut program,&input_preds[0],"input_data0".to_string());
    program.push(remit_commitment).var().expr().eq().verify();
    let amount_preds:Vec<zkvm::Predicate> = input_preds[1..].to_vec();

    let base_states_len = base_state_preds.clone().len();

    (0..base_states_len).into_iter().for_each(|i|{
        let base_state_pred = &base_state_preds[i];
        let base_nonce_pred = util::get_array_pred(&base_state_pred,0).unwrap();
        let base_amount_pred = util::get_array_pred(&base_state_pred,3).unwrap();
        let base_data_pred = util::get_array_pred(&base_state_pred,4).unwrap();
        let base_fee_pred = util::get_array_pred(&base_data_pred,0).unwrap();
        let base_gas_pred = util::get_array_pred(&base_data_pred,1).unwrap();
        let amount_pred = &amount_preds[i];
        let base_state_label = "base_state".to_string()+&i.to_string();
        let amount_label = "input_data".to_string()+&(i+1).to_string();
        util::call_commitment(&mut program,&base_amount_pred,base_state_label.clone()+"_amount");
        util::call_commitment(&mut program,&amount_pred,amount_label.clone());
        program.range(BitRange::max()).add();

        if(i==0){
            for j in (0..amount_preds.len()){
                util::call_commitment(&mut program,&amount_preds[i],"input_data".to_string()+&(j+1).to_string());
                program.neg().add();
            }
        }

        let output_state_pred = &output_state_preds[i];
        let output_nonce_pred = util::get_array_pred(&output_state_pred,0).unwrap();
        let output_owner_pred = util::get_array_pred(&output_state_pred,2).unwrap();
        let output_amount_pred = util::get_array_pred(&output_state_pred,3).unwrap();
        let output_data_pred = util::get_array_pred(&output_state_pred,4).unwrap();
        let output_fee_pred = util::get_array_pred(&output_data_pred,0).unwrap();
        let output_gas_pred = util::get_array_pred(&output_data_pred,1).unwrap();
        let output_state_label = "output_state".to_string()+&i.to_string();
        util::call_commitment(&mut program,&output_amount_pred, output_state_label.clone()+"_amount");
        program.eq().verify();

        let address_commitment = util::hex_commit(&addresses[i]);
        util::call_commitment(&mut program, &base_nonce_pred, base_state_label.clone()+"_nonce");
        program.push(util::hex_commit(&hex::encode("remit"))).var().expr().add();
        util::call_commitment(&mut program, &output_nonce_pred, output_state_label.clone()+"_nonce");
        program.range(BitRange::max()).eq().verify();
        util::call_commitment(&mut program, &output_owner_pred, output_state_label.clone()+"_owner");
        program.push(address_commitment).var().expr().eq().verify();
        util::call_commitment(&mut program, &output_amount_pred, output_state_label.clone()+"_amount");
        util::call_commitment(&mut program, &output_fee_pred, output_state_label.clone()+"_data0");
        program.neg().add();
        util::call_commitment(&mut program, &output_gas_pred, output_state_label.clone()+"_data1");
        program.neg().add().range(BitRange::max()).drop();

        util::call_commitment(&mut program, &base_fee_pred, base_state_label.clone()+"_data0");
        util::call_commitment(&mut program, &output_fee_pred, output_state_label.clone()+"_data0");
        program.eq().verify();
        util::call_commitment(&mut program, &base_gas_pred, base_state_label.clone()+"_data1");
        util::call_commitment(&mut program, &output_gas_pred, output_state_label.clone()+"_data1");
        program.eq().verify();
    });
    program.sign_tx();

    program.clone()
}

pub fn key_block_proof(verify_key:zkvm::VerificationKey,base_state_preds:Vec<zkvm::Predicate>,output_state_preds:Vec<zkvm::Predicate>,addresses:Vec<String>,height_sub:u64,issue:u64,unit_rate:u64,first_fee_rate:u64)->zkvm::Program{
    let mut program = zkvm::Program::new();
    let key_pred = zkvm::Predicate::Key(verify_key);
    program.push(key_pred).push(0).nonce();

    let ten_invert = zkvm::Commitment::unblinded(Scalar::from_bits([10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]).invert());
    let zero_commitment = util::hex_commit(&"0".to_string());
    let base_states_len = base_state_preds.clone().len();

    let unit_base_pred = &base_state_preds[0];
    let unit_base_nonce = util::get_array_pred(&unit_base_pred,0).unwrap();
    let unit_base_amount = util::get_array_pred(&unit_base_pred,3).unwrap();
    let unit_base_data = util::get_array_pred(&unit_base_pred,4).unwrap();
    let unit_base_flag = util::get_array_pred(&unit_base_data,0).unwrap();
    let unit_base_height = util::get_array_pred(&unit_base_data,1).unwrap();
    let unit_base_label = "base_state0".to_string();
    util::call_commitment(&mut program,&unit_base_flag,unit_base_label.clone()+"_data0");
    program.push(zero_commitment.clone()).var().expr().eq().verify();
    util::call_commitment(&mut program,&unit_base_height,unit_base_label.clone()+"_data1");
    program.push(height_sub).r#const().add();

    let unit_output_pred = &output_state_preds[0];
    let unit_output_nonce = util::get_array_pred(&unit_output_pred,0).unwrap();
    let unit_output_amount = util::get_array_pred(&unit_output_pred,3).unwrap();
    let unit_output_data = util::get_array_pred(&unit_output_pred,4).unwrap();
    let unit_output_flag = util::get_array_pred(&unit_output_data,0).unwrap();
    let unit_output_height = util::get_array_pred(&unit_output_data,1).unwrap();
    let unit_output_label = "output_state0".to_string();
    util::call_commitment(&mut program,&unit_output_height,unit_output_label.clone()+"_data1");
    program.eq().verify();
    util::call_commitment(&mut program, &unit_base_nonce, unit_base_label.clone()+"_nonce");
    program.push(util::hex_commit(&hex::encode("1"))).var().expr().add();
    util::call_commitment(&mut program, &unit_output_nonce, unit_output_label.clone()+"_nonce");
    program.range(BitRange::max()).eq().verify();
    util::call_commitment(&mut program,&unit_output_flag,unit_output_label.clone()+"_data0");
    program.push(zero_commitment.clone()).var().expr().eq().verify();
    util::call_commitment(&mut program,&unit_base_amount,unit_base_label.clone()+"_amount");
    for _  in (1..height_sub){
        program.push(unit_rate).r#const().mul().push(ten_invert.clone()).var().expr().mul();
    }
    util::call_commitment(&mut program,&unit_output_amount,unit_output_label.clone()+"_amount");
    program.range(BitRange::max()).eq().verify();

    let fee_preds:Vec<zkvm::Predicate> = base_state_preds.clone()[1..].into_iter().map(|pred|{
        let data_pred = util::get_array_pred(&pred,4).unwrap();
        util::get_array_pred(&data_pred,0).unwrap()
    }).collect();

    (1..base_states_len).into_iter().for_each(|i|{
        let base_state_pred = &base_state_preds[i];
        let base_nonce_pred = util::get_array_pred(&base_state_pred,0).unwrap();
        let base_amount_pred = util::get_array_pred(&base_state_pred,3).unwrap();
        let base_data_pred = util::get_array_pred(&base_state_pred,4).unwrap();
        let base_fee_pred = fee_preds[i-1].clone();
        let base_gas_pred = util::get_array_pred(&base_data_pred,1).unwrap();
        let base_state_label = "base_state".to_string()+&i.to_string();
        util::call_commitment(&mut program,&base_amount_pred,base_state_label.clone()+"_amount");
        util::call_commitment(&mut program,&base_fee_pred,base_state_label.clone()+"_data0");

        if(i==1){
            for j in (1..base_states_len){
                util::call_commitment(&mut program,&fee_preds[j-1],"base_state".to_string()+&(j-1).to_string()+"_data0");
                program.push(first_fee_rate).r#const().mul().push(ten_invert.clone()).var().expr().mul().add();
            }
            program.push(issue).push(first_fee_rate).r#const().mul().push(ten_invert.clone()).var().expr().mul().add();
        }
        else if(i==2){
            for j in (1..base_states_len){
                util::call_commitment(&mut program,&fee_preds[j-1],"base_state".to_string()+&(j-1).to_string()+"_data0");
                program.push(10-first_fee_rate).r#const().mul().push(ten_invert.clone()).var().expr().mul().add();
            }
            program.push(issue).push(10-first_fee_rate).r#const().mul().push(ten_invert.clone()).var().expr().mul();
        }

        let output_state_pred = &output_state_preds[i];
        let output_nonce_pred = util::get_array_pred(&output_state_pred,0).unwrap();
        let output_owner_pred = util::get_array_pred(&output_state_pred,2).unwrap();
        let output_amount_pred = util::get_array_pred(&output_state_pred,3).unwrap();
        let output_data_pred = util::get_array_pred(&output_state_pred,4).unwrap();
        let output_fee_pred = util::get_array_pred(&output_data_pred,0).unwrap();
        let output_gas_pred = util::get_array_pred(&output_data_pred,1).unwrap();
        let output_state_label = "output_state".to_string()+&i.to_string();
        util::call_commitment(&mut program,&output_amount_pred, output_state_label.clone()+"_amount");
        program.eq().verify();

        let address_commitment = util::hex_commit(&addresses[i]);
        util::call_commitment(&mut program, &base_nonce_pred, base_state_label.clone()+"_nonce");
        program.push(util::hex_commit(&hex::encode("1"))).var().expr().add();
        util::call_commitment(&mut program, &output_nonce_pred, output_state_label.clone()+"_nonce");
        program.range(BitRange::max()).eq().verify();
        util::call_commitment(&mut program, &output_owner_pred, output_state_label.clone()+"_owner");
        program.push(address_commitment).var().expr().eq().verify();
        util::call_commitment(&mut program, &output_fee_pred, output_state_label.clone()+"_data0");
        program.push(zero_commitment.clone()).var().expr().eq().verify();
        util::call_commitment(&mut program, &base_gas_pred, base_state_label.clone()+"_data1");
        util::call_commitment(&mut program, &output_gas_pred, output_state_label.clone()+"_data1");
        program.range(BitRange::max()).eq().verify();

        util::call_commitment(&mut program, &output_amount_pred, output_state_label.clone()+"_amount");
        util::call_commitment(&mut program, &output_fee_pred, output_state_label.clone()+"_data0");
        program.neg().add();
        util::call_commitment(&mut program, &output_gas_pred, output_state_label.clone()+"_data1");
        program.neg().add().range(BitRange::max()).drop();
    });
    program.sign_tx();

    program.clone()
}

pub fn micro_block_proof(verify_key:zkvm::VerificationKey,base_state_preds:Vec<zkvm::Predicate>,output_state_preds:Vec<zkvm::Predicate>,addresses:Vec<String>,fees:Vec<String>)->zkvm::Program{
    let mut program = zkvm::Program::new();
    let key_pred = zkvm::Predicate::Key(verify_key);
    program.push(key_pred).push(0).nonce();

    let zero_commitment = util::hex_commit(&"0".to_string());
    let base_states_len = base_state_preds.clone().len();

    (0..base_states_len-1).into_iter().for_each(|i|{
        if(i%2==0){
            let req_base_state = &base_state_preds[i];
            let req_base_nonce = util::get_array_pred(&req_base_state,0).unwrap();
            let req_base_amount = util::get_array_pred(&req_base_state,3).unwrap();
            let req_base_data = util::get_array_pred(&req_base_state,4).unwrap();
            let req_base_fee = util::get_array_pred(&req_base_data,0).unwrap();
            let req_base_gas = util::get_array_pred(&req_base_data,1).unwrap();
            let req_base_label = "base_state".to_string()+&i.to_string();
            util::call_commitment(&mut program,&req_base_amount,req_base_label.clone()+"_amount");
            util::call_commitment(&mut program,&req_base_gas,req_base_label.clone()+"_data1");
            program.neg().add();

            let req_output_state = &output_state_preds[i];
            let req_output_nonce = util::get_array_pred(&req_output_state,0).unwrap();
            let req_output_owner = util::get_array_pred(&req_output_state,2).unwrap();
            let req_output_amount = util::get_array_pred(&req_output_state,3).unwrap();
            let req_output_data = util::get_array_pred(&req_output_state,4).unwrap();
            let req_output_fee = util::get_array_pred(&req_output_data,0).unwrap();
            let req_output_gas = util::get_array_pred(&req_output_data,1).unwrap();
            let req_output_label = "output_state".to_string()+&i.to_string();
            let address_commitment = util::hex_commit(&addresses[i]);

            util::call_commitment(&mut program, &req_base_nonce, req_base_label.clone()+"_nonce");
            program.push(util::hex_commit(&hex::encode("1"))).var().expr().add();
            util::call_commitment(&mut program, &req_output_nonce, req_output_label.clone()+"_nonce");
            program.range(BitRange::max()).eq().verify();
            util::call_commitment(&mut program, &req_output_owner, req_output_label.clone()+"_owner");
            program.push(address_commitment).var().expr().eq().verify();
            util::call_commitment(&mut program, &req_output_amount, req_output_label.clone()+"_amount");
            program.range(BitRange::max()).eq().verify();
            util::call_commitment(&mut program,&req_base_fee,req_base_label.clone()+"_data0");
            program.push(util::hex_commit(&fees[i])).var().expr().add();
            util::call_commitment(&mut program, &req_output_fee, req_output_label.clone()+"_data0");
            program.eq().verify();
            util::call_commitment(&mut program, &req_output_gas, req_output_label.clone()+"_data1");
            program.push(zero_commitment.clone()).var().expr().eq().verify();

            util::call_commitment(&mut program, &req_output_amount, req_output_label.clone()+"_amount");
            util::call_commitment(&mut program, &req_output_fee, req_output_label.clone()+"_data0");
            program.neg().add().range(BitRange::max()).drop();



            let ref_base_state = &base_state_preds[i+1];
            let ref_base_nonce = util::get_array_pred(&ref_base_state,0).unwrap();
            let ref_base_amount = util::get_array_pred(&ref_base_state,3).unwrap();
            let ref_base_data = util::get_array_pred(&ref_base_state,4).unwrap();
            let ref_base_fee = util::get_array_pred(&ref_base_data,0).unwrap();
            let ref_base_gas = util::get_array_pred(&ref_base_data,1).unwrap();
            let ref_base_label = "base_state".to_string()+&(i+1).to_string();
            util::call_commitment(&mut program,&ref_base_amount,ref_base_label.clone()+"_amount");
            util::call_commitment(&mut program,&req_base_gas,req_base_label.clone()+"_data1");
            program.add();

            let ref_output_state = &output_state_preds[i+1];
            let ref_output_nonce = util::get_array_pred(&ref_output_state,0).unwrap();
            let ref_output_owner = util::get_array_pred(&ref_output_state,2).unwrap();
            let ref_output_amount = util::get_array_pred(&ref_output_state,3).unwrap();
            let ref_output_data = util::get_array_pred(&ref_output_state,4).unwrap();
            let ref_output_fee = util::get_array_pred(&ref_output_data,0).unwrap();
            let ref_output_gas = util::get_array_pred(&ref_output_data,1).unwrap();
            let ref_output_label = "output_state".to_string()+&(i+1).to_string();
            let address_commitment = util::hex_commit(&addresses[i+1]);

            util::call_commitment(&mut program, &ref_base_nonce, ref_base_label.clone()+"_nonce");
            program.push(util::hex_commit(&hex::encode("1"))).var().expr().add();
            util::call_commitment(&mut program, &ref_output_nonce, ref_output_label.clone()+"_nonce");
            program.range(BitRange::max()).eq().verify();
            util::call_commitment(&mut program, &ref_output_owner, ref_output_label.clone()+"_owner");
            program.push(address_commitment).var().expr().eq().verify();
            util::call_commitment(&mut program, &ref_output_amount, ref_output_label.clone()+"_amount");
            program.range(BitRange::max()).eq().verify();
            util::call_commitment(&mut program,&ref_base_fee,ref_base_label.clone()+"_data0");
            program.push(util::hex_commit(&fees[i+1])).var().expr().add();
            util::call_commitment(&mut program, &ref_output_fee, ref_output_label.clone()+"_data0");
            program.eq().verify();
            util::call_commitment(&mut program, &ref_output_gas, ref_output_label.clone()+"_data1");
            program.push(zero_commitment.clone()).var().expr().eq().verify();

            util::call_commitment(&mut program, &ref_output_amount, ref_output_label.clone()+"_amount");
            util::call_commitment(&mut program, &ref_output_fee, ref_output_label.clone()+"_data0");
            program.neg().add().range(BitRange::max()).drop();
        }
    });
    program.sign_tx();

    program.clone()
}
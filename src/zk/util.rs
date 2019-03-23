use zkvm;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use spacesuit::BitRange;
use merlin::Transcript;
extern crate hex;
extern crate sha2;
use sha2::{Sha256,Sha512};

use super::super::types;

/*pub fn pred2commitment(pred:&zkvm::Predicate)->zkvm::Commitment{
    zkvm::Commitment::Closed(pred.clone().to_point())
}*/

pub fn commitment2pred(commitment:&zkvm::Commitment,label:String)->zkvm::Predicate{
    let program = zkvm::Program::build(|prog:&mut zkvm::Program|{
        prog.push(commitment.clone()).var().expr()
    });
    let blind = Scalar::hash_from_bytes::<Sha512>(&hex2vec(label)[0..]).to_bytes().to_vec();
    zkvm::Predicate::Program(program,blind)
}

pub fn pred2program(pred:&zkvm::Predicate)->zkvm::Program{
    pred.clone().to_program().unwrap().0
}

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

pub fn digest(x:u64)->zkvm::Commitment{
    let hash = Scalar::hash_from_bytes::<Sha512>(&num2vec(x)[0..]);
    let commitment = zkvm::Commitment::blinded_with_factor(x,hash);
    commitment
}

pub fn batch_predicate(preds:&Vec<zkvm::Predicate>)->zkvm::Predicate{
    /*let len = preds.len();
    let mut pred_sum:zkvm::Predicate = hex_commit(&"0".to_string());
    for i in (0..len-1){
        pred_sum = pred_sum.or(preds[len-1-i].clone()).unwrap();
    }
    pred_sum*/
    zkvm::Predicate::disjunction(preds.clone()).unwrap()
}

pub fn hex_commit(hex:&String)->zkvm::Commitment{
    let num = u64::from_str_radix(&hex,16).unwrap();
    digest(num)
    /*let bytes = string.clone().into_bytes();
    let bytes_len = bytes.clone().len();
    let preds:Vec<zkvm::Predicate> = bytes.into_iter().map(|x:u8|{
            digest(u64::from(x))
    }).collect();
    batch_predicate(&preds)*/
}

pub fn state_commit(state:&types::State,label:String)->zkvm::Predicate{
    let nonce_pred = commitment2pred(&hex_commit(&state.nonce),label.clone()+"_nonce");
    let token_pred = commitment2pred(&hex_commit(&state.token),label.clone()+"_token");
    let owner_pred = commitment2pred(&hex_commit(&state.owner),label.clone()+"_owner");
    let amount_pred = commitment2pred(&hex_commit(&state.amount),label.clone()+"_amount");
    let data_str_preds = (0..state.data.len()).into_iter().map(|i| commitment2pred(&hex_commit(&state.data[i]),label.clone()+"_data"+&i.to_string())).collect();
    let data_pred = batch_predicate(&data_str_preds);
    batch_predicate(&vec![nonce_pred,token_pred,owner_pred,amount_pred,data_pred])
}

/*pub fn state_check(program:&mut zkvm::Program,nonce_pred:&zkvm::Predicate,owner_pred:&zkvm::Predicate,amount_pred:&zkvm::Predicate, label:String, address:&String){
    call_commitment(&mut program.clone(), &nonce_pred, label.clone()+"_nonce");
    program.range(BitRange::max()).verify();
    call_commitment(&mut program.clone(), &owner_pred, label.clone()+"_owner");
    let address_commitment = hex_commit(address);
    program.push(address_commitment).var().expr().eq().verify();
    call_commitment(&mut program.clone(), &amount_pred, label.clone()+"_amount");
    program.range(BitRange::max()).verify();
}*/


pub fn get_array_pred(pred:&zkvm::Predicate,index:usize)->Result<zkvm::Predicate,&str>{
    /*let mut dis:zkvm::Predicate = start_pred.clone();
    let mut return_pred:Option<zkvm::Commitment> = None;
    for i in (0..index) {
        dis = dis.clone().to_disjunction().unwrap().1;
        if(i==index){
            return_pred = Some(pred2commitment(&dis.clone().to_disjunction().unwrap().0));
            break;
        }
    }
    return_pred*/
    let preds = pred.clone().to_disjunction().unwrap();
    if(index>=preds.len()){
        return Err("invalid index");
    }
    let selected = preds[index].clone();
    Ok(selected)
}

pub fn generate_verification_key(private_key:&[u8; 64])->zkvm::VerificationKey {
    let private_scalar = Scalar::from_bytes_mod_order_wide(private_key);
    zkvm::VerificationKey::from_secret(&private_scalar)
}

pub fn call_commitment(program:&mut zkvm::Program,pred:&zkvm::Predicate,label:String) {
    program.push(pred.clone()).contract(0).push(Scalar::hash_from_bytes::<Sha512>(&hex2vec(label)[0..])).push(pred.clone().to_program().unwrap().0).call();
}

pub fn tx2proof(tx:zkvm::Tx,base_pred:zkvm::Predicate,input_pred:zkvm::Predicate,output_pred:zkvm::Predicate)->types::Proof {
    types::Proof {
        signature:tx.signature,
        proof:tx.proof,
        base_state:base_pred,
        input_data:input_pred,
        output_state:output_pred
    }
}
use bulletproofs::r1cs::R1CSProof;

#[derive(Debug)]
pub struct State {
    pub nonce:String,
    pub token:String,
    pub owner:String,
    pub amount:String,
    pub data:Vec<String>
}

#[derive(Debug)]
pub struct ProofInfo {
    pub addresses:Vec<String>,
    pub base_state:Vec<State>,
    pub input_data:Vec<String>,
    pub output_state:Vec<State>
}

#[derive(Debug)]
pub struct Proof {
    pub signature: zkvm::Signature,
    pub proof: R1CSProof,
    pub base_state:zkvm::Predicate,
    pub input_data:zkvm::Predicate,
    pub output_state:zkvm::Predicate
}
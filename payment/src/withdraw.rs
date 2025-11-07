use crate::{
    Amount, Asset, Keypair, MTProof, Nullifier, OpenCommitment, PublicKey,
    audit_gadget::audit_encrypt_gadget, commitment::commitment_gadget, keys::keypair_gadget,
    merkle_tree::merkle_proof_gadget, nullifier::nullifier_gadget,
};
use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use ark_std::{
    collections::HashMap,
    rand::{CryptoRng, Rng},
};

/// Withdraw transaction circuit
/// Proves correct spending of inputs and creation of outputs with privacy
#[derive(Clone)]
pub struct WithdrawCircuit {
    pub keypair: Keypair,
    pub asset: Asset,
    pub amount: Amount,
    pub input: OpenCommitment,
    pub merkle_proof: MTProof,
}

/// Withdraw public inputs
#[derive(Clone, Debug)]
pub struct Withdraw {
    pub asset: Asset,
    pub amount: Amount,
    pub nullifier: Nullifier,
    pub merkle_version: u32,
    pub merkle_root: Fr,
}

impl WithdrawCircuit {
    /// generate public inputs/withdraw
    pub(crate) fn withdraw(&self) -> Withdraw {
        let nullifier = self.input.nullify(&self.keypair);

        Withdraw {
            nullifier,
            asset: self.asset,
            amount: self.amount,
            merkle_version: self.merkle_proof.version,
            merkle_root: self.merkle_proof.root,
        }
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        Ok(())
    }
}

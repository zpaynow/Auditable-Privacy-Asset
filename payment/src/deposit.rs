use crate::{
    Keypair, MTProof, OpenCommitment, PublicKey, audit_gadget::audit_encrypt_gadget,
    commitment::commitment_gadget, keys::keypair_gadget, merkle_tree::merkle_proof_gadget,
    nullifier::nullifier_gadget, Commitment, Asset, Amount
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

/// Deposit transaction circuit
/// Proves correct spending of inputs and creation of outputs with privacy
#[derive(Clone)]
pub struct DepositCircuit {
    pub asset: Asset,
    pub amount: Amount,
    pub output: OpenCommitment,
    pub audit: Option<AuditCircuit>,
}

/// Audit memo encryption circuit
#[derive(Clone)]
pub struct AuditCircuit {
    pub auditor: PublicKey,
    pub memo: Vec<u8>,
    pub share: Fr,
}

/// Deposit public struct
#[derive(Clone, Debug)]
pub struct Deposit {
    pub asset: Asset,
    pub amount: Amount,
    pub commitment: Commitment,
    pub memo: Vec<u8>,
    pub audit: Option<Audit>,
}

/// Deposit public inputs
#[derive(Clone, Debug)]
pub struct Audit {
    pub auditor: PublicKey,
    pub memo: Vec<u8>,
}

impl DepositCircuit {
    /// generate public used deposit
    pub fn deposit<R: CryptoRng + Rng>(&self, prng: &mut R) -> crate::Result<Deposit> {
        let commitment = self.output.commit();
        let memo = self.output.commitment.memo_encrypt(prng)?;

        let audit = if let Some(audit) = &self.audit {
            Some(Audit {
                auditor: audit.auditor,
                memo: audit.memo.clone(),
            })
        } else {
            None
        };

        Ok(Deposit {
            asset: self.asset,
            amount: self.amount,
            commitment,
            memo,
            audit,
        })
    }

    /// generate public inputs
    pub(crate) fn publics(&self) -> Deposit {
        let commitment = self.output.commit();

        let audit = if let Some(audit) = &self.audit {
            Some(Audit {
                auditor: audit.auditor,
                memos: audit.memo.clone(),
            })
        } else {
            None
        };

        Deposit {
            asset: self.asset,
            amount: self.amount,
            commitment,
            memos: vec![],
            audit,
        }
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        Ok(())
    }
}

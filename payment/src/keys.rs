use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig, Fr as EdFr};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::{CurveVar, curves::twisted_edwards::AffineVar},
};
use ark_relations::r1cs::SynthesisError;
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};

/// BabyJubjub: PublicKey to receive the amount
pub type PublicKey = EdwardsAffine;

/// BabyJubjub: SecretKey to spent the output
pub type SecretKey = EdFr;

/// Main keypair
#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey, // TODO add zeroize
}

impl Keypair {
    /// generate an random keypair
    pub fn generate<R: Rng + CryptoRng>(rng: &mut R) -> Keypair {
        let secret = EdFr::rand(rng);
        Self::from_secret(secret)
    }

    pub fn from_seed(seed: &[u8]) -> crate::Result<Keypair> {
        let secret = EdFr::from_random_bytes(seed).ok_or(crate::AzError::KeypairInvalidSeed)?;
        Ok(Self::from_secret(secret))
    }

    pub fn from_secret(secret: EdFr) -> Keypair {
        let public = (EdwardsAffine::generator() * secret).into_affine();

        Keypair { secret, public }
    }

    pub fn secret_to_fq(&self) -> Fr {
        let sk_int = self.secret.into_bigint();
        Fr::from_bigint(sk_int).expect("Unexpect secret error")
    }
}

/// Circuit type for Edwards curve points
type EdwardsVar = AffineVar<EdwardsConfig, FpVar<Fr>>;

/// Proves that pk = sk * G (keypair relationship)
/// This ensures the prover knows the secret key for the claimed public key
///
/// # Arguments
/// * `sk` - Secret key as field element (witness)
/// * `pk_x` - Public key X coordinate (witness)
/// * `pk_y` - Public key Y coordinate (witness)
///
/// # Constraints
/// - Decomposes sk to bits: ~254 constraints
/// - Scalar multiplication: ~2500-3000 constraints
/// - Total: ~3000-4000 constraints
pub fn keypair_gadget(
    sk: &FpVar<Fr>,
    pk_x: &FpVar<Fr>,
    pk_y: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let cs = sk.cs();

    // 1. Allocate generator as constant
    let generator = EdwardsAffine::generator();
    let generator_var = EdwardsVar::new_constant(cs.clone(), generator)?;

    // 2. Convert secret key to bits for scalar multiplication
    // EdwardsAffine uses Fr as scalar field, so we can use sk directly
    let sk_bits = sk.to_bits_le()?;

    // 3. Perform scalar multiplication: computed_pk = sk × G
    let computed_pk = generator_var.scalar_mul_le(sk_bits.iter())?;

    // 4. Extract computed coordinates
    let computed_x = computed_pk.x;
    let computed_y = computed_pk.y;

    // 5. Enforce equality with claimed public key
    computed_x.enforce_equal(pk_x)?;
    computed_y.enforce_equal(pk_y)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_keypair_gadget_valid() {
        let rng = &mut ChaCha20Rng::from_seed([42u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate a valid keypair
        let keypair = Keypair::generate(rng);

        // Allocate variables
        let sk_fr = keypair.secret_to_fq();
        let sk_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(sk_fr)).unwrap();

        let pk_x_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(keypair.public.x)).unwrap();
        let pk_y_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(keypair.public.y)).unwrap();

        // Prove keypair relationship
        keypair_gadget(&sk_var, &pk_x_var, &pk_y_var).unwrap();

        // Check constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
        println!("Keypair gadget constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_keypair_gadget_invalid() {
        let rng = &mut ChaCha20Rng::from_seed([43u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate a keypair but use wrong public key
        let keypair = Keypair::generate(rng);
        let wrong_keypair = Keypair::generate(rng);

        // Allocate variables with mismatched keys
        let sk_fr = keypair.secret_to_fq();
        let sk_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(sk_fr)).unwrap();

        // Use wrong public key
        let pk_x_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(wrong_keypair.public.x)).unwrap();
        let pk_y_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(wrong_keypair.public.y)).unwrap();

        // Try to prove keypair relationship (should fail)
        keypair_gadget(&sk_var, &pk_x_var, &pk_y_var).unwrap();

        // Constraints should NOT be satisfied
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_keypair_gadget_matches_native() {
        let rng = &mut ChaCha20Rng::from_seed([44u8; 32]);
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate keypair
        let keypair = Keypair::generate(rng);

        // Compute public key natively
        let expected_pk = keypair.public;

        // Circuit computation
        let sk_fr = keypair.secret_to_fq();
        let sk_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(sk_fr)).unwrap();

        let pk_x_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(expected_pk.x)).unwrap();
        let pk_y_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(expected_pk.y)).unwrap();

        // Prove relationship
        keypair_gadget(&sk_var, &pk_x_var, &pk_y_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(pk_x_var.value().unwrap(), expected_pk.x);
        assert_eq!(pk_y_var.value().unwrap(), expected_pk.y);
    }
}

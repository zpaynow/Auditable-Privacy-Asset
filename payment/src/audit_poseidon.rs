use crate::{AzError, Keypair, PublicKey, Result, SecretKey, poseidon::poseidon_hash};
use ark_bn254::Fr;
use ark_ec::CurveGroup;
use ark_ed_on_bn254::EdwardsAffine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    UniformRand,
    rand::{CryptoRng, Rng},
};

/// Poseidon-based hybrid encryption for field elements (aligned with circuit)
///
/// This version encrypts field elements directly, matching the circuit gadget.
/// Encrypts: [asset, amount, owner_x, owner_y, nullifier] (5 field elements)
///
/// Returns: (ciphertext_bytes, ephemeral_secret_as_Fr)
pub fn audit_encrypt_field_elements<R: CryptoRng + Rng>(
    prng: &mut R,
    auditor_pk: &PublicKey,
    field_elements: &[Fr],
) -> Result<(Vec<u8>, Fr)> {
    // 1. Generate ephemeral keypair for ECDH
    let ephemeral_secret = SecretKey::rand(prng);
    let ephemeral_keypair = Keypair::from_secret(ephemeral_secret);

    // 2. Compute shared secret: shared = auditor_pk * ephemeral_sk
    let shared = *auditor_pk * ephemeral_keypair.secret;
    let shared_affine = shared.into_affine();

    // 3. Derive encryption key using Poseidon: key = Poseidon(shared_x, shared_y)
    let key = poseidon_hash(&[shared_affine.x, shared_affine.y]);

    // 4. Encrypt using Poseidon stream cipher
    // ciphertext[i] = plaintext[i] + Poseidon(key, nonce=0, i)
    let mut ciphertexts = Vec::with_capacity(field_elements.len());
    for (i, plaintext) in field_elements.iter().enumerate() {
        let keystream = poseidon_hash(&[key, Fr::from(0u64), Fr::from(i as u64)]);
        let ciphertext = *plaintext + keystream;
        ciphertexts.push(ciphertext);
    }

    // 5. Serialize: ephemeral_pk || ciphertexts
    let mut bytes = vec![];

    // Serialize ephemeral public key (uncompressed: 64 bytes)
    ephemeral_keypair
        .public
        .serialize_uncompressed(&mut bytes)
        .map_err(|_| AzError::Encryption)?;

    // Serialize ciphertexts (32 bytes each)
    for ct in &ciphertexts {
        ct.serialize_compressed(&mut bytes)
            .map_err(|_| AzError::Encryption)?;
    }

    // Convert ephemeral secret to Fr for circuit proof
    let ephemeral_secret_fr = ephemeral_keypair.secret_to_fq();

    Ok((bytes, ephemeral_secret_fr))
}

/// Decrypts field element ciphertext
///
/// Returns the decrypted field elements
pub fn audit_decrypt_field_elements(auditor_keypair: &Keypair, ctext: &[u8]) -> Result<Vec<Fr>> {
    // 1. Deserialize ephemeral public key (64 bytes compressed)
    let pk_size = auditor_keypair.public.uncompressed_size();
    if ctext.len() < pk_size {
        return Err(AzError::Decryption);
    }

    let ephemeral_pk = EdwardsAffine::deserialize_uncompressed(&ctext[..pk_size])
        .map_err(|_| AzError::Decryption)?;

    // 2. Compute shared secret: shared = ephemeral_pk * auditor_sk
    let shared = ephemeral_pk * auditor_keypair.secret;
    let shared_affine = shared.into_affine();

    // 3. Derive decryption key: key = Poseidon(shared_x, shared_y)
    let key = poseidon_hash(&[shared_affine.x, shared_affine.y]);

    // 4. Deserialize ciphertexts (32 bytes each)
    let mut ciphertexts = Vec::new();
    for bytes in ctext[pk_size..].chunks(32) {
        let ct = Fr::deserialize_compressed(bytes).map_err(|_| AzError::Decryption)?;
        ciphertexts.push(ct);
    }

    // 5. Decrypt using Poseidon stream cipher
    // plaintext[i] = ciphertext[i] - Poseidon(key, nonce=0, i)
    let mut plaintexts = Vec::with_capacity(ciphertexts.len());
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        let keystream = poseidon_hash(&[key, Fr::from(0u64), Fr::from(i as u64)]);
        let plaintext = *ciphertext - keystream;
        plaintexts.push(plaintext);
    }

    Ok(plaintexts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_field_element_encrypt_decrypt() {
        let rng = &mut ChaCha20Rng::from_seed([45u8; 32]);

        let auditor = Keypair::generate(rng);

        // Test field elements: [asset, amount, owner_x, owner_y, nullifier]
        let field_elements = vec![
            Fr::from(1u64),      // asset
            Fr::from(100u64),    // amount
            Fr::from(123456u64), // owner_x (simplified)
            Fr::from(789012u64), // owner_y (simplified)
            Fr::from(999999u64), // nullifier (simplified)
        ];

        let (ciphertext, _ephemeral_secret) =
            audit_encrypt_field_elements(rng, &auditor.public, &field_elements).unwrap();

        // Verify ciphertext size: 64 (ephemeral_pk) + 5*32 (ciphertexts) = 224 bytes
        assert_eq!(ciphertext.len(), 224);

        let decrypted = audit_decrypt_field_elements(&auditor, &ciphertext).unwrap();

        assert_eq!(field_elements, decrypted);
    }

    #[test]
    fn test_field_element_different_keys_fail() {
        let rng = &mut ChaCha20Rng::from_seed([46u8; 32]);

        let auditor1 = Keypair::generate(rng);
        let auditor2 = Keypair::generate(rng);

        let field_elements = vec![Fr::from(1u64), Fr::from(100u64), Fr::from(123u64)];

        let (ciphertext, _) =
            audit_encrypt_field_elements(rng, &auditor1.public, &field_elements).unwrap();

        // Try to decrypt with wrong key
        let decrypted = audit_decrypt_field_elements(&auditor2, &ciphertext).unwrap();

        // Should produce garbage, not the original field elements
        assert_ne!(field_elements, decrypted);
    }
}

//! Non-interactive Zero Knowledge proof for correct Hybrid
//! decryption key generation. We use the notation and scheme
//! presented in Figure 5 of the Treasury voting protocol spec.
//!
//! The proof is the following:
//!
//! `NIZK{(pk, C = (C1, C2), D), (sk): D = C1^sk AND pk = g^sk}`
//!
//! which is a proof of discrete log equality. We can therefore prove
//! correct decryption using a proof of discrete log equality.
use crate::cryptography::dl_equality::DleqZkp;
use crate::cryptography::elgamal::{HybridCiphertext, PublicKey, SecretKey, SymmetricKey};
use crate::traits::PrimeGroupElement;
use rand_core::{CryptoRng, RngCore};

/// Proof of correct decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zkp<G: PrimeGroupElement> {
    hybrid_dec_key_proof: DleqZkp<G>,
}

impl<G> Zkp<G>
where
    G: PrimeGroupElement,
{
    /// Generate a decryption zero knowledge proof.
    pub fn generate<R>(
        c: &HybridCiphertext<G>,
        pk: &PublicKey<G>,
        symmetric_key: &SymmetricKey<G>,
        sk: &SecretKey<G>,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let hybrid_dec_key_proof = DleqZkp::generate(
            &G::generator(),
            &c.e1,
            &pk.pk,
            &symmetric_key.group_repr,
            &sk.sk,
            rng,
        );
        Zkp {
            hybrid_dec_key_proof,
        }
    }

    /// Verify a decryption zero knowledge proof
    pub fn verify(
        &self,
        c: &HybridCiphertext<G>,
        symmetric_key: &SymmetricKey<G>,
        pk: &PublicKey<G>,
    ) -> bool {
        self.hybrid_dec_key_proof
            .verify(&G::generator(), &c.e1, &pk.pk, &symmetric_key.group_repr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::elgamal::Keypair;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand_core::OsRng;

    #[test]
    pub fn it_works() {
        let mut r = OsRng;

        let keypair = Keypair::<RistrettoPoint>::generate(&mut r);

        let plaintext = [10u8; 43];
        let ciphertext = keypair.public_key.hybrid_encrypt(&plaintext, &mut r);

        let decryption_key = keypair.secret_key.recover_symmetric_key(&ciphertext);

        let proof = Zkp::generate(
            &ciphertext,
            &keypair.public_key,
            &decryption_key,
            &keypair.secret_key,
            &mut r,
        );
        assert!(proof.verify(&ciphertext, &decryption_key, &keypair.public_key))
    }
}

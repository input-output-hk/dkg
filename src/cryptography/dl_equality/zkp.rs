//! Non-interactive Zero Knowledge proof of Discrete Logarithm
//! EQuality (DLEQ).
//!
//! The proof is the following:
//!
//! `NIZK{(base_1, base_2, point_1, point_2), (dlog): point_1 = base_1^dlog AND point_2 = base_2^dlog}`
//!
//! which makes the statement, the two bases `base_1` and `base_2`, and the two
//! points `point_1` and `point_2`. The witness, on the other hand
//! is the discrete logarithm, `dlog`.
#![allow(clippy::many_single_char_names)]
use super::challenge_context::ChallengeContext;
use crate::errors::ProofError;
use crate::traits;
use crate::traits::{PrimeGroupElement, Scalar};
use generic_array::typenum::{Sum, Unsigned};
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use std::ops::Add;

/// Proof of correct decryption.
/// Note: if the goal is to reduce the size of a proof, it is better to store the challenge
/// and the response. If on the other hand we want to allow for batch verification of
/// proofs, we should store the announcements and the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zkp<G: PrimeGroupElement> {
    challenge: G::CorrespondingScalar,
    response: G::CorrespondingScalar,
}

impl<G: PrimeGroupElement> Zkp<G> {
    /// Generate a DLEQ proof
    pub fn generate<R>(
        base_1: &G,
        base_2: &G,
        point_1: &G,
        point_2: &G,
        dlog: &G::CorrespondingScalar,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let w = G::CorrespondingScalar::random(rng);
        let announcement_1 = *base_1 * w;
        let announcement_2 = *base_2 * w;
        let mut challenge_context = ChallengeContext::new(base_1, base_2, point_1, point_2);
        let challenge = challenge_context.first_challenge(&announcement_1, &announcement_2);
        let response = challenge * *dlog + w;

        Zkp {
            challenge,
            response,
        }
    }

    /// Verify a DLEQ proof
    pub fn verify(
        &self,
        base_1: &G,
        base_2: &G,
        point_1: &G,
        point_2: &G,
    ) -> Result<(), ProofError> {
        let r1 = *base_1 * self.response;
        let r2 = *base_2 * self.response;
        let announcement_1 = r1 - (*point_1 * self.challenge);
        let announcement_2 = r2 - (*point_2 * self.challenge);

        let mut challenge_context = ChallengeContext::new(base_1, base_2, point_1, point_2);
        let challenge = challenge_context.first_challenge(&announcement_1, &announcement_2);
        // no need for constant time equality because of the hash in challenge()
        if challenge == self.challenge {
            Ok(())
        } else {
            Err(ProofError::ZkpVerificationFailed)
        }
    }

    pub fn to_bytes(
        &self,
    ) -> GenericArray<
        u8,
        Sum<
            <G::CorrespondingScalar as Scalar>::EncodingSize,
            <G::CorrespondingScalar as Scalar>::EncodingSize,
        >,
    >
        where
            <<<G as PrimeGroupElement>::CorrespondingScalar as traits::Scalar>::EncodingSize as Add>::Output: ArrayLength<u8>

    {
        let mut bytes = self.challenge.to_bytes().to_vec();
        bytes.extend_from_slice(self.response.to_bytes().as_slice());
        GenericArray::from_slice(&bytes).clone()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let size: usize =
            <<G::CorrespondingScalar as Scalar>::EncodingSize as Unsigned>::to_usize();
        if bytes.len() != 2 * size {
            return None;
        }
        let challenge = Scalar::from_bytes(&bytes[..size])?;
        let response = Scalar::from_bytes(&bytes[size..])?;

        Some(Self {
            challenge,
            response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Blake2b;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn it_works() {
        let mut r = ChaCha20Rng::from_seed([0u8; 32]);

        let dlog = Scalar::random(&mut r);
        let base_1 = RistrettoPoint::hash_to_group::<Blake2b>(&[0u8]);
        let base_2 = RistrettoPoint::hash_to_group::<Blake2b>(&[0u8]);
        let point_1 = base_1 * dlog;
        let point_2 = base_2 * dlog;

        let proof =
            Zkp::<RistrettoPoint>::generate(&base_1, &base_2, &point_1, &point_2, &dlog, &mut r);

        assert!(proof.verify(&base_1, &base_2, &point_1, &point_2).is_ok());

        let base_faked = RistrettoPoint::hash_to_group::<Blake2b>(&[13u8]);

        assert!(proof
            .verify(&base_1, &base_faked, &point_1, &point_2)
            .is_err());
    }

    #[test]
    fn serialisation() {
        let mut r = ChaCha20Rng::from_seed([0u8; 32]);

        let dlog = Scalar::random(&mut r);
        let base_1 = RistrettoPoint::hash_to_group::<Blake2b>(&[0u8]);
        let base_2 = RistrettoPoint::hash_to_group::<Blake2b>(&[0u8]);
        let point_1 = base_1 * dlog;
        let point_2 = base_2 * dlog;

        let proof =
            Zkp::<RistrettoPoint>::generate(&base_1, &base_2, &point_1, &point_2, &dlog, &mut r);

        let bytes = proof.to_bytes();
        let deserialised = Zkp::from_bytes(&bytes);
        assert!(deserialised.is_some());
        let unwrapped = deserialised.unwrap();
        assert!(unwrapped
            .verify(&base_1, &base_2, &point_1, &point_2)
            .is_ok())
    }
}

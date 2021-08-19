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
use rand_core::{CryptoRng, RngCore};
use crate::traits::{PrimeGroupElement, Scalar};
use std::ops::Mul;
use generic_array::GenericArray;

/// Proof of correct decryption.
/// Note: if the goal is to reduce the size of a proof, it is better to store the challenge
/// and the response. If on the other hand we want to allow for batch verification of
/// proofs, we should store the announcements and the response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Zkp<G: PrimeGroupElement> {
    challenge: G::CorrespondingScalar,
    response: G::CorrespondingScalar,
}

impl<G> Zkp<G>
where
    G: PrimeGroupElement,
    // Would be great to be able to specify the supertrait for the reference of the trait.
    // Does not seem possible: https://stackoverflow.com/questions/58849618/how-to-specify-a-supertrait-for-the-reference-of-a-trait
    for<'a> &'a G: Mul<G::CorrespondingScalar, Output = G>
{
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
        let announcement_1 = base_1 * w;
        let announcement_2 = base_2 * w;
        let mut challenge_context = ChallengeContext::new(base_1, base_2, point_1, point_2);
        let challenge = challenge_context.first_challenge(&announcement_1, &announcement_2);
        let response = challenge * dlog + w;

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
    ) -> bool {
        let r1 = base_1 * self.response;
        let r2 = base_2 * self.response;
        let announcement_1 = r1 - (point_1 * self.challenge);
        let announcement_2 = r2 - (point_2 * self.challenge );

        let mut challenge_context = ChallengeContext::new(base_1, base_2, point_1, point_2);
        let challenge = challenge_context.first_challenge(&announcement_1, &announcement_2);
        // no need for constant time equality because of the hash in challenge()
        challenge == self.challenge
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use super::*;
    use rand_core::OsRng;

    #[test]
    pub fn it_works() {
        let mut r: OsRng = OsRng;

        let dlog = Scalar::random(&mut r);
        let base_1 = RistrettoPoint::hash_to_group(&[0u8]);
        let base_2 = RistrettoPoint::hash_to_group(&[0u8]);
        let point_1 = base_1 * dlog;
        let point_2 = base_2 * dlog;

        let proof = Zkp::<RistrettoPoint>::generate(&base_1, &base_2, &point_1, &point_2, &dlog, &mut r);

        assert!(proof.verify(&base_1, &base_2, &point_1, &point_2));
    }
}

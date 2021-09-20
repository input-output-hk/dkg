use crate::traits::{PrimeGroupElement, Scalar};
use blake2::Blake2b;
use rand_core::{CryptoRng, RngCore};

/// Pedersen Commitment key
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitmentKey<G: PrimeGroupElement> {
    pub h: G,
}

impl<G: PrimeGroupElement> CommitmentKey<G> {
    /// Generate a new random commitment key by hashing the input
    pub fn generate(bytes: &[u8]) -> Self {
        CommitmentKey::<G> {
            h: G::hash_to_group::<Blake2b>(bytes),
        }
    }
    /// Return a commitment with the given opening, `o`
    pub fn commit_with_open(&self, o: &Open<G>) -> G {
        self.commit_with_random(&o.m, &o.r)
    }

    // Return a commitment with the given message, `m`,  and opening key, `r`
    fn commit_with_random(&self, m: &G::CorrespondingScalar, r: &G::CorrespondingScalar) -> G {
        G::generator() * *m + self.h * *r
    }

    /// Return a commitment, and the used randomness, `r`, where the latter is computed
    /// from a `Rng + CryptoRng`
    pub fn commit<R>(&self, m: &G::CorrespondingScalar, rng: &mut R) -> (G, G::CorrespondingScalar)
    where
        R: CryptoRng + RngCore,
    {
        let r = G::CorrespondingScalar::random(rng);
        (self.commit_with_random(m, &r), r)
    }

    /// Return a commitment of a boolean value, and the used randomness, `r`, where the latter is computed
    /// from a `Rng + CryptoRng`
    pub fn commit_bool<R>(&self, m: bool, rng: &mut R) -> (G, G::CorrespondingScalar)
    where
        R: CryptoRng + RngCore,
    {
        let r = G::CorrespondingScalar::random(rng);
        if m {
            (G::generator() + self.h * r, r)
        } else {
            (self.h * r, r)
        }
    }

    /// Verify that a given `commitment` opens to `o` under commitment key `self`
    #[allow(dead_code)]
    pub fn verify(&self, commitment: &G, o: &Open<G>) -> bool {
        let other = self.commit_with_open(o);
        commitment == &other
    }

    pub fn to_bytes(&self) -> [u8; G::SIZE] {
        self.h.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        G::from_bytes(bytes).map(|h| Self { h })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Open<G: PrimeGroupElement> {
    pub m: G::CorrespondingScalar,
    pub r: G::CorrespondingScalar,
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar as RScalar;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn commit_and_open() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let commitment_key = CommitmentKey::<RistrettoPoint>::generate(&[0u8]);
        let message = RScalar::random(&mut rng);
        let (comm, rand) = commitment_key.commit(&message, &mut rng);

        let opening = Open {
            m: message,
            r: rand,
        };

        assert!(commitment_key.verify(&comm, &opening));

        let comm_with_rand = commitment_key.commit_with_random(&message, &rand);

        assert_eq!(comm_with_rand, comm);

        let comm_with_open = commitment_key.commit_with_open(&opening);

        assert_eq!(comm_with_open, comm);
    }
}

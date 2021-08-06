#![allow(dead_code)]

//! Implementation of the different encryption/decryption mechanisms used in `chain-vote`, including their
//! corresponding structures. In particular, we use (lifted) ElGamal cryptosystem, and combine with ChaCha
//! stream cipher to produce a hybrid encryption scheme.

use crate::traits::{PrimeGroupElement, Scalar};
use rand_core::{CryptoRng, RngCore};

#[derive(Debug, Clone, Eq, PartialEq)]
/// ElGamal public key. pk = sk * G, where sk is the `SecretKey` and G is the group
/// generator.
pub struct PublicKey<G: PrimeGroupElement> {
    pub pk: G,
}

#[derive(Clone)]
/// ElGamal secret key
pub struct SecretKey<G: PrimeGroupElement> {
    pub sk: G::CorrespondingScalar,
}

#[derive(Clone)]
/// ElGamal keypair
pub struct Keypair<G: PrimeGroupElement> {
    pub secret_key: SecretKey<G>,
    pub public_key: PublicKey<G>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// ElGamal ciphertext. Given a message M represented by a group element, and ElGamal
/// ciphertext consists of (r * G; M + r * `PublicKey`), where r is a random `Scalar`.
pub struct Ciphertext<G: PrimeGroupElement> {
    pub(crate) e1: G,
    pub(crate) e2: G,
}

impl<G: PrimeGroupElement> PublicKey<G>
{
    /// Given a `message` represented as a group element, return a ciphertext.
    pub(crate) fn encrypt_point<R>(&self, message: &G, rng: &mut R) -> Ciphertext<G>
    where
        R: RngCore + CryptoRng,
    {
        let r = G::CorrespondingScalar::random(rng);
        self.encrypt_point_with_r(&message, &r)
    }

    // Given a `message` represented as a group element, return a ciphertext and the
    // randomness used.
    fn encrypt_point_return_r<R>(&self, message: &G, rng: &mut R) -> (Ciphertext<G>, G::CorrespondingScalar)
    where
        R: RngCore + CryptoRng,
    {
        let r = G::CorrespondingScalar::random(rng);
        (self.encrypt_point_with_r(&message, &r), r)
    }

    // Given a `message` represented as a group element, and some value used as `randomness`,
    // return the corresponding ciphertext. This function should only be called when the
    // randomness value needs to be a particular value (e.g. verification procedure of the unit vector ZKP).
    // Otherwise, `encrypt_point` should be used.
    fn encrypt_point_with_r(&self, message: &G, randomness: &G::CorrespondingScalar) -> Ciphertext<G> {
        Ciphertext {
            e1: G::generator() * randomness,
            e2: (self.pk * randomness) + message,
        }
    }

    /// Given a `message` represented as a `Scalar`, return a ciphertext using the
    /// "lifted ElGamal" mechanism. Mainly, return (r * G; `message` * G + r * `self`)
    pub(crate) fn encrypt<R>(&self, message: &G::CorrespondingScalar, rng: &mut R) -> Ciphertext<G>
    where
        R: RngCore + CryptoRng,
    {
        self.encrypt_point(&(G::generator() * message), rng)
    }

    /// Given a `message` represented as a `Scalar`, return a ciphertext and return
    /// the randomness used.
    pub(crate) fn encrypt_return_r<R>(&self, message: &G::CorrespondingScalar, rng: &mut R) -> (Ciphertext<G>, G::CorrespondingScalar)
    where
        R: RngCore + CryptoRng,
    {
        self.encrypt_point_return_r(&(G::generator() * message), rng)
    }

    /// Given a `message` represented as a `Scalar`, and some value used as `randomness`,
    /// return the corresponding ciphertext. This function should only be called when the
    /// randomness value is not random (e.g. verification procedure of the unit vector ZKP).
    /// Otherwise, `encrypt_point` should be used.
    pub(crate) fn encrypt_with_r(&self, message: &G::CorrespondingScalar, randomness: &G::CorrespondingScalar) -> Ciphertext<G> {
        self.encrypt_point_with_r(&(G::generator() * message), randomness)
    }
}

impl<G: PrimeGroupElement> SecretKey<G> {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = G::CorrespondingScalar::random(rng);
        Self { sk }
    }

    /// Decrypt ElGamal `Ciphertext` = (`cipher`.e1, `cipher`.e2), by computing
    /// `cipher`.e2 - `self` * `cipher`.e1. This returns the plaintext respresented
    /// as a `PrimeGroupElement`.
    pub(crate) fn decrypt_point(&self, cipher: &Ciphertext<G>) -> G {
        (cipher.e1 * (-self.sk)) + cipher.e2
    }
}


impl<G: PrimeGroupElement> Keypair<G> {
    #[allow(dead_code)]
    pub fn from_secretkey(secret_key: SecretKey<G>) -> Self {
        let public_key = PublicKey {
            pk: G::generator() * secret_key.sk,
        };
        Keypair {
            secret_key,
            public_key,
        }
    }

    /// Generate a keypair for encryption
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Keypair<G> {
        let sk = G::CorrespondingScalar::random(rng);
        let pk = G::generator() * sk;
        Keypair {
            secret_key: SecretKey::<G> { sk },
            public_key: PublicKey::<G> { pk },
        }
    }
}

impl<G: PrimeGroupElement> Ciphertext<G> {
    /// the zero ciphertext
    pub fn zero() -> Self {
        Ciphertext {
            e1: G::zero(),
            e2: G::zero(),
        }
    }

    pub fn elements(&self) -> (&G, &G) {
        (&self.e1, &self.e2)
    }
}
//
// impl<'a, 'b, G: PrimeGroupElement> Add<&'b Ciphertext<G>> for &'a Ciphertext<G> {
//     type Output = Ciphertext<G>;
//
//     fn add(self, other: &'b Ciphertext<G>) -> Ciphertext<G> {
//         Ciphertext {
//             e1: &self.e1 + &other.e1,
//             e2: &self.e2 + &other.e2,
//         }
//     }
// }
//
// std_ops_gen!(Ciphertext, Add, Ciphertext, Ciphertext, add);
//
// impl<'a, 'b, G: PrimeGroupElement> Sub<&'b Ciphertext> for &'a Ciphertext {
//     type Output = Ciphertext;
//
//     fn sub(self, other: &'b Ciphertext) -> Ciphertext {
//         Ciphertext {
//             e1: &self.e1 - &other.e1,
//             e2: &self.e2 - &other.e2,
//         }
//     }
// }
//
// std_ops_gen!(Ciphertext, Sub, Ciphertext, Ciphertext, sub);
//
// impl<'a, 'b, G: PrimeGroupElement> Mul<&'b Scalar> for &'a Ciphertext {
//     type Output = Ciphertext;
//     fn mul(self, rhs: &'b Scalar) -> Self::Output {
//         Ciphertext {
//             e1: &self.e1 * rhs,
//             e2: &self.e2 * rhs,
//         }
//     }
// }
//
// std_ops_gen!(Ciphertext, Mul, Scalar, Ciphertext, mul);
//
// impl<'a> Mul<u64> for &'a Ciphertext {
//     type Output = Ciphertext;
//     fn mul(self, rhs: u64) -> Self::Output {
//         Ciphertext {
//             e1: &self.e1 * rhs,
//             e2: &self.e2 * rhs,
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar as RScalar;
    use curve25519_dalek::traits::Identity;
    use blake2::Blake2b;

    use rand_core::OsRng;

    impl Scalar for RScalar {
        type Item = RScalar;

        fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
            RScalar::random(rng)
        }

        fn from_u64(scalar: u64) -> Self {
            RScalar::from(scalar)
        }
    }

    impl PrimeGroupElement for RistrettoPoint {
        type Item = RistrettoPoint;
        type CorrespondingScalar = RScalar;

        fn generator() -> Self {
            RISTRETTO_BASEPOINT_POINT
        }

        fn zero() -> Self {
            RistrettoPoint::identity()
        }

        fn from_hash(input: &[u8]) -> Self {
            RistrettoPoint::hash_from_bytes::<Blake2b>(input)
        }
    }

    // #[test]
    // fn zero() {
    //     let cipher = Ciphertext {
    //         e1: PrimeGroupElement::zero(),
    //         e2: PrimeGroupElement::zero(),
    //     };
    //     assert_eq!(Ciphertext::zero(), cipher)
    // }

    #[test]
    fn encrypt_decrypt_point() {
        let mut rng = OsRng;

        for n in 1..5 {
            let keypair = Keypair::<RistrettoPoint>::generate(&mut rng);
            let m = RistrettoPoint::generator() * RScalar::from_u64(n * 24);
            let cipher = keypair.public_key.encrypt_point(&m, &mut rng);
            let r = keypair.secret_key.decrypt_point(&cipher);
            assert_eq!(m, r)
        }
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rng = OsRng;

        for n in 1..5 {
            let keypair = Keypair::<RistrettoPoint>::generate(&mut rng);
            let m = RScalar::from_u64(n * 24);
            let cipher = keypair.public_key.encrypt(&m, &mut rng);
            let r = keypair.secret_key.decrypt_point(&cipher);
            assert_eq!(m * RistrettoPoint::generator(), r)
        }
    }
    //
    // #[test]
    // fn symmetric_encrypt_decrypt() {
    //     let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    //     let k = SecretKey::generate(&mut rng);
    //     let k = Keypair::from_secretkey(k);
    //
    //     let m = [1, 3, 4, 5, 6, 7];
    //
    //     let encrypted = &k.public_key.hybrid_encrypt(&m, &mut rng);
    //     let result = &k.secret_key.hybrid_decrypt(&encrypted);
    //
    //     assert_eq!(&m[..], &result[..])
    // }
}

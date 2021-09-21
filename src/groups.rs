use crate::traits::{PrimeGroupElement, Scalar};
use blake2::Digest;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as RScalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use generic_array::typenum::U64;
use rand_core::{CryptoRng, RngCore};

impl Scalar for RScalar {
    type Item = RScalar;
    const SIZE: usize = 32;

    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        RScalar::random(rng)
    }

    fn from_u64(scalar: u64) -> Self {
        RScalar::from(scalar)
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut bits = [0u8; 32];
        bits.copy_from_slice(bytes);
        Some(RScalar::from_bits(bits))
    }

    fn zero() -> Self {
        RScalar::zero()
    }

    fn one() -> Self {
        RScalar::one()
    }

    fn inverse(&self) -> Self {
        self.invert()
    }

    fn hash_to_scalar<H: Digest<OutputSize = U64> + Default>(input: &[u8]) -> Self {
        RScalar::hash_from_bytes::<H>(input)
    }
}

impl PrimeGroupElement for RistrettoPoint {
    type Item = RistrettoPoint;
    type CorrespondingScalar = RScalar;
    const SIZE: usize = 32;

    fn generator() -> Self {
        RISTRETTO_BASEPOINT_POINT
    }

    fn zero() -> Self {
        RistrettoPoint::identity()
    }

    fn hash_to_group<H: Digest<OutputSize = U64> + Default>(input: &[u8]) -> Self {
        RistrettoPoint::hash_from_bytes::<H>(input)
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.compress().to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let compressed_point = CompressedRistretto::from_slice(bytes);
        compressed_point.decompress()
    }

    fn vartime_multiscalar_multiplication<I, J>(scalars: I, points: J) -> Self
    where
        I: IntoIterator<Item = Self::CorrespondingScalar>,
        J: IntoIterator<Item = Self>,
    {
        RistrettoPoint::vartime_multiscalar_mul(scalars.into_iter(), points.into_iter())
    }
}

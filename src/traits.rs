use std::ops::{Add, Mul, Neg, Sub, AddAssign};
use std::fmt::Debug;
use rand_core::{CryptoRng, RngCore};
use generic_array::{ArrayLength, GenericArray};

pub trait Scalar:
    Copy
    + Clone
    + Debug
    + Default
    + Send
    + Sync
    + Eq
    + Neg<Output = Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + AddAssign<Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Mul<Self, Output = Self>
    + core::iter::Sum<Self>
    + for<'a> core::iter::Sum<&'a Self>
{
    type Item;

    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    fn from_u64(scalar: u64) -> Self;
}

pub trait PrimeGroupElement:
    Copy
    + Clone
    + Debug
    + Default
    + Send
    + Sync
    + Eq
    + Neg<Output = Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<<Self as PrimeGroupElement>::CorrespondingScalar, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> Mul<&'a <Self as PrimeGroupElement>::CorrespondingScalar, Output = Self>
    + core::iter::Sum<Self>
    + for<'a> core::iter::Sum<&'a Self>
{
    type Item;
    type CorrespondingScalar: Scalar;
    /// Output size for fixed output digest
    type EncodingSize: ArrayLength<u8>;

    fn generator() -> Self;

    fn zero() -> Self;

    fn from_hash(input: &[u8]) -> Self;

    fn to_bytes(&self) -> GenericArray<u8, Self::EncodingSize>;
}
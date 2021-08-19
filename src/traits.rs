use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub};
use blake2::Blake2b;

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
    + for<'a> Mul<&'a Self, Output = Self>
    + core::iter::Sum<Self>
    + for<'a> core::iter::Sum<&'a Self>
{
    type Item;
    type EncodingSize: ArrayLength<u8>;

    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    fn hash_to_scalar(input: Blake2b) -> Self;

    fn from_u64(scalar: u64) -> Self;

    fn to_bytes(&self) -> GenericArray<u8, Self::EncodingSize>;

    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    fn zero() -> Self;

    fn one() -> Self;

    fn exp_iter(&self) -> ScalarExp<Self> {
        let next_exp_x = Self::one();
        ScalarExp {
            x: *self,
            next_exp_x,
        }
    }
}

/// Provides an iterator over the powers of a `Scalar`.
///
/// This struct is created by the `exp_iter` function.
#[derive(Clone)]
pub struct ScalarExp<S: Scalar> {
    x: S,
    next_exp_x: S,
}

impl<S: Scalar> Iterator for ScalarExp<S> {
    type Item = S;

    fn next(&mut self) -> Option<S> {
        let exp_x = self.next_exp_x;
        self.next_exp_x = self.next_exp_x * self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
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
    /// todo: Ideally, it would be much more practical to define an associated constant. While this
    /// is expected to be included in future versions, it's usage is still quite limited. ,
    /// https://github.com/rust-lang/rust/issues/60551
    ///
    /// Defined as future work for now.
    type EncodingSize: ArrayLength<u8>;

    fn generator() -> Self;

    fn zero() -> Self;

    fn hash_to_group(input: &[u8]) -> Self;

    fn to_bytes(&self) -> GenericArray<u8, Self::EncodingSize>;

    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    fn vartime_multiscalar_multiplication<I, J>(scalars: I, points: J) -> Self
    where
        I: IntoIterator<Item = Self::CorrespondingScalar>,
        J: IntoIterator<Item = Self>;
}

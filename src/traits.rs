//! Trait definition for simplifying the representation of a group structure,
//! where we only need to two types (a scalar and a group element) with a binary
//! operation. These traits do not restrict on safe/unsafe groups, so it could
//! easily be called over `usize`, which would render the scheme insecure. We
//! restrict the use of this traits to the groups defined in `groups.rs`.
//!
//! An example of a valid group to instantiate this protocol is the [ristretto]
//! group. For that, we leverage the implementation available in the
//! [curve25519_dalek] crate.
//!
//! One can different point as follows
//!
//! # Examples
//!
//! ```rust
//! use blake2::Digest;
//! use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
//! use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
//! use curve25519_dalek::scalar::Scalar as RScalar;
//! use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
//! use derive_more::{Add, AddAssign, From, Mul, Neg, Sub};
//! use generic_array::typenum::{U32, U64};
//! use generic_array::GenericArray;
//! use rand_core::{CryptoRng, RngCore};
//! use DKG::traits::{PrimeGroupElement, Scalar};
//!
//! #[derive(Add, Sub, Neg, Mul, AddAssign, From, Clone, Copy, Debug, Eq, PartialEq)]
//! #[mul(forward)]
//! struct ScalarWrapper(RScalar);
//!
//! impl Scalar for ScalarWrapper {
//!     type Item = ScalarWrapper;
//!     type EncodingSize = U32;
//!
//!     fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
//!         Self(RScalar::random(rng))
//!     }
//!
//!     fn from_u64(scalar: u64) -> Self {
//!         ScalarWrapper(RScalar::from(scalar))
//!     }
//!
//!     fn to_bytes(&self) -> GenericArray<u8, U32> {
//!         let mut array = GenericArray::default();
//!         array.copy_from_slice(&self.to_bytes()[..]);
//!         array
//!     }
//!
//!     fn from_bytes(bytes: &[u8]) -> Option<Self> {
//!         if bytes.len() != 32 {
//!             return None;
//!         }
//!         let mut bits = [0u8; 32];
//!         bits.copy_from_slice(bytes);
//!         Some(ScalarWrapper(RScalar::from_bits(bits)))
//!     }
//!
//!     fn zero() -> Self {
//!         Self(RScalar::zero())
//!     }
//!
//!     fn one() -> Self {
//!         Self(RScalar::one())
//!     }
//!
//!     fn inverse(&self) -> Self {
//!         Self(self.0.invert())
//!     }
//!
//!     fn hash_to_scalar<H: Digest<OutputSize = U64> + Default>(input: &[u8]) -> Self {
//!         Self(RScalar::hash_from_bytes::<H>(input))
//!     }
//! }
//!
//! #[derive(Add, Sub, Neg, Mul, AddAssign, From, Clone, Copy, Debug, Eq, PartialEq)]
//! struct GroupElementWrapper(RistrettoPoint);
//!
//! impl std::ops::Mul<<GroupElementWrapper as PrimeGroupElement>::CorrespondingScalar>
//! for GroupElementWrapper
//! {
//!     type Output = Self;
//!
//!     fn mul(
//!         self,
//!         rhs: <GroupElementWrapper as PrimeGroupElement>::CorrespondingScalar,
//!     ) -> Self::Output {
//!         Self(self.0.mul(rhs.0))
//!     }
//! }
//!
//! impl PrimeGroupElement for GroupElementWrapper {
//!     type Item = GroupElementWrapper;
//!     type CorrespondingScalar = ScalarWrapper;
//!     type EncodingSize = U32;
//!     type CorrespondingScalarSize = U32;
//!     const SIZE: usize = 32;
//!
//!     fn generator() -> Self {
//!         Self(RISTRETTO_BASEPOINT_POINT)
//!     }
//!
//!     fn zero() -> Self {
//!         GroupElementWrapper(RistrettoPoint::identity())
//!     }
//!
//!     fn hash_to_group<H: Digest<OutputSize = U64> + Default>(input: &[u8]) -> Self {
//!         GroupElementWrapper(RistrettoPoint::hash_from_bytes::<H>(input))
//!     }
//!
//!     fn to_bytes(&self) -> [u8; Self::SIZE] {
//!         self.0.compress().to_bytes()
//!     }
//!
//!     fn from_bytes(bytes: &[u8]) -> Option<Self> {
//!         let compressed_point = CompressedRistretto::from_slice(bytes);
//!         compressed_point.decompress().map(Self)
//!     }
//!
//!     fn vartime_multiscalar_multiplication<I, J>(scalars: I, points: J) -> Self
//!         where
//!             I: IntoIterator<Item = Self::CorrespondingScalar>,
//!             J: IntoIterator<Item = Self>,
//!     {
//!         Self(RistrettoPoint::vartime_multiscalar_mul(
//!             scalars.into_iter().map(|s| s.0),
//!             points.into_iter().map(|s| s.0),
//!         ))
//!     }
//! }
//! ```
//!
//! [ristretto]: https://ristretto.group/
//! [curve25519_dalek]: https://doc.dalek.rs/curve25519_dalek/index.html

use blake2::Digest;
use generic_array::typenum::U64;
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub};

pub trait Scalar:
    Copy
    + Clone
    + Debug
    + Eq
    + Neg<Output = Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + AddAssign<Self>
{
    type Item;
    const SIZE: usize;

    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

    fn hash_to_scalar<H: Digest<OutputSize = U64> + Default>(input: &[u8]) -> Self;

    fn from_u64(scalar: u64) -> Self;

    fn to_bytes(&self) -> [u8; Self::SIZE];

    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    fn zero() -> Self;

    fn one() -> Self;

    fn inverse(&self) -> Self;

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
    + Eq
    + Neg<Output = Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<<Self as PrimeGroupElement>::CorrespondingScalar, Output = Self>
{
    type Item;
    type CorrespondingScalar: Scalar;
    /// Output size for fixed output digest
    /// todo: Ideally, it would be much more practical to define an associated constant. While this
    /// is expected to be included in future versions, it's usage is still quite limited. ,
    /// https://github.com/rust-lang/rust/issues/60551
    ///
    /// Defined as future work for now.
    const SIZE: usize;
    const ASSOCIATED_SCALAR_SIZE: usize;

    fn generator() -> Self;

    fn zero() -> Self;

    fn hash_to_group<H: Digest<OutputSize = U64> + Default>(input: &[u8]) -> Self;

    fn to_bytes(&self) -> [u8; Self::SIZE];

    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    fn vartime_multiscalar_multiplication<I, J>(scalars: I, points: J) -> Self
    where
        I: IntoIterator<Item = Self::CorrespondingScalar>,
        J: IntoIterator<Item = Self>;
}

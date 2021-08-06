#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(non_snake_case)]
//
// // The following related to some feature that will at some point stabilise
// // https://github.com/rust-lang/rust/issues/60551#issuecomment-855861197
// #![feature(associated_consts)]
// #![feature(const_generics)]
mod cryptography;

use std::ops::{Add, Mul, Neg, Sub, AddAssign};
use std::fmt::Debug;
use rand_core::{CryptoRng, RngCore};

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

    fn generator() -> Self;

    fn zero() -> Self;
}

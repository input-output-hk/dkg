#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(non_snake_case)]
mod cryptography;


use std::ops::{Add, Mul, Neg, Sub};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar as RScalar;
use std::fmt::Debug;

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
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Mul<Self, Output = Self>
    + core::iter::Sum<Self>
    + for<'a> core::iter::Sum<&'a Self>
{
    const BYTES_LEN: usize;
    type Item;
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
    const BYTES_LEN: usize;
    type Item;
    type CorrespondingScalar: Scalar;

    fn perform(&self) -> Self::Item;
    fn multiply(&self, scalar: &Self::CorrespondingScalar) -> Self::Item;
}

impl Scalar for RScalar {
    const BYTES_LEN: usize = 32;
    type Item = RScalar;
}

impl PrimeGroupElement for RistrettoPoint {
    const BYTES_LEN: usize = 32;
    type Item = RistrettoPoint;
    type CorrespondingScalar = RScalar;
    fn perform(&self) -> RistrettoPoint {
        self + self + self
    }
    fn multiply(&self, scalar: &RScalar) -> RistrettoPoint {
        scalar * self
    }
}

fn trying_it<A: PrimeGroupElement> (value: &A) -> A::Item {
    value.perform()
}

fn trying_mult<A: PrimeGroupElement> (value: &A, scalar: &A::CorrespondingScalar) -> A::Item {
    value.multiply(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    #[test]
    fn it_works() {
        let point = RISTRETTO_BASEPOINT_POINT;
        let scalar = RScalar::from(14u8);
        let exp_mul = scalar * point;
        let test = trying_it::<RistrettoPoint>(&point);
        let test2 = trying_mult::<RistrettoPoint>(&point, &scalar);

        assert_eq!(exp_mul, test2);
        assert_eq!(test, point + point + point);
    }
}

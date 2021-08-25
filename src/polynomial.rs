//! Module implementing polynomial with trait bounds.
#![allow(dead_code)]

use crate::traits::Scalar;
use rand_core::{CryptoRng, RngCore};

/// A polynomial of specific degree d
///
/// of the form: A * x^d + B * x^(d-1) + ... + Z * x^0
#[derive(Clone)]
pub struct Polynomial<S: Scalar> {
    elements: Box<[S]>,
}

impl<S: Scalar> std::fmt::Display for Polynomial<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (d, coef) in self.elements.iter().enumerate().rev() {
            match d {
                0 => write!(f, "{:?}", coef)?,
                1 => write!(f, "{:?} x +", coef)?,
                _ => write!(f, "{:?} x^{} +", coef, d)?,
            }
        }
        Ok(())
    }
}

impl<S: Scalar> Polynomial<S> {
    /// Generate a new 0 polynomial of specific degree
    pub fn new(degree: usize) -> Self {
        Self {
            elements: std::iter::repeat(S::zero()).take(degree+1).collect(),
        }
    }

    pub fn set2(mut self, x0: S, x1: S) -> Self {
        assert!(self.degree() >= 1);
        self.elements[0] = x0;
        self.elements[1] = x1;
        self
    }

    /// Return the degree of the polynomial
    pub fn degree(&self) -> usize {
        assert!(!self.elements.is_empty());
        self.elements.len() - 1
    }

    /// Initialize from a vector, where each element represent the term coefficient
    /// starting from the lowest degree
    pub fn from_vec(elements: Vec<S>) -> Self {
        assert_ne!(elements.len(), 0);
        Polynomial { elements: elements.into_boxed_slice() }
    }

    /// generate a new polynomial of specific degree
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, degree: usize) -> Polynomial<S> {
        Polynomial { elements: std::iter::repeat_with(|| S::random(rng)).take(degree+1).collect() }
    }

    /// get the value of a polynomial a0 + a1 * x^1 + a2 * x^2 + .. + an * x^n for a value x=at
    pub fn evaluate(&self, at: &S) -> S {
        S::sum(self.elements.iter().zip(at.exp_iter()).map(|(&e, x)| e * x))
    }

    /// Evaluate the polynomial at x=0
    pub fn at_zero(&self) -> S {
        self.elements[0]
    }

    pub fn get_coefficient_at(&self, degree: usize) -> &S {
        &self.elements[degree]
    }

    pub fn get_coefficients(&self) -> std::slice::Iter<'_, S> {
        self.elements.iter()
    }
}

impl<S: Scalar> AsRef<[S]> for Polynomial<S> {
    fn as_ref(&self) -> &[S] {
        &self.elements
    }
}

impl<S: Scalar> AsMut<[S]> for Polynomial<S> {
    fn as_mut(&mut self) -> &mut [S] {
        &mut self.elements
    }
}


impl<S: Scalar> std::ops::Add<Polynomial<S>> for Polynomial<S> {
    type Output = Polynomial<S>;

    fn add(self, rhs: Polynomial<S>) -> Self::Output {
        if self.degree() >= rhs.degree() {
            let mut x = self.elements;
            for (e, r) in x.iter_mut().zip(rhs.elements.iter()) {
                *e = *e + r;
            }
            Self { elements: x }
        } else {
            let mut x = rhs.elements;
            for (e, r) in x.iter_mut().zip(self.elements.iter()) {
                *e = *e + r;
            }
            Self { elements: x }
        }
    }
}

impl<S: Scalar> std::ops::Mul<Polynomial<S>> for Polynomial<S> {
    type Output = Polynomial<S>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Polynomial<S>) -> Self::Output {
        //println!("muling {} * {}", self, rhs);
        let mut result = Self::new(self.degree() + rhs.degree() + 1);
        for (left_degree, &left_coeff) in self.elements.iter().enumerate() {
            for (right_degree, &right_coeff) in rhs.elements.iter().enumerate() {
                let degree = left_degree + right_degree;
                result.elements[degree] += left_coeff * right_coeff;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar as RScalar;
    #[test]
    fn poly_tests() {
        let poly_deg_4 = Polynomial::<RScalar>::new(4).set2(RScalar::one(), RScalar::from_u64(3));

        assert_eq!(poly_deg_4.degree(), 4);
        assert_eq!(
            poly_deg_4.evaluate(&RScalar::from_u64(3)),
            RScalar::from_u64(10)
        );
        assert_eq!(poly_deg_4.at_zero(), RScalar::one());

        let poly_deg_2 =
            Polynomial::<RScalar>::new(2).set2(RScalar::from_u64(13), RScalar::from_u64(2));
        let added_polys = poly_deg_4.clone() + poly_deg_2.clone();

        let expected_poly =
            Polynomial::<RScalar>::from_vec(vec![RScalar::from_u64(14), RScalar::from_u64(5)]);

        for (a, b) in added_polys
            .get_coefficients()
            .zip(expected_poly.get_coefficients())
        {
            assert_eq!(a, b);
        }

        let mult_poly = poly_deg_4 * poly_deg_2;

        let expected_mult = Polynomial::<RScalar>::from_vec(vec![
            RScalar::from_u64(13),
            RScalar::from_u64(41),
            RScalar::from_u64(6),
        ]);

        for (a, b) in mult_poly
            .get_coefficients()
            .zip(expected_mult.get_coefficients())
        {
            assert_eq!(a, b);
        }
    }
}

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
            elements: std::iter::repeat(S::zero()).take(degree + 1).collect(),
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
        Polynomial {
            elements: elements.into_boxed_slice(),
        }
    }

    /// generate a new polynomial of specific degree
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, degree: usize) -> Self {
        Polynomial {
            elements: std::iter::repeat_with(|| S::random(rng))
                .take(degree + 1)
                .collect(),
        }
    }

    /// get the value of a polynomial a0 + a1 * x^1 + a2 * x^2 + .. + an * x^n for a value x=at
    pub fn evaluate(&self, at: &S) -> S {
        self.elements
            .iter()
            .zip(at.exp_iter())
            .map(|(&e, x)| e * x)
            .fold(S::zero(), |a, b| a + b)
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

    /// Given indices //(x_1, \ldots, x_n//), and evaluated points //(y_1, \ldots, y_n//), one can
    /// compute a polynomial of degree //(n - 1//) by computing the following:
    /// //(P(x) = \sum_{i=1}^n y_i\prod_{k=1, k\neq i}^n\frac{x - x_k}{x_j - x_k}.//)
    pub fn interpolate(degree: usize, evaluated_points: &[S], indices: &[S]) -> Self {
        assert_eq!(degree + 1, evaluated_points.len());
        assert_eq!(degree + 1, indices.len());
        let mut polynomial = Self::from_vec(vec![S::zero()]);

        for i in 0..degree + 1 {
            let mut tem_polynomial = Self::from_vec(vec![evaluated_points[i]]);
            for j in 0..degree + 1 {
                if i == j {
                    continue;
                }
                tem_polynomial =
                    tem_polynomial * Self::from_vec(vec![(indices[i] - indices[j]).inverse()]);
                tem_polynomial = tem_polynomial * Self::from_vec(vec![-indices[j], S::one()]);
            }
            polynomial = polynomial + tem_polynomial;
        }
        polynomial
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
                *e += *r;
            }
            Self { elements: x }
        } else {
            let mut x = rhs.elements;
            for (e, r) in x.iter_mut().zip(self.elements.iter()) {
                *e += *r;
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
        let mut result = Self::new(self.degree() + rhs.degree());
        for (left_degree, &left_coeff) in self.elements.iter().enumerate() {
            for (right_degree, &right_coeff) in rhs.elements.iter().enumerate() {
                let degree = left_degree + right_degree;
                result.elements[degree] += left_coeff * right_coeff;
            }
        }
        result
    }
}

fn lagrange_coefficient<S: Scalar>(evaluation_point: S, coefficient_index: S, indices: &[S]) -> S {
    let mut result = S::one();
    for &i in indices {
        if i != coefficient_index {
            result = result * (evaluation_point - i) * (coefficient_index - i).inverse();
        }
    }
    result
}

pub fn lagrange_interpolation<S: Scalar>(
    evaluation_point: S,
    evaluated_points: &[S],
    indices: &[S],
) -> S {
    assert_eq!(evaluated_points.len(), indices.len());
    let mut result = S::zero();
    for (&x, &y) in indices.iter().zip(evaluated_points.iter()) {
        let lagrange_coefficient = lagrange_coefficient(evaluation_point, x, indices);
        result += lagrange_coefficient * y;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar as RScalar;
    #[test]
    fn lagrange() {
        let polynomial =
            Polynomial::<RScalar>::new(2).set2(RScalar::from_u64(13), RScalar::from_u64(2));
        let x1 = RScalar::from_u64(5);
        let x2 = RScalar::from_u64(7);
        let x3 = RScalar::from_u64(2);

        let indices = [x1, x2, x3];

        let y1 = polynomial.evaluate(&x1);
        let y2 = polynomial.evaluate(&x2);
        let y3 = polynomial.evaluate(&x3);

        let evaluated_points = [y1, y2, y3];

        let interpolated_zero =
            lagrange_interpolation(RScalar::zero(), &evaluated_points, &indices);
        let expected_zero = polynomial.evaluate(&RScalar::zero());

        assert_eq!(interpolated_zero, expected_zero);
    }

    #[test]
    fn lagrange_coefficients() {
        let polynomial =
            Polynomial::<RScalar>::new(2).set2(RScalar::from_u64(13), RScalar::from_u64(2));
        let x1 = RScalar::from_u64(5);
        let x2 = RScalar::from_u64(7);
        let x3 = RScalar::from_u64(2);

        let indices = [x1, x2, x3];

        let y1 = polynomial.evaluate(&x1);
        let y2 = polynomial.evaluate(&x2);
        let y3 = polynomial.evaluate(&x3);

        let evaluated_points = [y1, y2, y3];

        let interpolated_polynomial =
            Polynomial::<RScalar>::interpolate(2, &evaluated_points, &indices);

        for (a, b) in polynomial
            .get_coefficients()
            .zip(interpolated_polynomial.get_coefficients())
        {
            assert_eq!(a, b);
        }
    }

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

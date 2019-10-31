/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};

/// Represents a degree-3 vector polynomial. `A + B*X + C*X^2 + D*X^3`.
pub struct VecPoly3(
    pub FieldElementVector, // coefficient of constant term
    pub FieldElementVector, // coefficient of x
    pub FieldElementVector, // coefficient of x^2
    pub FieldElementVector, // coefficient of x^3
);

/// Represents a degree-6 scalar polynomial, without the zeroth degree. `b*x + c*x^2 + d*x^3 + e*x^5 + f*x^6`
pub struct Poly6 {
    pub t1: FieldElement, // coefficient of x
    pub t2: FieldElement, // coefficient of x^2
    pub t3: FieldElement, // coefficient of x^3
    pub t4: FieldElement, // coefficient of x^4
    pub t5: FieldElement, // coefficient of x^5
    pub t6: FieldElement, // coefficient of x^6
}

impl VecPoly3 {
    /// Return a zero polynomial (coefficients are vectors of 0)
    pub fn zero(n: usize) -> Self {
        VecPoly3(
            FieldElementVector::new(n),
            FieldElementVector::new(n),
            FieldElementVector::new(n),
            FieldElementVector::new(n),
        )
    }

    /// Compute an inner product of `lhs`, `rhs` which have the property that:
    /// - `lhs.0` is zero;
    /// - `rhs.2` is zero;
    /// This is the case in the constraint system proof.
    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6 {
        // Unwraps are fine as the initialization of vector polynomial ensures vectors are of equal length

        let t1 = lhs.1.inner_product(&rhs.0).unwrap();
        let t2 = lhs.1.inner_product(&rhs.1).unwrap() + lhs.2.inner_product(&rhs.0).unwrap();
        let t3 = lhs.2.inner_product(&rhs.1).unwrap() + &lhs.3.inner_product(&rhs.0).unwrap();
        let t4 = lhs.1.inner_product(&rhs.3).unwrap() + &lhs.3.inner_product(&rhs.1).unwrap();
        let t5 = lhs.2.inner_product(&rhs.3).unwrap();
        let t6 = lhs.3.inner_product(&rhs.3).unwrap();

        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }

    /// Evaluate polynomial at `x`
    pub fn eval(&self, x: &FieldElement) -> FieldElementVector {
        let n = self.0.len();
        let mut out = FieldElementVector::new(n);
        let x_vec = FieldElementVector::new_vandermonde_vector(x, 4);
        for i in 0..n {
            // out[i] = self.0[i] + self.1[i]*x + self.2[i]*x^2 + self.3[i]*x^3
            out[i] = &self.0[i]
                + &self.1[i] * &x_vec[1]
                + &self.2[i] * &x_vec[2]
                + &self.3[i] * &x_vec[3];
        }
        out
    }

    /// Evaluate polynomial at `x`. Found to be slower than `eval`
    #[cfg(test)]
    pub fn eval_alt(&self, x: &FieldElement) -> FieldElementVector {
        let n = self.0.len();
        let mut out = FieldElementVector::new(n);
        for i in 0..n {
            // out[i] = self.0[i] + x*(self.1[i] + x*(self.2[i] + x*self.3[i]))
            out[i] = &self.0[i] + x * (&self.1[i] + x * (&self.2[i] + x * &self.3[i]));
        }
        out
    }
}

impl Poly6 {
    pub fn eval(&self, x: &FieldElement) -> FieldElement {
        // t1*x + t2*x^2 + t3*x^3 + t4*x^4 + t5*x^5 + t6*x^6
        // = x*(t1 + t2*x + t3*x^2 + t4*x^3 + t5*x^4 + t6*x^5)
        // = x*(t1 + x*(t2 + t3*x + t4*x^2 + t5*x^3 + t6*x^4))
        // ... = x*(t1 + x*(t2 + x*(t3 + x*(t4 + x*(t5 + x*t6)))))
        x * (&self.t1
            + x * (&self.t2 + x * (&self.t3 + x * (&self.t4 + x * (&self.t5 + x * &self.t6)))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn timing_vec_poly_evaluation() {
        // Comparing timing of 2 polynomial evaluation methods. `eval` turns out ot be faster than `eval_alt`
        let n = 100;
        let p1_0 = FieldElementVector::random(n);
        let p1_1 = FieldElementVector::random(n);
        let p1_2 = FieldElementVector::random(n);
        let p1_3 = FieldElementVector::random(n);

        let p1 = VecPoly3(p1_0, p1_1, p1_2, p1_3);
        let x = FieldElement::random();

        let start = Instant::now();
        let r1 = p1.eval(&x);
        println!("eval time for {} is {:?}", n, start.elapsed());

        let start = Instant::now();
        let r2 = p1.eval_alt(&x);
        println!("eval_alt time for {} is {:?}", n, start.elapsed());

        assert_eq!(r1, r2);
    }
}

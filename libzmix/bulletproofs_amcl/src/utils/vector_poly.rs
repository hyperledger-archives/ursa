/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};

/// Represents a degree-1 vector polynomial. `A + B*X`.
pub struct VecPoly1(pub FieldElementVector, pub FieldElementVector);

/// Represents a degree-3 vector polynomial. `A + B*X + C*X^2 + D*X^3`.
pub struct VecPoly3(
    pub FieldElementVector,
    pub FieldElementVector,
    pub FieldElementVector,
    pub FieldElementVector,
);

/// Represents a degree-2 scalar polynomial `a + b*x + c*x^2`
pub struct Poly2(pub FieldElement, pub FieldElement, pub FieldElement);

/// Represents a degree-6 scalar polynomial, without the zeroth degree. `b*x + c*x^2 + d*x^3 + e*x^5 + f*x^6`
pub struct Poly6 {
    pub t1: FieldElement,
    pub t2: FieldElement,
    pub t3: FieldElement,
    pub t4: FieldElement,
    pub t5: FieldElement,
    pub t6: FieldElement,
}

impl VecPoly1 {
    pub fn zero(n: usize) -> Self {
        VecPoly1(FieldElementVector::new(n), FieldElementVector::new(n))
    }

    pub fn inner_product(&self, rhs: &VecPoly1) -> Poly2 {
        // Uses Karatsuba's method

        let l = self;
        let r = rhs;

        // Unwraps are fine as the initialization of vector polynomial ensures vectors are of equal length

        let t0 = l.0.inner_product(&r.0).unwrap();
        let t2 = l.1.inner_product(&r.1).unwrap();

        let l0_plus_l1 = l.0.plus(&l.1).unwrap();
        let r0_plus_r1 = r.0.plus(&r.1).unwrap();

        let t1 = l0_plus_l1.inner_product(&r0_plus_r1).unwrap() - (&t0 + &t2);

        Poly2(t0, t1, t2)
    }

    pub fn eval(&self, x: &FieldElement) -> FieldElementVector {
        let n = self.0.len();
        let mut out = FieldElementVector::new(n);
        for i in 0..n {
            out[i] = &self.0[i] + (&self.1[i] * x);
        }
        out
    }
}

impl VecPoly3 {
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

    pub fn eval(&self, x: &FieldElement) -> FieldElementVector {
        let n = self.0.len();
        let mut out = FieldElementVector::new(n);
        for i in 0..n {
            out[i] = &self.0[i] + x * (&self.1[i] + x * (&self.2[i] + x * &self.3[i]));
        }
        out
    }
}

impl Poly2 {
    pub fn eval(&self, x: &FieldElement) -> FieldElement {
        &self.0 + x * (&self.1 + x * &self.2)
    }
}

impl Poly6 {
    pub fn eval(&self, x: &FieldElement) -> FieldElement {
        x * (&self.t1
            + x * (&self.t2 + x * (&self.t3 + x * (&self.t4 + x * (&self.t5 + x * &self.t6)))))
    }
}

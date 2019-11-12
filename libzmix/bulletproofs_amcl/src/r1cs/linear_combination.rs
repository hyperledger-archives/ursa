/*
    SPDX-License-Identifier: Apache-2.0 OR MIT
*/

use amcl_wrapper::field_elem::FieldElement;

use std::collections::HashMap;
use std::iter::FromIterator;
use std::ops::{Add, AddAssign, Mul, Neg, Sub};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Variable {
    /// Represents an external input specified by a commitment.
    Committed(usize),
    /// Represents the left input of a multiplication gate.
    MultiplierLeft(usize),
    /// Represents the right input of a multiplication gate.
    MultiplierRight(usize),
    /// Represents the output of a multiplication gate.
    MultiplierOutput(usize),
    /// Represents the constant 1.
    One(),
}

#[derive(Clone, Debug)]
pub struct AllocatedQuantity {
    pub variable: Variable,
    pub assignment: Option<FieldElement>,
}

/// Represents a linear combination of `Variables`.  Each term is represented by a `(Variable, FieldElement)`
/// pair where FieldElement is the coefficient. The linear combination might have several terms for
/// the same variable with different coefficients, use `simplify` to combine those terms.
#[derive(Clone, Debug)]
pub struct LinearCombination {
    pub terms: Vec<(Variable, FieldElement)>,
}

impl Default for LinearCombination {
    fn default() -> Self {
        LinearCombination { terms: Vec::new() }
    }
}

impl LinearCombination {
    pub fn get_terms(self) -> Vec<(Variable, FieldElement)> {
        self.terms
    }

    /// Simplify linear combination by taking Variables common across terms and adding their corresponding scalars.
    /// Useful when linear combinations become large. Takes ownership of linear combination as this function is useful
    /// when memory is limited and the obvious action after this function call will be to free the memory held by the old linear combination
    pub fn simplify(self) -> Self {
        // Build hashmap to hold unique variables with their values.
        let mut vars: HashMap<Variable, FieldElement> = HashMap::new();

        let terms = self.get_terms();
        for (var, val) in terms {
            *vars.entry(var).or_insert(FieldElement::zero()) += val;
        }

        let mut new_lc_terms = vec![];
        for (var, val) in vars {
            new_lc_terms.push((var, val));
        }
        new_lc_terms.iter().collect()
    }

    pub fn len(&self) -> usize {
        self.terms.len()
    }
}

impl From<Variable> for LinearCombination {
    fn from(v: Variable) -> LinearCombination {
        let one = FieldElement::one();
        LinearCombination {
            terms: vec![(v, one)],
        }
    }
}

impl From<FieldElement> for LinearCombination {
    fn from(s: FieldElement) -> LinearCombination {
        LinearCombination {
            terms: vec![(Variable::One(), s)],
        }
    }
}

impl FromIterator<(Variable, FieldElement)> for LinearCombination {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (Variable, FieldElement)>,
    {
        LinearCombination {
            terms: iter.into_iter().collect(),
        }
    }
}

impl<'a> FromIterator<&'a (Variable, FieldElement)> for LinearCombination {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = &'a (Variable, FieldElement)>,
    {
        LinearCombination {
            terms: iter.into_iter().cloned().collect(),
        }
    }
}

// Arithmetic on linear combinations

impl Mul<LinearCombination> for FieldElement {
    type Output = LinearCombination;

    fn mul(self, other: LinearCombination) -> Self::Output {
        let out_terms = other
            .terms
            .into_iter()
            .map(|(var, scalar)| (var, scalar * &self))
            .collect();
        LinearCombination { terms: out_terms }
    }
}

impl Mul<LinearCombination> for &FieldElement {
    type Output = LinearCombination;

    fn mul(self, other: LinearCombination) -> Self::Output {
        let out_terms = other
            .terms
            .into_iter()
            .map(|(var, scalar)| (var, scalar * self))
            .collect();
        LinearCombination { terms: out_terms }
    }
}

impl Neg for LinearCombination {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s = s.negation();
        }
        self
    }
}

impl<L: Into<LinearCombination>> Add<L> for LinearCombination {
    type Output = Self;

    fn add(mut self, rhs: L) -> Self::Output {
        self.terms.extend(rhs.into().terms.iter().cloned());
        LinearCombination { terms: self.terms }
    }
}

impl<L: Into<LinearCombination>> Sub<L> for LinearCombination {
    type Output = Self;

    fn sub(mut self, rhs: L) -> Self::Output {
        self.terms.extend(
            rhs.into()
                .terms
                .iter()
                .map(|(var, coeff)| (*var, coeff.negation())),
        );
        LinearCombination { terms: self.terms }
    }
}

impl<L: Into<LinearCombination>> AddAssign<L> for LinearCombination {
    fn add_assign(&mut self, rhs: L) {
        self.terms.extend(rhs.into().terms.iter().cloned());
    }
}

// Arithmetic on variables produces linear combinations

impl Add<Variable> for FieldElement {
    type Output = LinearCombination;

    fn add(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(Variable::One(), self), (other, FieldElement::one())],
        }
    }
}

impl<L: Into<LinearCombination>> Sub<L> for Variable {
    type Output = LinearCombination;

    fn sub(self, other: L) -> Self::Output {
        LinearCombination::from(self) - other.into()
    }
}

impl Neg for Variable {
    type Output = LinearCombination;

    fn neg(self) -> Self::Output {
        -LinearCombination::from(self)
    }
}

impl<L: Into<LinearCombination>> Add<L> for Variable {
    type Output = LinearCombination;

    fn add(self, other: L) -> Self::Output {
        LinearCombination::from(self) + other.into()
    }
}

// Arithmetic on FieldElement with variables produces linear combinations

impl Sub<Variable> for FieldElement {
    type Output = LinearCombination;

    fn sub(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(Variable::One(), self), (other, FieldElement::minus_one())],
        }
    }
}

impl Mul<Variable> for FieldElement {
    type Output = LinearCombination;

    fn mul(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(other, self)],
        }
    }
}

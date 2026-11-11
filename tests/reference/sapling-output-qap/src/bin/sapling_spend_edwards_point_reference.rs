use bellman::gadgets::num::AllocatedNum;
use bellman::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use bls12_381::Scalar;
use ff::{Field, PrimeField};
use group::{Curve, Group};
use jubjub::ExtendedPoint;
use serde::Serialize;

const SAPLING_REVISION: &str = "88a7946b4a3066787776e11f0a502654167e022d";
const BELLMAN_REVISION: &str = "b726862a4ece8a627e7fea486d77b502a6edbb0b";
const BELLMAN_CRATE_VERSION: &str = "0.15.0";
const EDWARDS_D: Scalar = Scalar::from_raw([
    0x0106_5fd6_d634_3eb1,
    0x292d_7f6d_3757_9d26,
    0xf5fd_9207_e6bd_7fd4,
    0x2a93_18e7_4bfa_2b48,
]);

#[derive(Serialize)]
struct Export {
    format: &'static str,
    sapling_crypto_revision: &'static str,
    bellman_revision: &'static str,
    bellman_crate_version: &'static str,
    curve_d: String,
    cases: Vec<Case>,
}

#[derive(Serialize)]
struct Case {
    name: &'static str,
    u: String,
    v: String,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct VariableRecord {
    identity: String,
    annotation: String,
    assignment: String,
}

#[derive(Serialize)]
struct Term {
    identity: String,
    coefficient_hex: String,
}

#[derive(Serialize)]
struct Row {
    index: usize,
    annotation: String,
    a: Vec<Term>,
    b: Vec<Term>,
    c: Vec<Term>,
}

#[derive(Default)]
struct TraceConstraintSystem {
    namespaces: Vec<String>,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

impl TraceConstraintSystem {
    fn full_name(&self, name: String) -> String {
        if self.namespaces.is_empty() {
            name
        } else {
            format!("{}/{}", self.namespaces.join("/"), name)
        }
    }

    fn identity(variable: Variable) -> String {
        match variable.get_unchecked() {
            Index::Input(index) => format!("Input({index})"),
            Index::Aux(index) => format!("Aux({index})"),
        }
    }

    fn terms(lc: &LinearCombination<Scalar>) -> Vec<Term> {
        lc.as_ref()
            .iter()
            .map(|(variable, coefficient)| Term {
                identity: Self::identity(*variable),
                coefficient_hex: scalar_hex(*coefficient),
            })
            .collect()
    }

    fn assignment(&self, variable: Variable) -> Option<Scalar> {
        match variable.get_unchecked() {
            Index::Input(0) => Some(Scalar::ONE),
            Index::Input(_) => None,
            Index::Aux(index) => self
                .variables
                .get(index)
                .and_then(|record| decode_scalar(&record.assignment)),
        }
    }

    fn row_value(&self, terms: &[Term]) -> Option<Scalar> {
        let mut result = Scalar::ZERO;
        for term in terms {
            let variable = parse_variable(&term.identity)?;
            let coefficient = decode_scalar(&term.coefficient_hex)?;
            result += coefficient * self.assignment(variable)?;
        }
        Some(result)
    }

    fn is_satisfied(&self) -> bool {
        self.constraints.iter().all(|row| {
            match (
                self.row_value(&row.a),
                self.row_value(&row.b),
                self.row_value(&row.c),
            ) {
                (Some(a), Some(b), Some(c)) => a * b == c,
                _ => false,
            }
        })
    }
}

impl ConstraintSystem<Scalar> for TraceConstraintSystem {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, annotation: A, assignment: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.variables.len();
        let value = assignment()?;
        let label = annotation().into();
        self.variables.push(VariableRecord {
            identity: format!("Aux({index})"),
            annotation: self.full_name(label),
            assignment: scalar_hex(value),
        });
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        annotation: A,
        assignment: F,
    ) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let _ = annotation();
        let _ = assignment()?;
        Err(SynthesisError::Unsatisfiable)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
    {
        let label = self.full_name(annotation().into());
        self.constraints.push(Row {
            index: self.constraints.len(),
            annotation: label,
            a: Self::terms(&a(LinearCombination::zero())),
            b: Self::terms(&b(LinearCombination::zero())),
            c: Self::terms(&c(LinearCombination::zero())),
        });
    }

    fn push_namespace<NR, N>(&mut self, name: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.namespaces.push(name().into());
    }

    fn pop_namespace(&mut self) {
        self.namespaces.pop().expect("namespace stack is balanced");
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

fn source_interpret<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    u: &AllocatedNum<Scalar>,
    v: &AllocatedNum<Scalar>,
) -> Result<(), SynthesisError> {
    let u_squared = u.square(cs.namespace(|| "u^2"))?;
    let v_squared = v.square(cs.namespace(|| "v^2"))?;
    let product = u_squared.mul(cs.namespace(|| "u^2 v^2"), &v_squared)?;

    let one = CS::one();
    cs.enforce(
        || "on curve check",
        |lc| lc - u_squared.get_variable() + v_squared.get_variable(),
        |lc| lc + one,
        |lc| lc + one + (EDWARDS_D, product.get_variable()),
    );

    Ok(())
}

fn source_witness(
    cs: impl ConstraintSystem<Scalar>,
    point: ExtendedPoint,
) -> Result<(Scalar, Scalar), SynthesisError> {
    let affine = point.to_affine();
    let u = affine.get_u();
    let v = affine.get_v();
    source_witness_coordinates(cs, u, v)?;
    Ok((u, v))
}

fn source_witness_coordinates(
    mut cs: impl ConstraintSystem<Scalar>,
    u_value: Scalar,
    v_value: Scalar,
) -> Result<(), SynthesisError> {
    let u = AllocatedNum::alloc(cs.namespace(|| "u"), || Ok(u_value))?;
    let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(v_value))?;
    source_interpret(cs.namespace(|| "point interpretation"), &u, &v)?;
    Ok(())
}

fn build_case(name: &'static str, point: ExtendedPoint) -> Result<Case, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let (u, v) = source_witness(system.namespace(|| "point"), point)?;
    let satisfied = system.is_satisfied();
    Ok(Case {
        name,
        u: scalar_decimal(u),
        v: scalar_decimal(v),
        satisfied,
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn build_off_curve_case() -> Result<Case, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let u_value = Scalar::ONE;
    let v_value = Scalar::ONE;
    source_witness_coordinates(system.namespace(|| "point"), u_value, v_value)?;
    let satisfied = system.is_satisfied();
    Ok(Case {
        name: "off_curve",
        u: scalar_decimal(u_value),
        v: scalar_decimal(v_value),
        satisfied,
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn scalar_decimal(value: Scalar) -> String {
    scalar_to_decimal(value.to_repr().as_ref())
}

fn scalar_to_decimal(bytes: &[u8]) -> String {
    let mut digits = vec![0u8];
    for byte in bytes.iter().rev() {
        let mut carry = u16::from(*byte);
        for digit in &mut digits {
            let value = u16::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits
        .iter()
        .rev()
        .map(|digit| char::from(b'0' + *digit))
        .collect()
}

fn scalar_hex(value: Scalar) -> String {
    value
        .to_repr()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_scalar(value: &str) -> Option<Scalar> {
    let bytes = hex_to_bytes(value)?;
    let repr: [u8; 32] = bytes.try_into().ok()?;
    Option::from(Scalar::from_repr(repr))
}

fn hex_to_bytes(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some(((hi << 4) | lo) as u8)
        })
        .collect()
}

fn parse_variable(identity: &str) -> Option<Variable> {
    if let Some(index) = identity
        .strip_prefix("Input(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return Some(Variable::new_unchecked(Index::Input(index.parse().ok()?)));
    }
    let index = identity
        .strip_prefix("Aux(")
        .and_then(|value| value.strip_suffix(')'))?
        .parse()
        .ok()?;
    Some(Variable::new_unchecked(Index::Aux(index)))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let generator: ExtendedPoint = jubjub::SubgroupPoint::generator().into();
    let cases = vec![
        build_case("identity", ExtendedPoint::identity())?,
        build_case("generator", generator)?,
        build_case("negative_generator", -generator)?,
        build_off_curve_case()?,
    ];
    let output = Export {
        format: "bellman-sapling-edwards-point-reference-v1",
        sapling_crypto_revision: SAPLING_REVISION,
        bellman_revision: BELLMAN_REVISION,
        bellman_crate_version: BELLMAN_CRATE_VERSION,
        curve_d: scalar_hex(EDWARDS_D),
        cases,
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

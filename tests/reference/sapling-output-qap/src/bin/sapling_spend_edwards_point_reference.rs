use bellman::gadgets::Assignment;
use bellman::gadgets::boolean::AllocatedBit;
use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::lookup::{lookup3_xy, lookup3_xy_with_conditional_negation};
use bellman::gadgets::num::{AllocatedNum, Num};
use bellman::{ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use bls12_381::Scalar;
use ff::{Field, PrimeField, PrimeFieldBits};
use group::{Curve, Group};
use jubjub::ExtendedPoint;
use serde::Serialize;
use std::ops::{AddAssign, MulAssign, SubAssign};

const SAPLING_REVISION: &str = "88a7946b4a3066787776e11f0a502654167e022d";
const BELLMAN_REVISION: &str = "b726862a4ece8a627e7fea486d77b502a6edbb0b";
const BELLMAN_CRATE_VERSION: &str = "0.15.0";
const EDWARDS_D: Scalar = Scalar::from_raw([
    0x0106_5fd6_d634_3eb1,
    0x292d_7f6d_3757_9d26,
    0xf5fd_9207_e6bd_7fd4,
    0x2a93_18e7_4bfa_2b48,
]);
const MONTGOMERY_A: Scalar = Scalar::from_raw([0xa002, 0, 0, 0]);
const MONTGOMERY_SCALE: Scalar = Scalar::from_raw([
    0x8f45_35f7_cf82_b8d9,
    0xce40_6970_3da8_8abd,
    0x31de_341e_77d7_64e5,
    0x2762_de61_e862_645e,
]);

#[derive(Serialize)]
struct Export {
    format: &'static str,
    sapling_crypto_revision: &'static str,
    bellman_revision: &'static str,
    bellman_crate_version: &'static str,
    curve_d: String,
    cases: Vec<Case>,
    non_small_order_cases: Vec<NonSmallOrderCase>,
    representations: Vec<RepresentationCase>,
    fixed_base: FixedBaseExport,
    variable_base: VariableBaseExport,
    montgomery_mappings: Vec<MontgomeryMapping>,
    montgomery_cases: Vec<MontgomeryCase>,
    signed_lookup: SignedLookupExport,
    pedersen: PedersenExport,
    note_commitment: NoteCommitmentExport,
    merkle_authentication: MerkleAuthenticationExport,
    conditional_anchor: ConditionalAnchorExport,
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
struct NonSmallOrderCase {
    name: &'static str,
    synthesis_succeeded: bool,
    synthesis_error: Option<String>,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct RepresentationCase {
    name: &'static str,
    bits: Vec<BitRecord>,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct BitRecord {
    identity: String,
    value: bool,
}

#[derive(Serialize)]
struct FixedBaseExport {
    base_u: String,
    base_v: String,
    windows: Vec<Vec<PointRecord>>,
    cases: Vec<FixedBaseCase>,
}

#[derive(Serialize)]
struct PointRecord {
    u: String,
    v: String,
}

#[derive(Serialize)]
struct FixedBaseCase {
    name: String,
    output_u: String,
    output_v: String,
    selectors: Vec<BitRecord>,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct VariableBaseExport {
    cases: Vec<VariableBaseCase>,
}

#[derive(Serialize)]
struct VariableBaseCase {
    name: String,
    base_u: String,
    base_v: String,
    scalar_bits: Vec<BitRecord>,
    output_u: String,
    output_v: String,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct MontgomeryMapping {
    name: &'static str,
    edwards_u: String,
    edwards_v: String,
    x: Option<String>,
    y: Option<String>,
}

#[derive(Serialize)]
struct MontgomeryCase {
    name: &'static str,
    input_x: String,
    input_y: String,
    other_x: Option<String>,
    other_y: Option<String>,
    synthesis_succeeded: bool,
    synthesis_error: Option<String>,
    montgomery_x: Option<String>,
    montgomery_y: Option<String>,
    edwards_u: Option<String>,
    edwards_v: Option<String>,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct SignedLookupExport {
    table: Vec<PointRecord>,
    cases: Vec<SignedLookupCase>,
}

#[derive(Serialize)]
struct SignedLookupCase {
    name: String,
    selector: u8,
    lookup_index: u8,
    negative: bool,
    output_x: String,
    output_y: String,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct PedersenExport {
    tables: Vec<Vec<Vec<PointRecord>>>,
    cases: Vec<PedersenCase>,
}

#[derive(Serialize)]
struct PedersenCase {
    name: String,
    message_bits: Vec<bool>,
    output_u: String,
    output_v: String,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct NoteCommitmentExport {
    randomness_base: PointRecord,
    cases: Vec<NoteCommitmentCase>,
}

#[derive(Serialize)]
struct NoteCommitmentCase {
    name: String,
    value: u64,
    diversifier: [u8; 11],
    g_d_u: String,
    g_d_v: String,
    pk_d_u: String,
    pk_d_v: String,
    rcm_bits: Vec<bool>,
    note_bit_count: usize,
    commitment_u: String,
    commitment_v: String,
    hash_u: String,
    hash_v: String,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct MerkleAuthenticationExport {
    cases: Vec<MerkleAuthenticationCase>,
}

#[derive(Serialize)]
struct MerkleAuthenticationCase {
    name: String,
    leaf: String,
    directions: Vec<bool>,
    siblings: Vec<String>,
    root: String,
    satisfied: bool,
    variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct ConditionalAnchorExport {
    cases: Vec<ConditionalAnchorCase>,
}

#[derive(Serialize)]
struct ConditionalAnchorCase {
    name: String,
    root: String,
    value: String,
    anchor: String,
    anchor_position: usize,
    satisfied: bool,
    inputs: Vec<VariableRecord>,
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

struct SourcePoint {
    u: AllocatedNum<Scalar>,
    v: AllocatedNum<Scalar>,
}

struct SourceMontgomeryPoint {
    x: Num<Scalar>,
    y: Num<Scalar>,
}

#[derive(Default)]
struct TraceConstraintSystem {
    namespaces: Vec<String>,
    inputs: Vec<VariableRecord>,
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
            Index::Input(index) => self
                .inputs
                .get(index - 1)
                .and_then(|record| decode_scalar(&record.assignment)),
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
        let index = self.inputs.len() + 1;
        let value = assignment()?;
        let label = annotation().into();
        self.inputs.push(VariableRecord {
            identity: format!("Input({index})"),
            annotation: self.full_name(label),
            assignment: scalar_hex(value),
        });
        Ok(Variable::new_unchecked(Index::Input(index)))
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
) -> Result<SourcePoint, SynthesisError> {
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

    Ok(SourcePoint {
        u: u.clone(),
        v: v.clone(),
    })
}

fn source_witness(
    cs: impl ConstraintSystem<Scalar>,
    point: ExtendedPoint,
) -> Result<SourcePoint, SynthesisError> {
    let affine = point.to_affine();
    let u = affine.get_u();
    let v = affine.get_v();
    source_witness_coordinates(cs, u, v)
}

fn source_witness_coordinates(
    mut cs: impl ConstraintSystem<Scalar>,
    u_value: Scalar,
    v_value: Scalar,
) -> Result<SourcePoint, SynthesisError> {
    let u = AllocatedNum::alloc(cs.namespace(|| "u"), || Ok(u_value))?;
    let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(v_value))?;
    source_interpret(cs.namespace(|| "point interpretation"), &u, &v)
}

fn source_montgomery_point<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    x_value: Scalar,
    y_value: Scalar,
) -> Result<SourceMontgomeryPoint, SynthesisError> {
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(x_value))?;
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(y_value))?;
    Ok(SourceMontgomeryPoint {
        x: x.into(),
        y: y.into(),
    })
}

fn source_montgomery_add<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &SourceMontgomeryPoint,
    other: &SourceMontgomeryPoint,
) -> Result<SourceMontgomeryPoint, SynthesisError> {
    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
        let numerator = other
            .y
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?
            - point
                .y
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
        let denominator = other
            .x
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?
            - point
                .x
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
        Option::<Scalar>::from(denominator.invert())
            .map(|inverse| numerator * inverse)
            .ok_or(SynthesisError::DivisionByZero)
    })?;
    cs.enforce(
        || "evaluate lambda",
        |lc| lc + &other.x.lc(Scalar::ONE) - &point.x.lc(Scalar::ONE),
        |lc| lc + lambda.get_variable(),
        |lc| lc + &other.y.lc(Scalar::ONE) - &point.y.lc(Scalar::ONE),
    );

    let xprime = AllocatedNum::alloc(cs.namespace(|| "xprime"), || {
        let mut value = lambda
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?
            .square();
        value -= MONTGOMERY_A;
        value -= point
            .x
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        value -= other
            .x
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(value)
    })?;
    let one = CS::one();
    cs.enforce(
        || "evaluate xprime",
        |lc| lc + lambda.get_variable(),
        |lc| lc + lambda.get_variable(),
        |lc| {
            lc + (MONTGOMERY_A, one)
                + &point.x.lc(Scalar::ONE)
                + &other.x.lc(Scalar::ONE)
                + xprime.get_variable()
        },
    );

    let yprime = AllocatedNum::alloc(cs.namespace(|| "yprime"), || {
        let mut value = xprime
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        value -= point
            .x
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        value *= lambda
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        value += point
            .y
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(-value)
    })?;
    cs.enforce(
        || "evaluate yprime",
        |lc| lc + &point.x.lc(Scalar::ONE) - xprime.get_variable(),
        |lc| lc + lambda.get_variable(),
        |lc| lc + yprime.get_variable() + &point.y.lc(Scalar::ONE),
    );
    Ok(SourceMontgomeryPoint {
        x: xprime.into(),
        y: yprime.into(),
    })
}

fn source_pedersen_tables() -> Vec<Vec<Vec<(Scalar, Scalar)>>> {
    sapling_crypto::constants::PEDERSEN_HASH_GENERATORS
        .iter()
        .cloned()
        .map(|mut generator| {
            let mut segment = Vec::with_capacity(63);
            for _ in 0..63 {
                let mut multiple = generator;
                let mut window = Vec::with_capacity(4);
                for _ in 0..4 {
                    window.push(
                        source_edwards_to_montgomery(ExtendedPoint::from(multiple))
                            .expect("pinned Pedersen window points are finite"),
                    );
                    multiple += generator;
                }
                segment.push(window);
                for _ in 0..4 {
                    generator = generator.double();
                }
            }
            segment
        })
        .collect()
}

fn source_pedersen_hash<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    message_bits: &[Boolean],
    personalization_bits: &[bool],
    tables: &[Vec<Vec<(Scalar, Scalar)>>],
) -> Result<SourcePoint, SynthesisError> {
    let mut bits: Vec<Boolean> = personalization_bits
        .iter()
        .copied()
        .map(Boolean::constant)
        .collect();
    assert_eq!(bits.len(), 6);
    bits.extend(message_bits.iter().cloned());
    let boolean_false = Boolean::constant(false);
    let mut bit_offset = 0;
    let mut edwards_result: Option<SourcePoint> = None;
    let mut segment_index = 0;

    while bit_offset < bits.len() {
        let segment_tables = tables
            .get(segment_index)
            .ok_or(SynthesisError::Unsatisfiable)?;
        let mut segment_result: Option<SourceMontgomeryPoint> = None;
        let mut window_index = 0;
        while bit_offset < bits.len() && window_index < segment_tables.len() {
            let a = bits[bit_offset].clone();
            let b = bits
                .get(bit_offset + 1)
                .cloned()
                .unwrap_or_else(|| boolean_false.clone());
            let c = bits
                .get(bit_offset + 2)
                .cloned()
                .unwrap_or_else(|| boolean_false.clone());
            bit_offset += 3;

            let coordinates = &segment_tables[window_index];
            let selected = lookup3_xy_with_conditional_negation(
                cs.namespace(|| format!("segment {segment_index}, window {window_index}")),
                &[a, b, c],
                coordinates,
            )?;
            let selected = SourceMontgomeryPoint {
                x: selected.0,
                y: selected.1,
            };
            segment_result = Some(match segment_result {
                None => selected,
                Some(accumulator) => source_montgomery_add(
                    cs.namespace(|| {
                        format!("addition of segment {segment_index}, window {window_index}")
                    }),
                    &selected,
                    &accumulator,
                )?,
            });
            window_index += 1;
        }

        let montgomery = segment_result.ok_or(SynthesisError::Unsatisfiable)?;
        let converted = source_montgomery_into_edwards(
            cs.namespace(|| format!("conversion of segment {segment_index} into edwards")),
            &montgomery,
        )?;
        edwards_result = Some(match edwards_result {
            None => converted,
            Some(accumulator) => source_add(
                cs.namespace(|| format!("addition of segment {segment_index} to accumulator")),
                &converted,
                &accumulator,
            )?,
        });
        segment_index += 1;
    }

    edwards_result.ok_or(SynthesisError::Unsatisfiable)
}

fn source_note_commitment<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: u64,
    g_d: &SourcePoint,
    pk_d: &SourcePoint,
    rcm: jubjub::Fr,
    pedersen_tables: &[Vec<Vec<(Scalar, Scalar)>>],
    randomness_table: &[Vec<(Scalar, Scalar)>],
) -> Result<(SourcePoint, SourcePoint, usize), SynthesisError> {
    let value_bits = bellman::gadgets::boolean::u64_into_boolean_vec_le(
        cs.namespace(|| "value commitment/value"),
        Some(value),
    )?;
    let mut note_contents = value_bits.clone();
    note_contents.extend(source_repr(cs.namespace(|| "representation of g_d"), g_d)?);
    note_contents.extend(source_repr(
        cs.namespace(|| "representation of pk_d"),
        pk_d,
    )?);
    let note_bit_count = note_contents.len();
    let hash = source_pedersen_hash(
        cs.namespace(|| "note content hash"),
        &note_contents,
        &[true; 6],
        pedersen_tables,
    )?;

    let rcm_bits =
        bellman::gadgets::boolean::field_into_boolean_vec_le(cs.namespace(|| "rcm"), Some(rcm))?;
    let randomness = source_fixed_base_multiplication(
        cs.namespace(|| "computation of commitment randomness"),
        randomness_table,
        &rcm_bits,
    )?;
    let commitment = source_add(
        cs.namespace(|| "randomization of note commitment"),
        &hash,
        &randomness,
    )?;
    Ok((hash, commitment, note_bit_count))
}

fn source_valid_diversifier(seed: u8) -> ([u8; 11], ExtendedPoint) {
    for counter in 0..=u8::MAX {
        let mut diversifier = [seed; 11];
        diversifier[10] = counter;
        if let Some(g_d) = sapling_crypto::keys::Diversifier(diversifier).g_d() {
            return (diversifier, g_d.into());
        }
    }
    panic!("no valid Sapling diversifier found for deterministic fixture seed");
}

fn build_note_commitment_export() -> Result<NoteCommitmentExport, SynthesisError> {
    let randomness_generator = sapling_crypto::constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR;
    let randomness_affine = ExtendedPoint::from(randomness_generator).to_affine();
    let randomness_table = source_fixed_base_tables(randomness_generator);
    let pedersen_tables = source_pedersen_tables();
    let pk_d = sapling_crypto::constants::PROOF_GENERATION_KEY_GENERATOR;
    let cases: Vec<(String, u64, u8, ExtendedPoint, jubjub::Fr)> = vec![
        (
            "zero_value_zero_rcm".to_owned(),
            0,
            0,
            ExtendedPoint::from(pk_d),
            jubjub::Fr::ZERO,
        ),
        (
            "one_value_one_rcm".to_owned(),
            1,
            1,
            ExtendedPoint::from(pk_d.double()),
            jubjub::Fr::ONE,
        ),
        (
            "maximum_value_maximum_rcm".to_owned(),
            u64::MAX,
            2,
            ExtendedPoint::from(-pk_d),
            -jubjub::Fr::ONE,
        ),
        (
            "middle_value_mixed_rcm".to_owned(),
            0x0123_4567_89ab_cdef,
            3,
            ExtendedPoint::from(pk_d),
            jubjub::Fr::from(0x5a5a_a5a5_u64),
        ),
    ];
    let cases = cases
        .into_iter()
        .map(|(name, value, diversifier_seed, pk_d, rcm)| {
            let (diversifier, g_d) = source_valid_diversifier(diversifier_seed);
            let g_d = g_d.to_affine();
            let pk_d = pk_d.to_affine();
            let mut system = TraceConstraintSystem::default();
            let g_d = source_witness_coordinates(
                system.namespace(|| "input g_d"),
                g_d.get_u(),
                g_d.get_v(),
            )?;
            let pk_d = source_witness_coordinates(
                system.namespace(|| "input pk_d"),
                pk_d.get_u(),
                pk_d.get_v(),
            )?;
            let (hash, commitment, note_bit_count) = source_note_commitment(
                &mut system,
                value,
                &g_d,
                &pk_d,
                rcm,
                &pedersen_tables,
                &randomness_table,
            )?;
            let rcm_bits = rcm
                .to_le_bits()
                .iter()
                .by_vals()
                .take(jubjub::Fr::NUM_BITS as usize)
                .collect();
            Ok(NoteCommitmentCase {
                name,
                value,
                diversifier,
                g_d_u: scalar_decimal(g_d.u.get_value().ok_or(SynthesisError::AssignmentMissing)?),
                g_d_v: scalar_decimal(g_d.v.get_value().ok_or(SynthesisError::AssignmentMissing)?),
                pk_d_u: scalar_decimal(
                    pk_d.u
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                pk_d_v: scalar_decimal(
                    pk_d.v
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                rcm_bits,
                note_bit_count,
                commitment_u: scalar_decimal(
                    commitment
                        .u
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                commitment_v: scalar_decimal(
                    commitment
                        .v
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                hash_u: scalar_decimal(
                    hash.u
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                hash_v: scalar_decimal(
                    hash.v
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                satisfied: system.is_satisfied(),
                variables: system.variables,
                constraints: system.constraints,
            })
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    Ok(NoteCommitmentExport {
        randomness_base: PointRecord {
            u: scalar_decimal(randomness_affine.get_u()),
            v: scalar_decimal(randomness_affine.get_v()),
        },
        cases,
    })
}

fn source_merkle_authentication_path<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    leaf: &AllocatedNum<Scalar>,
    directions: &[bool],
    siblings: &[Scalar],
    pedersen_tables: &[Vec<Vec<(Scalar, Scalar)>>],
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    if directions.len() != siblings.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut current = leaf.clone();
    for (level, (direction, sibling_value)) in directions.iter().zip(siblings.iter()).enumerate() {
        let mut level_cs = cs.namespace(|| format!("merkle tree hash {level}"));
        let cur_is_right = Boolean::from(AllocatedBit::alloc(
            level_cs.namespace(|| "position bit"),
            Some(*direction),
        )?);

        let path_element =
            AllocatedNum::alloc(level_cs.namespace(|| "path element"), || Ok(*sibling_value))?;
        let (left, right) = AllocatedNum::conditionally_reverse(
            level_cs.namespace(|| "conditional reversal of preimage"),
            &current,
            &path_element,
            &cur_is_right,
        )?;
        let mut preimage = left.to_bits_le(level_cs.namespace(|| "ul into bits"))?;
        preimage.extend(right.to_bits_le(level_cs.namespace(|| "ur into bits"))?);
        let personalization: Vec<bool> = (0..6).map(|bit| (level >> bit) & 1 == 1).collect();
        current = source_pedersen_hash(
            level_cs.namespace(|| "computation of pedersen hash"),
            &preimage,
            &personalization,
            pedersen_tables,
        )?
        .u;
    }
    Ok(current)
}

fn build_merkle_authentication_export() -> Result<MerkleAuthenticationExport, SynthesisError> {
    let pedersen_tables = source_pedersen_tables();
    let cases: Vec<(String, Vec<bool>)> = vec![
        ("all_left_position_zero".to_owned(), vec![false; 32]),
        ("all_right_position_maximum".to_owned(), vec![true; 32]),
        (
            "alternating_directions".to_owned(),
            (0..32).map(|level| level % 2 == 1).collect(),
        ),
        (
            "mixed_directions".to_owned(),
            (0..32).map(|level| (level * 7 + 3) % 11 < 5).collect(),
        ),
        ("depth_one_right".to_owned(), vec![true]),
        (
            "depth_thirty_one_mixed".to_owned(),
            (0..31).map(|level| (level * 5 + 1) % 9 < 4).collect(),
        ),
    ];
    let cases = cases
        .into_iter()
        .map(|(name, directions)| {
            let leaf_value = Scalar::from(0x0123_4567_89ab_cdef_u64);
            let siblings: Vec<Scalar> = (0..directions.len())
                .map(|level| Scalar::from(1000 + level as u64))
                .collect();
            let mut system = TraceConstraintSystem::default();
            let leaf = AllocatedNum::alloc(system.namespace(|| "leaf"), || Ok(leaf_value))?;
            let root = source_merkle_authentication_path(
                &mut system,
                &leaf,
                &directions,
                &siblings,
                &pedersen_tables,
            )?;
            Ok(MerkleAuthenticationCase {
                name,
                leaf: scalar_decimal(leaf_value),
                directions,
                siblings: siblings
                    .iter()
                    .map(|value| scalar_decimal(*value))
                    .collect(),
                root: scalar_decimal(root.get_value().ok_or(SynthesisError::AssignmentMissing)?),
                satisfied: system.is_satisfied(),
                variables: system.variables,
                constraints: system.constraints,
            })
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    Ok(MerkleAuthenticationExport { cases })
}

fn source_conditional_anchor<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    root: &AllocatedNum<Scalar>,
    value: &AllocatedNum<Scalar>,
    anchor: Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let rt = AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || Ok(anchor))?;
    cs.enforce(
        || "conditionally enforce correct root",
        |lc| lc + root.get_variable() - rt.get_variable(),
        |lc| lc + value.get_variable(),
        |lc| lc,
    );
    rt.inputize(cs.namespace(|| "anchor"))?;
    Ok(rt)
}

fn build_conditional_anchor_export() -> Result<ConditionalAnchorExport, SynthesisError> {
    let modulus_minus_one = -Scalar::ONE;
    let cases: Vec<(&str, Scalar, Scalar, Scalar)> = vec![
        (
            "nonzero_matching_anchor",
            Scalar::from(42),
            Scalar::ONE,
            Scalar::from(42),
        ),
        (
            "nonzero_mismatching_anchor",
            Scalar::from(42),
            Scalar::ONE,
            Scalar::from(43),
        ),
        (
            "zero_mismatching_anchor",
            Scalar::from(42),
            Scalar::ZERO,
            Scalar::from(43),
        ),
        (
            "zero_matching_anchor",
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
        ),
        (
            "maximum_field_boundary",
            modulus_minus_one,
            modulus_minus_one,
            modulus_minus_one,
        ),
        (
            "invalid_merkle_root_boundary",
            modulus_minus_one,
            Scalar::ONE,
            Scalar::ZERO,
        ),
    ];
    let cases = cases
        .into_iter()
        .map(|(name, root_value, note_value, anchor_value)| {
            let mut system = TraceConstraintSystem::default();
            for input_name in ["rk.u", "rk.v", "cv.u", "cv.v"] {
                system.alloc_input(|| input_name, || Ok(Scalar::ONE))?;
            }
            let value = AllocatedNum::alloc(system.namespace(|| "note value"), || Ok(note_value))?;
            let root = AllocatedNum::alloc(system.namespace(|| "merkle root"), || Ok(root_value))?;
            let _rt = source_conditional_anchor(&mut system, &root, &value, anchor_value)?;
            let anchor_position = system.inputs.len();
            Ok(ConditionalAnchorCase {
                name: name.to_owned(),
                root: scalar_decimal(root_value),
                value: scalar_decimal(note_value),
                anchor: scalar_decimal(anchor_value),
                anchor_position,
                satisfied: system.is_satisfied(),
                inputs: system.inputs,
                variables: system.variables,
                constraints: system.constraints,
            })
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    Ok(ConditionalAnchorExport { cases })
}

fn source_montgomery_into_edwards<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &SourceMontgomeryPoint,
) -> Result<SourcePoint, SynthesisError> {
    let u = AllocatedNum::alloc(cs.namespace(|| "u"), || {
        let numerator = point
            .x
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?
            * MONTGOMERY_SCALE;
        let denominator = point
            .y
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        Option::<Scalar>::from(denominator.invert())
            .map(|inverse| numerator * inverse)
            .ok_or(SynthesisError::DivisionByZero)
    })?;
    cs.enforce(
        || "u computation",
        |lc| lc + &point.y.lc(Scalar::ONE),
        |lc| lc + u.get_variable(),
        |lc| lc + &point.x.lc(MONTGOMERY_SCALE),
    );

    let v = AllocatedNum::alloc(cs.namespace(|| "v"), || {
        let x = point
            .x
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        let numerator = x - Scalar::ONE;
        let denominator = x + Scalar::ONE;
        Option::<Scalar>::from(denominator.invert())
            .map(|inverse| numerator * inverse)
            .ok_or(SynthesisError::DivisionByZero)
    })?;
    let one = CS::one();
    cs.enforce(
        || "v computation",
        |lc| lc + &point.x.lc(Scalar::ONE) + one,
        |lc| lc + v.get_variable(),
        |lc| lc + &point.x.lc(Scalar::ONE) - one,
    );
    Ok(SourcePoint { u, v })
}

fn source_edwards_to_montgomery(point: ExtendedPoint) -> Option<(Scalar, Scalar)> {
    let affine = point.to_affine();
    let u = affine.get_u();
    let v = affine.get_v();
    if v == Scalar::ONE {
        None
    } else if u == Scalar::ZERO {
        Some((Scalar::ZERO, Scalar::ZERO))
    } else {
        let x = (Scalar::ONE + v) * Option::<Scalar>::from((Scalar::ONE - v).invert())?;
        let y = x * Option::<Scalar>::from(u.invert())? * MONTGOMERY_SCALE;
        Some((x, y))
    }
}

fn source_signed_lookup_table() -> Vec<(Scalar, Scalar)> {
    let generator = sapling_crypto::constants::PEDERSEN_HASH_GENERATORS[0];
    let mut multiple = generator;
    let mut table = Vec::with_capacity(4);
    for _ in 0..4 {
        table.push(
            source_edwards_to_montgomery(ExtendedPoint::from(multiple))
                .expect("Pedersen table points are finite in Montgomery coordinates"),
        );
        multiple += generator;
    }
    table
}

fn build_signed_lookup_export() -> Result<SignedLookupExport, SynthesisError> {
    let table = source_signed_lookup_table();
    let cases = (0u8..8)
        .map(|selector| {
            let mut system = TraceConstraintSystem::default();
            let bits = allocate_source_bits(
                system.namespace(|| "selector bits"),
                &[selector & 1 != 0, selector & 2 != 0, selector & 4 != 0],
            )?;
            let result = lookup3_xy_with_conditional_negation(
                system.namespace(|| "signed lookup"),
                &bits,
                &table,
            )?;
            Ok(SignedLookupCase {
                name: format!("selector_{selector}"),
                selector,
                lookup_index: selector & 3,
                negative: selector & 4 != 0,
                output_x: scalar_decimal(
                    result
                        .0
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                output_y: scalar_decimal(
                    result
                        .1
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                satisfied: system.is_satisfied(),
                variables: system.variables,
                constraints: system.constraints,
            })
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    Ok(SignedLookupExport {
        table: table
            .iter()
            .map(|(x, y)| PointRecord {
                u: scalar_decimal(*x),
                v: scalar_decimal(*y),
            })
            .collect(),
        cases,
    })
}

fn build_pedersen_export() -> Result<PedersenExport, SynthesisError> {
    let tables = source_pedersen_tables();
    let cases: Vec<(String, Vec<bool>)> = vec![
        ("empty_message".to_owned(), Vec::new()),
        ("zero_window_boundary".to_owned(), vec![false; 183]),
        ("next_segment_boundary".to_owned(), vec![false; 184]),
        (
            "alternating_multi_segment".to_owned(),
            (0..184).map(|index| index % 2 == 0).collect(),
        ),
        ("all_zero_all_generators".to_owned(), vec![false; 1128]),
        ("all_one_all_generators".to_owned(), vec![true; 1128]),
    ];
    let cases = cases
        .into_iter()
        .map(|(name, message_bits)| {
            let mut system = TraceConstraintSystem::default();
            let allocated_bits =
                allocate_source_bits(system.namespace(|| "input bits"), &message_bits)?;
            let output = source_pedersen_hash(
                system.namespace(|| "pedersen hash"),
                &allocated_bits,
                &[true; 6],
                &tables,
            )?;
            Ok(PedersenCase {
                name,
                message_bits,
                output_u: scalar_decimal(
                    output
                        .u
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                output_v: scalar_decimal(
                    output
                        .v
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?,
                ),
                satisfied: system.is_satisfied(),
                variables: system.variables,
                constraints: system.constraints,
            })
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    Ok(PedersenExport {
        tables: tables
            .iter()
            .map(|segment| {
                segment
                    .iter()
                    .map(|window| {
                        window
                            .iter()
                            .map(|(x, y)| PointRecord {
                                u: scalar_decimal(*x),
                                v: scalar_decimal(*y),
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect(),
        cases,
    })
}

fn source_conditionally_select<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &SourcePoint,
    condition: &Boolean,
) -> Result<SourcePoint, SynthesisError> {
    let one = CS::one();
    let u_prime = AllocatedNum::alloc(cs.namespace(|| "u'"), || {
        if *condition.get_value().get()? {
            Ok(*point.u.get_value().get()?)
        } else {
            Ok(Scalar::ZERO)
        }
    })?;
    cs.enforce(
        || "u' computation",
        |lc| lc + point.u.get_variable(),
        |_| condition.lc(one, Scalar::ONE),
        |lc| lc + u_prime.get_variable(),
    );

    let v_prime = AllocatedNum::alloc(cs.namespace(|| "v'"), || {
        if *condition.get_value().get()? {
            Ok(*point.v.get_value().get()?)
        } else {
            Ok(Scalar::ONE)
        }
    })?;
    cs.enforce(
        || "v' computation",
        |lc| lc + point.v.get_variable(),
        |_| condition.lc(one, Scalar::ONE),
        |lc| lc + v_prime.get_variable() - &condition.not().lc(one, Scalar::ONE),
    );
    Ok(SourcePoint {
        u: u_prime,
        v: v_prime,
    })
}

fn source_variable_base_multiplication<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &SourcePoint,
    by: &[Boolean],
) -> Result<SourcePoint, SynthesisError> {
    let mut current_base: Option<SourcePoint> = None;
    let mut result: Option<SourcePoint> = None;
    for (index, bit) in by.iter().enumerate() {
        current_base = Some(match current_base {
            None => SourcePoint {
                u: point.u.clone(),
                v: point.v.clone(),
            },
            Some(previous) => {
                source_double(cs.namespace(|| format!("doubling {index}")), &previous)?
            }
        });
        let selected = source_conditionally_select(
            cs.namespace(|| format!("selection {index}")),
            current_base
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)?,
            bit,
        )?;
        result = Some(match result {
            None => selected,
            Some(accumulator) => source_add(
                cs.namespace(|| format!("addition {index}")),
                &accumulator,
                &selected,
            )?,
        });
    }
    result.ok_or(SynthesisError::AssignmentMissing)
}

fn build_case(name: &'static str, point: ExtendedPoint) -> Result<Case, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let result = source_witness(system.namespace(|| "point"), point)?;
    let satisfied = system.is_satisfied();
    Ok(Case {
        name,
        u: scalar_decimal(
            result
                .u
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        v: scalar_decimal(
            result
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        satisfied,
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn build_off_curve_case() -> Result<Case, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let u_value = Scalar::ONE;
    let v_value = Scalar::ONE;
    let result = source_witness_coordinates(system.namespace(|| "point"), u_value, v_value)?;
    let satisfied = system.is_satisfied();
    Ok(Case {
        name: "off_curve",
        u: scalar_decimal(
            result
                .u
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        v: scalar_decimal(
            result
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        satisfied,
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn source_double<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &SourcePoint,
) -> Result<SourcePoint, SynthesisError> {
    let t = AllocatedNum::alloc(cs.namespace(|| "T"), || {
        let mut value = point
            .u
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        value.add_assign(
            point
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        );
        let mut other = point
            .u
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        other.add_assign(
            point
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        );
        value.mul_assign(&other);
        Ok(value)
    })?;
    cs.enforce(
        || "T computation",
        |lc| lc + point.u.get_variable() + point.v.get_variable(),
        |lc| lc + point.u.get_variable() + point.v.get_variable(),
        |lc| lc + t.get_variable(),
    );

    let a = point.u.mul(cs.namespace(|| "A computation"), &point.v)?;
    let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
        let mut value = a
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?
            .square();
        value.mul_assign(&EDWARDS_D);
        Ok(value)
    })?;
    cs.enforce(
        || "C computation",
        |lc| lc + (EDWARDS_D, a.get_variable()),
        |lc| lc + a.get_variable(),
        |lc| lc + c.get_variable(),
    );

    let u3 = AllocatedNum::alloc(cs.namespace(|| "u3"), || {
        let mut numerator = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        numerator = numerator.double();
        let mut denominator = Scalar::ONE;
        denominator.add_assign(c.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        Option::<Scalar>::from(denominator.invert())
            .map(|inverse| numerator * inverse)
            .ok_or(SynthesisError::DivisionByZero)
    })?;
    let one = CS::one();
    cs.enforce(
        || "u3 computation",
        |lc| lc + one + c.get_variable(),
        |lc| lc + u3.get_variable(),
        |lc| lc + a.get_variable() + a.get_variable(),
    );

    let v3 = AllocatedNum::alloc(cs.namespace(|| "v3"), || {
        let mut numerator = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        numerator = numerator.double().neg();
        numerator.add_assign(t.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        let mut denominator = Scalar::ONE;
        denominator.sub_assign(c.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        Option::<Scalar>::from(denominator.invert())
            .map(|inverse| numerator * inverse)
            .ok_or(SynthesisError::DivisionByZero)
    })?;
    cs.enforce(
        || "v3 computation",
        |lc| lc + one - c.get_variable(),
        |lc| lc + v3.get_variable(),
        |lc| lc + t.get_variable() - a.get_variable() - a.get_variable(),
    );
    Ok(SourcePoint { u: u3, v: v3 })
}

fn source_assert_not_small_order<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &SourcePoint,
) -> Result<(), SynthesisError> {
    let first = source_double(cs.namespace(|| "first doubling"), point)?;
    let second = source_double(cs.namespace(|| "second doubling"), &first)?;
    let third = source_double(cs.namespace(|| "third doubling"), &second)?;
    third.u.assert_nonzero(cs.namespace(|| "check u != 0"))
}

fn source_repr<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    point: &SourcePoint,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bits = Vec::new();
    let u_bits = point.u.to_bits_le_strict(cs.namespace(|| "unpack u"))?;
    let v_bits = point.v.to_bits_le_strict(cs.namespace(|| "unpack v"))?;
    bits.extend(v_bits);
    bits.push(u_bits[0].clone());
    Ok(bits)
}

fn build_representation_case(
    name: &'static str,
    u_value: Scalar,
    v_value: Scalar,
) -> Result<RepresentationCase, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let point = source_witness_coordinates(system.namespace(|| "point"), u_value, v_value)?;
    let bits = source_repr(system.namespace(|| "representation"), &point)?;
    let bits = bits
        .iter()
        .map(|bit| match bit {
            Boolean::Is(bit) => Ok(BitRecord {
                identity: TraceConstraintSystem::identity(bit.get_variable()),
                value: bit.get_value().ok_or(SynthesisError::AssignmentMissing)?,
            }),
            _ => Err(SynthesisError::Unsatisfiable),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RepresentationCase {
        name,
        bits,
        satisfied: system.is_satisfied(),
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn build_non_small_order_case(
    name: &'static str,
    u_value: Scalar,
    v_value: Scalar,
) -> NonSmallOrderCase {
    let mut system = TraceConstraintSystem::default();
    let result = source_witness_coordinates(system.namespace(|| "point"), u_value, v_value);
    let synthesis = match result {
        Ok(point) => source_assert_not_small_order(system.namespace(|| "non-small-order"), &point),
        Err(error) => Err(error),
    };
    let synthesis_error = synthesis.as_ref().err().map(|error| format!("{error:?}"));
    NonSmallOrderCase {
        name,
        synthesis_succeeded: synthesis.is_ok(),
        synthesis_error,
        satisfied: system.is_satisfied(),
        variables: system.variables,
        constraints: system.constraints,
    }
}

fn source_add<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    left: &SourcePoint,
    right: &SourcePoint,
) -> Result<SourcePoint, SynthesisError> {
    let uppercase_u = AllocatedNum::alloc(cs.namespace(|| "U"), || {
        let mut left_sum = left
            .u
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        left_sum.add_assign(
            left.v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        );
        let mut right_sum = right
            .u
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        right_sum.add_assign(
            right
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        );
        left_sum.mul_assign(&right_sum);
        Ok(left_sum)
    })?;
    cs.enforce(
        || "U computation",
        |lc| lc + left.u.get_variable() + left.v.get_variable(),
        |lc| lc + right.u.get_variable() + right.v.get_variable(),
        |lc| lc + uppercase_u.get_variable(),
    );

    let a = right.v.mul(cs.namespace(|| "A computation"), &left.u)?;
    let b = right.u.mul(cs.namespace(|| "B computation"), &left.v)?;
    let c = AllocatedNum::alloc(cs.namespace(|| "C"), || {
        let mut value = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        value.mul_assign(b.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        value.mul_assign(&EDWARDS_D);
        Ok(value)
    })?;
    cs.enforce(
        || "C computation",
        |lc| lc + (EDWARDS_D, a.get_variable()),
        |lc| lc + b.get_variable(),
        |lc| lc + c.get_variable(),
    );

    let u3 = AllocatedNum::alloc(cs.namespace(|| "u3"), || {
        let mut numerator = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        numerator.add_assign(b.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        let mut denominator = Scalar::ONE;
        denominator.add_assign(c.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        Option::<Scalar>::from(denominator.invert())
            .map(|inverse| numerator * inverse)
            .ok_or(SynthesisError::DivisionByZero)
    })?;
    let one = CS::one();
    cs.enforce(
        || "u3 computation",
        |lc| lc + one + c.get_variable(),
        |lc| lc + u3.get_variable(),
        |lc| lc + a.get_variable() + b.get_variable(),
    );

    let v3 = AllocatedNum::alloc(cs.namespace(|| "v3"), || {
        let mut numerator = uppercase_u
            .get_value()
            .ok_or(SynthesisError::AssignmentMissing)?;
        numerator.sub_assign(a.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        numerator.sub_assign(b.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        let mut denominator = Scalar::ONE;
        denominator.sub_assign(c.get_value().ok_or(SynthesisError::AssignmentMissing)?);
        Option::<Scalar>::from(denominator.invert())
            .map(|inverse| numerator * inverse)
            .ok_or(SynthesisError::DivisionByZero)
    })?;
    cs.enforce(
        || "v3 computation",
        |lc| lc + one - c.get_variable(),
        |lc| lc + v3.get_variable(),
        |lc| lc + uppercase_u.get_variable() - a.get_variable() - b.get_variable(),
    );
    Ok(SourcePoint { u: u3, v: v3 })
}

fn source_fixed_base_multiplication<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    base: &[Vec<(Scalar, Scalar)>],
    by: &[Boolean],
) -> Result<SourcePoint, SynthesisError> {
    let mut result: Option<SourcePoint> = None;
    for (i, (chunk, window)) in by.chunks(3).zip(base.iter()).enumerate() {
        let chunk_a = chunk
            .first()
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_b = chunk
            .get(1)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let chunk_c = chunk
            .get(2)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(false));
        let (u, v) = lookup3_xy(
            cs.namespace(|| format!("window table lookup {i}")),
            &[chunk_a, chunk_b, chunk_c],
            window,
        )?;
        let point = SourcePoint { u, v };
        result = Some(match result {
            None => point,
            Some(accumulator) => source_add(
                cs.namespace(|| format!("addition {i}")),
                &accumulator,
                &point,
            )?,
        });
    }
    result.ok_or(SynthesisError::Unsatisfiable)
}

fn source_fixed_base_tables(mut generator: jubjub::SubgroupPoint) -> Vec<Vec<(Scalar, Scalar)>> {
    let mut windows = Vec::new();
    for _ in 0..84 {
        let mut coefficients = vec![(Scalar::ZERO, Scalar::ONE)];
        let mut multiple = generator;
        for _ in 0..7 {
            let affine = ExtendedPoint::from(multiple).to_affine();
            coefficients.push((affine.get_u(), affine.get_v()));
            multiple += generator;
        }
        windows.push(coefficients);
        generator = multiple;
    }
    windows
}

fn allocate_source_bits<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    values: &[bool],
) -> Result<Vec<Boolean>, SynthesisError> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some(*value))
                .map(Boolean::from)
        })
        .collect()
}

fn build_fixed_base_case(
    name: String,
    values: Vec<bool>,
    base: &[Vec<(Scalar, Scalar)>],
) -> Result<FixedBaseCase, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let bits = allocate_source_bits(system.namespace(|| "scalar bits"), &values)?;
    let output = source_fixed_base_multiplication(
        system.namespace(|| "fixed base multiplication"),
        base,
        &bits,
    )?;
    let selectors = bits
        .iter()
        .map(|bit| match bit {
            Boolean::Is(bit) => Ok(BitRecord {
                identity: TraceConstraintSystem::identity(bit.get_variable()),
                value: bit.get_value().ok_or(SynthesisError::AssignmentMissing)?,
            }),
            _ => Err(SynthesisError::Unsatisfiable),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FixedBaseCase {
        name,
        output_u: scalar_decimal(
            output
                .u
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        output_v: scalar_decimal(
            output
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        selectors,
        satisfied: system.is_satisfied(),
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn fixed_base_case_values() -> Vec<(String, Vec<bool>)> {
    let mut cases = (0u8..8)
        .map(|selector| {
            (
                format!("selector_{selector}"),
                (0..3).map(|bit| selector & (1 << bit) != 0).collect(),
            )
        })
        .collect::<Vec<_>>();
    for scalar in [0u64, 1, 7, 8, 9, 63, 64, 65, 511, 512, 513] {
        cases.push((
            format!("scalar_{scalar}"),
            (0..252)
                .map(|bit| bit < 64 && (scalar >> bit) & 1 != 0)
                .collect(),
        ));
    }
    cases.push((
        "u64_max".to_owned(),
        (0..64).map(|bit| u64::MAX >> bit & 1 != 0).collect(),
    ));
    let max_scalar = -jubjub::Fr::ONE;
    cases.push((
        "maximum_scalar".to_owned(),
        max_scalar
            .to_le_bits()
            .iter()
            .by_vals()
            .take(jubjub::Fr::NUM_BITS as usize)
            .collect(),
    ));
    cases.push((
        "all_windows_all_selectors".to_owned(),
        (0..252)
            .map(|bit| {
                let window = bit / 3;
                let selector = (window % 8) as u8;
                selector & (1 << (bit % 3)) != 0
            })
            .collect(),
    ));
    cases
}

fn build_fixed_base_export() -> Result<FixedBaseExport, SynthesisError> {
    let base = sapling_crypto::constants::SPENDING_KEY_GENERATOR;
    let affine = ExtendedPoint::from(base).to_affine();
    let tables = source_fixed_base_tables(base);
    let windows = tables
        .iter()
        .map(|window| {
            window
                .iter()
                .map(|(u, v)| PointRecord {
                    u: scalar_decimal(*u),
                    v: scalar_decimal(*v),
                })
                .collect()
        })
        .collect();
    let cases = fixed_base_case_values()
        .into_iter()
        .map(|(name, bits)| build_fixed_base_case(name, bits, &tables))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FixedBaseExport {
        base_u: scalar_decimal(affine.get_u()),
        base_v: scalar_decimal(affine.get_v()),
        windows,
        cases,
    })
}

fn build_variable_base_case(
    name: String,
    base: ExtendedPoint,
    values: Vec<bool>,
) -> Result<VariableBaseCase, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let base_affine = base.to_affine();
    let point = source_witness(system.namespace(|| "base"), base)?;
    let bits = allocate_source_bits(system.namespace(|| "scalar bits"), &values)?;
    let output = source_variable_base_multiplication(
        system.namespace(|| "variable base multiplication"),
        &point,
        &bits,
    )?;
    let scalar_bits = bits
        .iter()
        .map(|bit| match bit {
            Boolean::Is(bit) => Ok(BitRecord {
                identity: TraceConstraintSystem::identity(bit.get_variable()),
                value: bit.get_value().ok_or(SynthesisError::AssignmentMissing)?,
            }),
            _ => Err(SynthesisError::Unsatisfiable),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VariableBaseCase {
        name,
        base_u: scalar_decimal(base_affine.get_u()),
        base_v: scalar_decimal(base_affine.get_v()),
        scalar_bits,
        output_u: scalar_decimal(
            output
                .u
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        output_v: scalar_decimal(
            output
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        satisfied: system.is_satisfied(),
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn build_variable_base_export() -> Result<VariableBaseExport, SynthesisError> {
    let generator = sapling_crypto::constants::SPENDING_KEY_GENERATOR.into();
    let cases: Vec<(String, ExtendedPoint, Vec<bool>)> = vec![
        ("generator_zero".to_owned(), generator, vec![false]),
        ("generator_one".to_owned(), generator, vec![true]),
        (
            "generator_small".to_owned(),
            generator,
            vec![true, false, true, true],
        ),
        (
            "generator_boundary_31".to_owned(),
            generator,
            (0..5).map(|i| 31 >> i & 1 != 0).collect(),
        ),
        (
            "generator_boundary_32".to_owned(),
            generator,
            (0..6).map(|i| 32 >> i & 1 != 0).collect(),
        ),
        (
            "generator_boundary_63".to_owned(),
            generator,
            (0..6).map(|i| 63 >> i & 1 != 0).collect(),
        ),
        (
            "generator_boundary_64".to_owned(),
            generator,
            (0..7).map(|i| 64 >> i & 1 != 0).collect(),
        ),
        ("generator_maximum_scalar".to_owned(), generator, {
            (-jubjub::Fr::ONE)
                .to_le_bits()
                .iter()
                .by_vals()
                .take(jubjub::Fr::NUM_BITS as usize)
                .collect()
        }),
        (
            "identity_mixed".to_owned(),
            ExtendedPoint::identity(),
            vec![true, false, true, true],
        ),
        (
            "negative_generator_mixed".to_owned(),
            -generator,
            vec![true, true, false, true, false],
        ),
        (
            "generator_all_zero_252".to_owned(),
            generator,
            vec![false; 252],
        ),
        (
            "generator_all_one_252".to_owned(),
            generator,
            vec![true; 252],
        ),
    ];
    let cases = cases
        .into_iter()
        .map(|(name, base, bits)| build_variable_base_case(name, base, bits))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VariableBaseExport { cases })
}

fn build_montgomery_case(
    name: &'static str,
    point_values: (Scalar, Scalar),
    other_values: Option<(Scalar, Scalar)>,
    convert_to_edwards: bool,
) -> Result<MontgomeryCase, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let mut montgomery_x = None;
    let mut montgomery_y = None;
    let mut edwards_u = None;
    let mut edwards_v = None;
    let synthesis = (|| {
        let point = source_montgomery_point(
            system.namespace(|| "montgomery point"),
            point_values.0,
            point_values.1,
        )?;
        let result = if let Some((x, y)) = other_values {
            let other = source_montgomery_point(system.namespace(|| "other point"), x, y)?;
            source_montgomery_add(system.namespace(|| "montgomery addition"), &point, &other)?
        } else {
            point
        };
        montgomery_x = Some(scalar_decimal(
            result
                .x
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ));
        montgomery_y = Some(scalar_decimal(
            result
                .y
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ));
        if convert_to_edwards {
            let output =
                source_montgomery_into_edwards(system.namespace(|| "conversion"), &result)?;
            edwards_u = Some(scalar_decimal(
                output
                    .u
                    .get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?,
            ));
            edwards_v = Some(scalar_decimal(
                output
                    .v
                    .get_value()
                    .ok_or(SynthesisError::AssignmentMissing)?,
            ));
        }
        Ok::<(), SynthesisError>(())
    })();
    Ok(MontgomeryCase {
        name,
        input_x: scalar_decimal(point_values.0),
        input_y: scalar_decimal(point_values.1),
        other_x: other_values.map(|(x, _)| scalar_decimal(x)),
        other_y: other_values.map(|(_, y)| scalar_decimal(y)),
        synthesis_succeeded: synthesis.is_ok(),
        synthesis_error: synthesis.err().map(|error| format!("{error:?}")),
        montgomery_x,
        montgomery_y,
        edwards_u,
        edwards_v,
        satisfied: system.is_satisfied(),
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn build_montgomery_mappings() -> Vec<MontgomeryMapping> {
    let generator: ExtendedPoint = sapling_crypto::constants::SPENDING_KEY_GENERATOR.into();
    let twice_generator = generator + generator;
    let cases = [
        ("identity", ExtendedPoint::identity()),
        ("generator", generator),
        ("negative_generator", -generator),
        ("twice_generator", twice_generator),
        (
            "order_two",
            jubjub::AffinePoint::from_raw_unchecked(Scalar::ZERO, -Scalar::ONE).to_extended(),
        ),
    ];
    cases
        .into_iter()
        .map(|(name, point)| {
            let affine = point.to_affine();
            let coordinates = source_edwards_to_montgomery(point);
            MontgomeryMapping {
                name,
                edwards_u: scalar_decimal(affine.get_u()),
                edwards_v: scalar_decimal(affine.get_v()),
                x: coordinates.map(|(x, _)| scalar_decimal(x)),
                y: coordinates.map(|(_, y)| scalar_decimal(y)),
            }
        })
        .collect()
}

fn build_montgomery_cases() -> Result<Vec<MontgomeryCase>, SynthesisError> {
    let generator: ExtendedPoint = sapling_crypto::constants::SPENDING_KEY_GENERATOR.into();
    let twice_generator = generator + generator;
    let negative_generator = -generator;
    let generator_montgomery = source_edwards_to_montgomery(generator).unwrap();
    let twice_montgomery = source_edwards_to_montgomery(twice_generator).unwrap();
    let negative_montgomery = source_edwards_to_montgomery(negative_generator).unwrap();
    let modulus_minus_one = -Scalar::ONE;
    let modulus_minus_two = modulus_minus_one - Scalar::ONE;
    let cases = vec![
        build_montgomery_case("convert_generator", generator_montgomery, None, true)?,
        build_montgomery_case(
            "convert_negative_generator",
            negative_montgomery,
            None,
            true,
        )?,
        build_montgomery_case("convert_twice_generator", twice_montgomery, None, true)?,
        build_montgomery_case("convert_zero_x", (Scalar::ZERO, Scalar::ONE), None, true)?,
        build_montgomery_case(
            "convert_boundary_coordinates",
            (modulus_minus_two, modulus_minus_one),
            None,
            true,
        )?,
        build_montgomery_case(
            "convert_zero_y",
            (Scalar::from(7), Scalar::ZERO),
            None,
            true,
        )?,
        build_montgomery_case(
            "convert_x_minus_one",
            (modulus_minus_one, Scalar::from(2)),
            None,
            true,
        )?,
        build_montgomery_case(
            "convert_unchecked_off_curve",
            (Scalar::from(3), Scalar::from(7)),
            None,
            true,
        )?,
        build_montgomery_case(
            "add_generator_twice_generator",
            generator_montgomery,
            Some(twice_montgomery),
            true,
        )?,
        build_montgomery_case(
            "add_negative_generator_twice_generator",
            negative_montgomery,
            Some(twice_montgomery),
            true,
        )?,
        build_montgomery_case(
            "add_boundary_coordinates",
            (Scalar::ZERO, Scalar::ZERO),
            Some((Scalar::ONE, modulus_minus_one)),
            false,
        )?,
        build_montgomery_case(
            "add_equal_x_opposites",
            generator_montgomery,
            Some(negative_montgomery),
            true,
        )?,
    ];
    Ok(cases)
}

fn build_add_case(
    name: &'static str,
    left_point: ExtendedPoint,
    right_point: ExtendedPoint,
) -> Result<Case, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let left = source_witness(system.namespace(|| "left"), left_point)?;
    let right = source_witness(system.namespace(|| "right"), right_point)?;
    let result = source_add(system.namespace(|| "addition"), &left, &right)?;
    Ok(Case {
        name,
        u: scalar_decimal(
            result
                .u
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        v: scalar_decimal(
            result
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        satisfied: system.is_satisfied(),
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn build_double_case(name: &'static str, point: ExtendedPoint) -> Result<Case, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let input = source_witness(system.namespace(|| "point"), point)?;
    let result = source_double(system.namespace(|| "doubling"), &input)?;
    Ok(Case {
        name,
        u: scalar_decimal(
            result
                .u
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        v: scalar_decimal(
            result
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        satisfied: system.is_satisfied(),
        variables: system.variables,
        constraints: system.constraints,
    })
}

fn build_off_curve_add_case(generator: ExtendedPoint) -> Result<Case, SynthesisError> {
    let mut system = TraceConstraintSystem::default();
    let invalid =
        source_witness_coordinates(system.namespace(|| "left"), Scalar::ONE, Scalar::ONE)?;
    let right = source_witness(system.namespace(|| "right"), generator)?;
    let result = source_add(system.namespace(|| "addition"), &invalid, &right)?;
    Ok(Case {
        name: "off_curve_addition",
        u: scalar_decimal(
            result
                .u
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        v: scalar_decimal(
            result
                .v
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?,
        ),
        satisfied: system.is_satisfied(),
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
    let twice_generator = generator + generator;
    let cases = vec![
        build_case("identity", ExtendedPoint::identity())?,
        build_case("generator", generator)?,
        build_case("negative_generator", -generator)?,
        build_off_curve_case()?,
        build_add_case(
            "identity_add_generator",
            ExtendedPoint::identity(),
            generator,
        )?,
        build_add_case(
            "generator_add_identity",
            generator,
            ExtendedPoint::identity(),
        )?,
        build_add_case("negative_generator_add_generator", -generator, generator)?,
        build_add_case("generator_add_negative_generator", generator, -generator)?,
        build_add_case("equal_point_addition", generator, generator)?,
        build_add_case("nontrivial_point_addition", generator, twice_generator)?,
        build_double_case("identity_double", ExtendedPoint::identity())?,
        build_double_case("generator_double", generator)?,
        build_double_case("negative_generator_double", -generator)?,
        build_off_curve_add_case(generator)?,
    ];
    let non_small_order_cases = vec![
        build_non_small_order_case(
            "generator",
            generator.to_affine().get_u(),
            generator.to_affine().get_v(),
        ),
        build_non_small_order_case(
            "negative_generator",
            (-generator).to_affine().get_u(),
            (-generator).to_affine().get_v(),
        ),
        build_non_small_order_case(
            "twice_generator",
            twice_generator.to_affine().get_u(),
            twice_generator.to_affine().get_v(),
        ),
        build_non_small_order_case("identity", Scalar::ZERO, Scalar::ONE),
        build_non_small_order_case("order_two", Scalar::ZERO, -Scalar::ONE),
        build_non_small_order_case("off_curve", Scalar::ONE, Scalar::ONE),
    ];
    let representations = vec![
        build_representation_case(
            "generator",
            generator.to_affine().get_u(),
            generator.to_affine().get_v(),
        )?,
        build_representation_case(
            "negative_generator",
            (-generator).to_affine().get_u(),
            (-generator).to_affine().get_v(),
        )?,
        build_representation_case("identity", Scalar::ZERO, Scalar::ONE)?,
        build_representation_case("order_two", Scalar::ZERO, -Scalar::ONE)?,
        build_representation_case(
            "twice_generator",
            twice_generator.to_affine().get_u(),
            twice_generator.to_affine().get_v(),
        )?,
        build_representation_case("off_curve", Scalar::ONE, Scalar::ONE)?,
    ];
    let output = Export {
        format: "bellman-sapling-edwards-point-reference-v11",
        sapling_crypto_revision: SAPLING_REVISION,
        bellman_revision: BELLMAN_REVISION,
        bellman_crate_version: BELLMAN_CRATE_VERSION,
        curve_d: scalar_hex(EDWARDS_D),
        cases,
        non_small_order_cases,
        representations,
        fixed_base: build_fixed_base_export()?,
        variable_base: build_variable_base_export()?,
        montgomery_mappings: build_montgomery_mappings(),
        montgomery_cases: build_montgomery_cases()?,
        signed_lookup: build_signed_lookup_export()?,
        pedersen: build_pedersen_export()?,
        note_commitment: build_note_commitment_export()?,
        merkle_authentication: build_merkle_authentication_export()?,
        conditional_anchor: build_conditional_anchor_export()?,
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

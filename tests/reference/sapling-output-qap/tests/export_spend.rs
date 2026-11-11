use std::fs;

use bellman::gadgets::test::TestConstraintSystem;
use bellman::{Circuit, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use bls12_381::Scalar;
use ff::{Field, PrimeField, PrimeFieldBits};
use group::{Curve, Group, GroupEncoding};
use jubjub;
use rand_core::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use sapling_crypto::circuit::{Spend, ValueCommitmentOpening};
use sapling_crypto::{
    Diversifier, Note, ProofGenerationKey, Rseed, keys::SpendValidatingKey, value::NoteValue,
};
use serde::Serialize;

const SAPLING_REVISION: &str = "88a7946b4a3066787776e11f0a502654167e022d";
const BELLMAN_REVISION: &str = "b726862a4ece8a627e7fea486d77b502a6edbb0b";
const EXPECTED_UPSTREAM_TEST_HASH: &str =
    "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89";

#[derive(Serialize)]
struct Export {
    format: &'static str,
    sapling_crypto_revision: &'static str,
    bellman_revision: &'static str,
    fixture: Fixture,
    upstream_test_asserted_hash: &'static str,
    observed_test_constraint_system_hash: String,
    num_inputs_including_one: usize,
    num_auxiliary_variables: usize,
    num_constraints: usize,
    satisfied: bool,
    inputs: Vec<VariableRecord>,
    auxiliary_variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Serialize)]
struct Fixture {
    name: &'static str,
    seed_hex: &'static str,
    iteration: usize,
}

#[derive(Serialize)]
struct VariableRecord {
    identity: String,
    annotation: String,
    allocation_event_index: usize,
    allocation_api: &'static str,
    allocation_namespace: Vec<String>,
    namespace_hierarchy: Vec<String>,
    gadget_scope: String,
    allocation_label: String,
    source_context: &'static str,
    source_file: Option<String>,
    source_line: Option<usize>,
    semantic_gadget_id: Option<String>,
    parent_gadget_context: Vec<String>,
    gadget_invocation_context: Vec<String>,
    allocation_role: Option<String>,
    semantic_allocation_id: Option<String>,
    assignment_hex: Option<String>,
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

struct TraceConstraintSystem {
    namespaces: Vec<String>,
    inputs: Vec<VariableRecord>,
    auxiliary_variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
    next_allocation_event: usize,
}

impl TraceConstraintSystem {
    fn new() -> Self {
        Self {
            namespaces: Vec::new(),
            inputs: vec![VariableRecord {
                identity: "Input(0)".to_owned(),
                annotation: "ONE".to_owned(),
                allocation_event_index: 0,
                allocation_api: "implicit-one",
                allocation_namespace: Vec::new(),
                namespace_hierarchy: Vec::new(),
                gadget_scope: String::new(),
                allocation_label: "ONE".to_owned(),
                source_context: "Bellman ConstraintSystem callback; caller source location is not exposed",
                source_file: None,
                source_line: None,
                semantic_gadget_id: Some("sapling.spend.constant".to_owned()),
                parent_gadget_context: vec!["sapling.spend".to_owned()],
                gadget_invocation_context: vec!["constant:ONE".to_owned()],
                allocation_role: Some("implicit one constant".to_owned()),
                semantic_allocation_id: Some("sapling.spend.constant|ONE|implicit-one".to_owned()),
                assignment_hex: Some(scalar_hex(Scalar::ONE)),
            }],
            auxiliary_variables: Vec::new(),
            constraints: Vec::new(),
            next_allocation_event: 1,
        }
    }

    fn full_name(&self, name: String) -> String {
        if self.namespaces.is_empty() {
            name
        } else {
            format!("{}/{}", self.namespaces.join("/"), name)
        }
    }

    fn semantic_provenance(
        &self,
    ) -> (
        Option<String>,
        Vec<String>,
        Vec<String>,
        Option<String>,
        Option<String>,
    ) {
        let Some(root) = self.namespaces.first() else {
            return (None, Vec::new(), Vec::new(), None, None);
        };
        let semantic_root_is_classified = root.starts_with("merkle tree hash ")
            || matches!(
                root.as_str(),
                "ak" | "ar"
                    | "nsk"
                    | "rcm"
                    | "computation of ivk"
                    | "nf computation"
                    | "note content hash"
                    | "value commitment"
                    | "compute pk_d"
                    | "computation of nk"
                    | "computation of randomization for the signing key"
                    | "computation of commitment randomness"
                    | "representation of ak"
                    | "representation of nk"
                    | "representation of g_d"
                    | "representation of pk_d"
                    | "representation of rho"
            );
        let remainder = &self.namespaces[1..];
        let (gadget_id, invocation_context, parent_context, nested_invocations) =
            if let Some(level) = root.strip_prefix("merkle tree hash ") {
                (
                    "sapling.spend.merkle-authentication-path".to_owned(),
                    vec![format!("level:{level}")],
                    vec![
                        "sapling.spend".to_owned(),
                        "sapling.spend.merkle-authentication-path".to_owned(),
                    ],
                    Vec::new(),
                )
            } else {
                let direct = match root.as_str() {
                    "ak" => Some(("sapling.spend.authorization-key", "invocation:ak")),
                    "ar" => Some(("sapling.spend.authorization-randomizer", "invocation:ar")),
                    "nsk" => Some(("sapling.spend.nullifier-spending-key", "invocation:nsk")),
                    "rcm" => Some(("sapling.spend.note-commitment-randomness", "invocation:rcm")),
                    "computation of ivk" => Some(("sapling.spend.ivk.blake2s", "hash:ivk")),
                    "nf computation" => Some(("sapling.spend.nullifier.blake2s", "hash:nullifier")),
                    "note content hash" => {
                        Some(("sapling.spend.note-content.pedersen", "hash:note-content"))
                    }
                    "value commitment" => Some((
                        "sapling.spend.value-commitment",
                        "relation:value-commitment",
                    )),
                    "compute pk_d" => {
                        Some(("sapling.spend.pk-d.scalar-multiplication", "mul:pk-d"))
                    }
                    "computation of nk" => {
                        Some(("sapling.spend.nk.fixed-base-multiplication", "mul:nk"))
                    }
                    "computation of randomization for the signing key" => {
                        Some(("sapling.spend.randomized-authorization-key", "mul:ar"))
                    }
                    "computation of commitment randomness" => {
                        Some(("sapling.spend.note-commitment-randomness", "mul:rcm"))
                    }
                    "representation of ak" => Some(("sapling.spend.ak.representation", "repr:ak")),
                    "representation of nk" => Some(("sapling.spend.nk.representation", "repr:nk")),
                    "representation of g_d" => {
                        Some(("sapling.spend.g-d.representation", "repr:g-d"))
                    }
                    "representation of pk_d" => {
                        Some(("sapling.spend.pk-d.representation", "repr:pk-d"))
                    }
                    "representation of rho" => {
                        Some(("sapling.spend.rho.representation", "repr:rho"))
                    }
                    _ => None,
                };
                let (gadget_id, invocation) = direct
                    .map(|(gadget, invocation)| (gadget.to_owned(), invocation.to_owned()))
                    .unwrap_or_else(|| {
                        (
                            format!(
                                "sapling.spend.upstream-scope:{}",
                                Self::normalize_semantic_role(root)
                            ),
                            "namespace-root".to_owned(),
                        )
                    });
                let invocation_context = if invocation == "namespace-root" {
                    vec![format!(
                        "namespace-root:{}",
                        Self::normalize_semantic_role(root)
                    )]
                } else {
                    vec![invocation]
                };
                let mut nested = Vec::new();
                for segment in remainder {
                    for prefix in [
                        "final block",
                        "block ",
                        "round ",
                        "mixing invocation ",
                        "mixing step ",
                        "segment ",
                        "window ",
                        "addition ",
                    ] {
                        if let Some(value) = segment.strip_prefix(prefix) {
                            nested.push(format!("{}:{}", prefix.trim().replace(' ', "-"), value));
                            break;
                        }
                    }
                }
                (
                    gadget_id.clone(),
                    invocation_context,
                    vec!["sapling.spend".to_owned(), gadget_id],
                    nested,
                )
            };
        let mut nested_context = parent_context.clone();
        nested_context.extend(invocation_context.iter().cloned());
        nested_context.extend(nested_invocations);
        if remainder
            .iter()
            .any(|segment| segment == "computation of pedersen hash")
        {
            nested_context.push("sapling.pedersen-hash".to_owned());
        }
        let role = if remainder.is_empty() {
            "namespace-root allocation".to_owned()
        } else {
            remainder.join("/")
        };
        let semantic_id = semantic_root_is_classified.then(|| {
            format!(
                "{}|{}|{}",
                gadget_id,
                invocation_context.join("/"),
                Self::normalize_semantic_role(&role)
            )
        });
        (
            Some(gadget_id),
            parent_context,
            nested_context,
            Some(role),
            semantic_id,
        )
    }

    fn normalize_semantic_role(role: &str) -> String {
        let mut normalized = String::new();
        let mut separator_pending = false;
        for character in role.chars() {
            if character.is_ascii_alphanumeric() {
                if separator_pending && !normalized.is_empty() {
                    normalized.push('/');
                }
                normalized.push(character.to_ascii_lowercase());
                separator_pending = false;
            } else {
                separator_pending = true;
            }
        }
        normalized
    }

    fn variable_record(
        &self,
        identity: String,
        label: String,
        assignment: Scalar,
        allocation_event_index: usize,
        allocation_api: &'static str,
    ) -> VariableRecord {
        let namespace_hierarchy = self.namespaces.clone();
        let (
            semantic_gadget_id,
            parent_gadget_context,
            gadget_invocation_context,
            allocation_role,
            semantic_allocation_id,
        ) = self.semantic_provenance();
        VariableRecord {
            identity,
            annotation: self.full_name(label.clone()),
            allocation_event_index,
            allocation_api,
            allocation_namespace: namespace_hierarchy.clone(),
            gadget_scope: namespace_hierarchy.join("/"),
            namespace_hierarchy,
            allocation_label: label,
            source_context: "Bellman ConstraintSystem callback; caller source location is not exposed",
            source_file: None,
            source_line: None,
            semantic_gadget_id,
            parent_gadget_context,
            gadget_invocation_context,
            allocation_role,
            semantic_allocation_id,
            assignment_hex: Some(scalar_hex(assignment)),
        }
    }

    fn variable_identity(variable: Variable) -> String {
        match variable.get_unchecked() {
            Index::Input(index) => format!("Input({index})"),
            Index::Aux(index) => format!("Aux({index})"),
        }
    }

    fn term_list(lc: &LinearCombination<Scalar>) -> Vec<Term> {
        lc.as_ref()
            .iter()
            .map(|(variable, coefficient)| Term {
                identity: Self::variable_identity(*variable),
                coefficient_hex: scalar_hex(*coefficient),
            })
            .collect()
    }

    fn assignment(&self, variable: Variable) -> Option<Scalar> {
        let record = match variable.get_unchecked() {
            Index::Input(index) => self.inputs.get(index),
            Index::Aux(index) => self.auxiliary_variables.get(index),
        }?;
        record.assignment_hex.as_ref().map(|value| {
            let bytes = hex_to_bytes(value);
            Option::from(Scalar::from_repr(bytes.try_into().unwrap()))
                .expect("exported scalar assignments are canonical")
        })
    }

    fn rows_satisfied(&self) -> bool {
        self.constraints.iter().all(|row| {
            let a = row_value(self, &row.a);
            let b = row_value(self, &row.b);
            let c = row_value(self, &row.c);
            matches!((a, b, c), (Some(a), Some(b), Some(c)) if a * b == c)
        })
    }
}

fn row_value(system: &TraceConstraintSystem, terms: &[Term]) -> Option<Scalar> {
    let mut result = Scalar::ZERO;
    for term in terms {
        let index = parse_identity(&term.identity);
        let variable = Variable::new_unchecked(index);
        let assignment = system.assignment(variable)?;
        let coefficient_bytes = hex_to_bytes(&term.coefficient_hex);
        let coefficient: Scalar =
            Option::from(Scalar::from_repr(coefficient_bytes.try_into().unwrap()))?;
        result += coefficient * assignment;
    }
    Some(result)
}

fn parse_identity(identity: &str) -> Index {
    if let Some(index) = identity
        .strip_prefix("Input(")
        .and_then(|value| value.strip_suffix(')'))
    {
        Index::Input(index.parse().unwrap())
    } else {
        Index::Aux(
            identity
                .strip_prefix("Aux(")
                .and_then(|value| value.strip_suffix(')'))
                .unwrap()
                .parse()
                .unwrap(),
        )
    }
}

fn scalar_hex(value: Scalar) -> String {
    value
        .to_repr()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex_to_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap();
            let lo = (pair[1] as char).to_digit(16).unwrap();
            ((hi << 4) | lo) as u8
        })
        .collect()
}

impl ConstraintSystem<Scalar> for TraceConstraintSystem {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, annotation: A, assignment: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.auxiliary_variables.len();
        let allocation_event_index = self.next_allocation_event;
        self.next_allocation_event += 1;
        let variable = Variable::new_unchecked(Index::Aux(index));
        let label = annotation().into();
        let value = assignment()?;
        self.auxiliary_variables.push(self.variable_record(
            format!("Aux({index})"),
            label,
            value,
            allocation_event_index,
            "alloc",
        ));
        Ok(variable)
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
        let index = self.inputs.len();
        let allocation_event_index = self.next_allocation_event;
        self.next_allocation_event += 1;
        let variable = Variable::new_unchecked(Index::Input(index));
        let label = annotation().into();
        let value = assignment()?;
        self.inputs.push(self.variable_record(
            format!("Input({index})"),
            label,
            value,
            allocation_event_index,
            "alloc_input",
        ));
        Ok(variable)
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
    {
        let name = self.full_name(annotation().into());
        let a = a(LinearCombination::zero());
        let b = b(LinearCombination::zero());
        let c = c(LinearCombination::zero());
        let index = self.constraints.len();
        self.constraints.push(Row {
            index,
            annotation: name,
            a: Self::term_list(&a),
            b: Self::term_list(&b),
            c: Self::term_list(&c),
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

#[test]
fn export_pinned_spend_fixture() {
    let seed = [
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ];
    let mut rng = XorShiftRng::from_seed(seed);
    let tree_depth = 32;
    let value_commitment = ValueCommitmentOpening {
        value: NoteValue::from_raw(rng.next_u64()),
        randomness: jubjub::Fr::random(&mut rng),
    };
    let spend_validating_key = loop {
        let key = jubjub::SubgroupPoint::random(&mut rng).to_bytes();
        if let Some(key) = SpendValidatingKey::temporary_zcash_from_bytes(&key) {
            break key;
        }
    };
    let proof_generation_key =
        ProofGenerationKey::from_parts(spend_validating_key, jubjub::Fr::random(&mut rng)).unwrap();
    let viewing_key = proof_generation_key.to_viewing_key();

    let payment_address = loop {
        let mut bytes = [0; 11];
        rng.fill_bytes(&mut bytes);
        if let Some(address) = viewing_key.to_payment_address(Diversifier(bytes)) {
            break address;
        }
    };
    let commitment_randomness = jubjub::Fr::random(&mut rng);
    let auth_path = vec![Some((Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); tree_depth];
    let ar = jubjub::Fr::random(&mut rng);

    let note = Note::from_parts(
        payment_address,
        value_commitment.value,
        Rseed::BeforeZip212(commitment_randomness),
    );
    let cmu = note.cmu();
    let mut current = Option::<Scalar>::from(Scalar::from_bytes(&cmu.to_bytes())).unwrap();
    for (level, entry) in auth_path.iter().enumerate() {
        let (sibling, direction) = entry.unwrap();
        let (left, right) = if direction {
            (sibling, current)
        } else {
            (current, sibling)
        };
        let left_bits = left.to_le_bits();
        let right_bits = right.to_le_bits();
        let hash = sapling_crypto::pedersen_hash::pedersen_hash(
            sapling_crypto::pedersen_hash::Personalization::MerkleTree(level),
            left_bits
                .iter()
                .by_vals()
                .take(Scalar::NUM_BITS as usize)
                .chain(right_bits.iter().by_vals().take(Scalar::NUM_BITS as usize)),
        );
        current = jubjub::ExtendedPoint::from(hash).to_affine().get_u();
    }

    let spend = Spend {
        value_commitment_opening: Some(value_commitment),
        proof_generation_key: Some(proof_generation_key),
        payment_address: Some(payment_address),
        commitment_randomness: Some(commitment_randomness),
        ar: Some(ar),
        auth_path,
        anchor: Some(current),
    };

    let mut test_system = TestConstraintSystem::<Scalar>::new();
    spend.clone().synthesize(&mut test_system).unwrap();
    assert!(test_system.is_satisfied());
    assert_eq!(test_system.num_constraints(), 98_777);
    assert_eq!(test_system.num_inputs(), 8);
    let test_hash = test_system.hash();
    assert_eq!(test_hash, EXPECTED_UPSTREAM_TEST_HASH);

    let mut trace = TraceConstraintSystem::new();
    spend.synthesize(&mut trace).unwrap();
    assert!(trace.rows_satisfied());
    assert_eq!(trace.constraints.len(), 98_777);
    assert_eq!(trace.inputs.len(), 8);
    assert_eq!(trace.auxiliary_variables.len(), 98_638);
    let mut allocation_event_indices: Vec<_> = trace
        .inputs
        .iter()
        .chain(trace.auxiliary_variables.iter())
        .map(|variable| variable.allocation_event_index)
        .collect();
    allocation_event_indices.sort_unstable();
    assert_eq!(
        allocation_event_indices,
        (0..trace.inputs.len() + trace.auxiliary_variables.len()).collect::<Vec<_>>()
    );
    let export = Export {
        format: "bellman-sapling-spend-reference-v1",
        sapling_crypto_revision: SAPLING_REVISION,
        bellman_revision: BELLMAN_REVISION,
        fixture: Fixture {
            name: "pinned sapling-crypto Spend test fixture iteration 0",
            seed_hex: "5862be3d763d318d17db37325406bce5",
            iteration: 0,
        },
        upstream_test_asserted_hash: EXPECTED_UPSTREAM_TEST_HASH,
        observed_test_constraint_system_hash: test_hash,
        num_inputs_including_one: trace.inputs.len(),
        num_auxiliary_variables: trace.auxiliary_variables.len(),
        num_constraints: trace.constraints.len(),
        satisfied: true,
        inputs: trace.inputs,
        auxiliary_variables: trace.auxiliary_variables,
        constraints: trace.constraints,
    };
    let path = std::env::var("SAPLING_SPEND_EXPORT")
        .expect("set SAPLING_SPEND_EXPORT to an external artifact path");
    fs::write(path, serde_json::to_vec(&export).unwrap()).unwrap();
}

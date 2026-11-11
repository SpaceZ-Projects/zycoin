# Authoritative Sapling Spend reference baseline

## Scope and trust boundary

The source-level reference used by ZyCoin's test-only Bellman tooling is
`zcash/sapling-crypto` revision
`88a7946b4a3066787776e11f0a502654167e022d`. Its Spend implementation is
`sapling-crypto/src/circuit.rs`, `Spend::synthesize`, with the direct circuit
gadgets in `src/circuit/ecc.rs` and `src/circuit/pedersen_hash.rs`.
`tests/reference/sapling-output-qap/Cargo.toml` pins Bellman `=0.15.0`;
`Cargo.lock` records the crates.io checksum
`973b16549796a1274a63e00159a03250e66e8263e2ac6344b1c9fdfe9b7a8325`.
The reference export identifies Bellman revision
`b726862a4ece8a627e7fea486d77b502a6edbb0b`.

The pinned official Spend parameter file has SHA-256
`8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13`.
That hash identifies the exact file bytes, not its circuit. Bellman's
parameter encoding has no circuit identifier. The available transcript lacks
the required Phase-1 artifact and exact ceremony-era setup evidence.
Therefore the above commits are the authoritative **reference implementation
for this audit**, but available evidence does not independently establish that
the official parameter ceremony used this exact source revision.

## Reference synthesis contract

The pinned export synthesizes **98,777 constraints**, **8 inputs including
ONE**, and **98,638 auxiliary variables** (98,646 variables total). ZyCoin's
current ordered matrix is also 98,777 rows by 98,646 columns, but has
fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
Equal dimensions do not establish equal matrices.

The public input order is `rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`,
`nf[0]`, `nf[1]`; ONE is the implicit column zero. The first four public
coordinates are inputized during the early key/value-commitment stages,
`anchor` is inputized after the Merkle path, and the two nullifier chunks
are inputized last. Bellman numbers public inputs separately from auxiliaries,
so those inputize calls do not insert input columns among auxiliary columns.
ZyCoin allocates all seven public inputs at entry, preserving their public
indices but not the reference's temporal allocation events.

`Spend::synthesize` emits constraints in this stage order:

1. Witness and validate `ak`; check it is not small order.
2. Decompose `ar`, multiply by the spending-key generator, add to `ak`, and
   inputize `rk`.
3. Decompose `nsk`; compute `nk`; serialize `ak` and `nk`; compute/truncate
   the IVK BLAKE2s output.
4. Witness/check `g_d`; compute `pk_d = [ivk]g_d`.
5. Expose the value commitment: allocate 64 little-endian value bits, compute
   the value-generator multiplication, allocate/decompose `rcv`, compute its
   fixed-base multiplication, add the points, and inputize `cv`.
6. Serialize `g_d` and `pk_d`; Pedersen-hash the note contents; decompose
   `rcm`, compute its fixed-base multiplication, and randomize the note
   commitment.
7. For each of 32 path levels, allocate a direction bit and sibling, select
   ordered left/right inputs, decompose them, and Pedersen-hash the parent.
8. Allocate the conditional-anchor auxiliary `rt`, enforce
   `(root - rt) * value = 0`, and inputize `rt` as `anchor`.
9. Multiply the nullifier-position generator directly by the 32 direction
   bits; add to the note commitment to obtain `rho`.
10. Serialize `rho`, compute nullifier BLAKE2s, then multipack its 256 bits
    into the final two public inputs.

Each Bellman `ConstraintSystem::enforce` call contributes an ordered
`A * B = C` row. Linear combinations, constants, and factor orientation are
significant to the ordered matrix even when two rows express the same
polynomial relation. Witness values are supplied through allocation closures
and feed later witness construction; they do not choose a different circuit
branch in the listed synthesis sequence.

The reference witness dependencies are: `ak` and `nsk` from the proof
generation key; `ar` and `rcm` as scalar openings; the address-derived
`g_d`/`pk_d`; the value and `rcv` opening; 32 ordered `(sibling, direction)`
authentication-path entries; and the supplied anchor. `rk`, `cv`, and the
note commitment are computed from those openings. The path directions feed
both Merkle left/right selection and the later position-generator
multiplication. `nk` and serialized `rho` feed nullifier BLAKE2s; the hash
bits feed the final public chunks. ZyCoin's `_prepare_witness` additionally
checks the derived keys, commitments, path position, anchor policy, nullifier,
and public inputs before allocating circuit variables.

### Direct gadget boundary

- Sapling-local: `expose_value_commitment` in `circuit.rs`; `EdwardsPoint`
  operations in `circuit/ecc.rs`; and `pedersen_hash` in
  `circuit/pedersen_hash.rs`.
- Bellman library gadgets called by `Spend::synthesize`: `boolean`
  (little-endian bit decomposition and Boolean operations), `num`
  (field variables, serialization and selection), `blake2s`, `multipack`,
  and lookup gadgets used by fixed-base multiplication and Pedersen hashing.
- Constants and generator-window tables come from
  `circuit/constants.rs` and Sapling's circuit constants. The Python port
  consumes corresponding local constants and point arithmetic; these remain
  part of the compatibility boundary.

## Function-by-function porting map

“Equivalent” here means the same intended relation and witness semantics; it
does **not** mean identical allocation order, row order, A/B/C factorization,
or matrix.

| Reference function or stage | ZyCoin counterpart | Port-map status |
|---|---|---|
| `Spend::synthesize`: `ak`, `ar`, `rk` | `_prepare_witness`; `constrain_sapling_spend`; `constrain_sapling_randomized_authorization_key` | **Already equivalent at relation level.** Different public-input allocation timing, event/row order, and low-level factorizations remain. |
| `nsk`, `nk`, `ak.repr`, `nk.repr`, IVK BLAKE2s | `constrain_fixed_base_jubjub_mul`; `constrain_jubjub_repr`; `constrain_sapling_ivk` | **Already equivalent at relation level.** Source-exact bit allocation and primitive row construction require direct parity evidence. |
| `g_d`, non-small-order check, `pk_d = [ivk]g_d` | `constrain_jubjub_point`; `constrain_jubjub_not_small_order`; `constrain_jubjub_scalar_mul` | **Different implementation order.** Local serializes `pk_d` before value commitment; the reference does so after `cv` inputization. Relation semantics are covered. |
| `expose_value_commitment` | `constrain_sapling_value_commitment` and allocations in `constrain_sapling_spend` | **Different implementation order.** Local allocates both bit decompositions before the relation; the reference interleaves value multiplication and `rcv` decomposition/multiplication. Relation semantics are covered. |
| Note contents, Pedersen note hash, `rcm` randomization | `constrain_note_commitment`; `constrain_pedersen_hash`; fixed-base and point-addition helpers | **Requires further investigation.** Exact Bellman lookup, conversion, allocation, and row factorization parity is not established by relation matching. |
| Merkle level direction, sibling selection and Pedersen hash | `make_merkle_path_witness`; `constrain_merkle_authentication_path` | **Different implementation.** Local allocates a packed 32-bit position and reconstructs it; Bellman passes direction bits directly. The path relation is represented. |
| Conditional anchor | `constrain_sapling_conditional_anchor` | **Different implementation.** Bellman allocates `rt`, enforces the root/value row, and binds `rt` to public anchor with another row; ZyCoin directly relates root and public anchor in one row. The projected relation is the same. |
| `g^position`, `rho`, `rho.repr`, nullifier BLAKE2s | `constrain_sapling_nullifier_rho`; `constrain_jubjub_repr`; `constrain_sapling_nullifier_hash` | **Already equivalent at relation level; requires further investigation for exact layout.** The local-only packed-position representation helper remains. |
| Nullifier multipacking | `make_sapling_nullifier_multipacking_witness`; `constrain_sapling_nullifier_multipacking` | **Already equivalent at relation level.** 256 digest bits become a 254-bit chunk and a 2-bit chunk; ordered-row parity remains part of the full-matrix gate. |
| Bellman Boolean/number/lookup/Blake2s primitives | `src/r1cs.py`, `src/blake2s_gadget.py`, and `src/sapling_gadgets.py` helpers | **Requires further investigation.** Functionality exists; identical allocation events and A/B/C rows for every primitive composition are not established. |

No whole Spend relation was found to be missing from the Python implementation.
The unresolved work is source-exact lowering: allocation events, variable
positions, constraint sequence, and A/B/C coefficient representation across
the directly used primitives. This is consistent with the pinned-export
correspondence: 98,637 of 98,638 auxiliary identities and 98,775 of 98,777
rows are paired, but 48,546 pairs move; 251 rows swap A/B, 28,351 use
nontrivial factor normalizations, and 333 match only after expanding
`A*B-C`. The known helper differences are the local packed-position variable
and row, and Bellman's conditional-anchor `rt` and its two rows. These facts
do not establish exact source equivalence or official parameter compatibility.
**Missing functionality:** none identified at the whole-relation level.

## Safe incremental porting sequence

1. **Start with Edwards point witness/interpretation.** Compare
   `ecc::EdwardsPoint::witness` plus `interpret` against
   `allocate_jubjub_point` plus `constrain_jubjub_point` in an isolated
   test-only harness. Check allocations, assignments, every ordered A/B/C
   term, and satisfaction for valid and invalid points. It is a bounded unit
   that avoids hash, scalar-window, and whole-circuit ordering confounders.
2. Add isolated parity cases for point add/double and non-small-order checks;
   then strict representation, fixed-base lookup, and variable-base
   multiplication. Retain the exact source's allocation and enforcement
   order in each unit rather than normalizing factors.
3. Verify note/value Pedersen and Merkle hashing (including boundary window
   lengths), then BLAKE2s and nullifier multipacking, each against Bellman
   traces and complete ordered rows.
4. Recompose `Spend::synthesize` in source order. Resolve `rt` inputization
   and direct position-bit use as their own reviewed changes; do not remove a
   constraint solely to match a fingerprint.
5. Accept full alignment only after comparing the complete ordered A/B/C
   matrices, variable identities and assignments, witness satisfaction, and
   the exact matrix fingerprint. Recheck official queries only after that
   gate. Keep parameter-to-circuit binding and ceremony validity separate.

### First isolated unit: Edwards point witness/interpretation

The prescribed first unit is implemented only under `tests/`. The Python
port follows `EdwardsPoint::witness` and `EdwardsPoint::interpret`, and the
Rust test harness independently exercises the corresponding allocation,
`AllocatedNum::square`/`mul`, and final Bellman `enforce` operations using
Bellman 0.15.0. The source-defined `EDWARDS_D` is exported by the reference
and checked against ZyCoin's field constant.

For each fixture the comparison checks variable annotation/order and scalar
assignment, all four ordered A/B/C rows including labels, indices, and
canonical coefficients, plus satisfaction:

| Fixture | Variables (auxiliary) | Rows | Bellman / Python satisfied |
|---|---:|---:|---|
| Identity | 5 | 4 | yes / yes |
| Jubjub subgroup generator | 5 | 4 | yes / yes |
| Negative generator | 5 | 4 | yes / yes |
| Off-curve raw coordinates through `interpret` | 5 | 4 | no / no |

The three valid point fixtures agree exactly in allocation order and
assignments; all fixtures agree exactly in each ordered A/B/C expression and
row label. The off-curve case intentionally exercises `interpret` with raw
coordinates: as in Bellman, synthesis completes but the curve constraint is
unsatisfied. Missing and malformed Python witnesses are rejected before any
variable or row is added; mutating an assigned coordinate also makes the
constraint system unsatisfied. Bellman's `witness` takes a typed
`ExtendedPoint`, so the off-curve case independently tests its `interpret`
subroutine, not invalid Jubjub-point construction.

Changed files are test-only:

- `tests/sapling_spend_reference_port.py`
- `tests/test_sapling_spend_reference_port.py`
- `tests/reference/sapling-output-qap/src/bin/sapling_spend_edwards_point_reference.rs`

The focused differential suite passed **3 tests**; existing Spend circuit
regressions passed **6 tests**. `cargo fmt --check`, the Rust reference
build, and Ruff on both changed Python test files passed. The full Sapling
regression suite passed **209 tests, 1 skipped** in **2,840.438 seconds**.
Production Spend, Output, parameter files, and proving gates remain unchanged.

### Next isolated units: Edwards point addition and doubling

The next step in the same prescribed sequence is implemented in the isolated
test-only Python port. The test reference uses Bellman 0.15 `AllocatedNum`
operations and ordered `ConstraintSystem::enforce` rows while following
`EdwardsPoint::add` and `EdwardsPoint::double` in the pinned Sapling source.
It preserves the source's intermediate formulas, assignment order, namespace
labels, and A/B/C factorization; it does not call production Spend helpers.

The differential set covers six additions: identity + generator, generator +
identity, negative generator + generator, generator + negative generator,
equal generator addition, and generator + twice-generator. It also covers
doubling identity, generator, and negative generator, plus an off-curve raw
point addition. For each regular addition, both witnessed points allocate 10
auxiliaries and four curve rows apiece; the operation adds six auxiliaries and
six rows, for **16 auxiliaries and 14 ordered constraints** total. Each
doubling adds five operation auxiliaries and five rows to one witnessed point,
for **10 auxiliaries and 9 ordered constraints** total. The invalid addition
has the same counts, and both reference and Python matrices are unsatisfied
on the input-point curve row.

All fixture allocations, annotations, ordered assignments, labels, and every
coefficient in every row match exactly. Output coordinates equal the
independently computed Jubjub group operation results. Mutating a doubling
intermediate produces the same failing row indices against both matrices.
Missing, malformed, foreign, or assignment-inconsistent point inputs reject
before the addition/doubling port adds any variables or constraints.

The focused isolated suite passed **6 tests**, existing Spend circuit tests
passed **6 tests**, and the Rust formatting/reference build and Ruff passed.
The full Sapling regression suite passed **212 tests, 1 skipped** in
**2,928.896 seconds**. It includes the repository's pre-existing synthetic
setup regression, which generated and exercised its test-only synthetic
parameters during suite execution. This was an unintended consequence of
running the complete suite despite this task's synthetic-setup restriction;
the isolated port itself does not use or create parameters, and no synthetic
parameter code or fixture was changed. Production Spend and Output, official
parameters, and proving gates remain unchanged.

### Non-small-order check

The next prescribed unit, `EdwardsPoint::assert_not_small_order` from the
pinned `sapling-crypto/src/circuit/ecc.rs`, is implemented only in the isolated
test port. It performs the source-ordered `"first doubling"`, `"second
doubling"`, and `"third doubling"` calls, then `AllocatedNum::assert_nonzero`
under `"check u != 0"`. Bellman 0.15 `AllocatedNum::assert_nonzero` allocates
`"ephemeral inverse"` and enforces the ordered row
`u * inverse = 1` (`"nonzero assertion constraint"`). The Python port
preserves these labels, intermediate assignments, and row order.

The independent Bellman comparison covers the subgroup generator, its
negative, twice the generator, identity, order-two point `(0, -1)`, and
off-curve `(1, 1)`. Each of the three prime-order point syntheses succeeds
with **21 auxiliary variables and 20 constraints**; the matrices, all ordered
assignments, labels, A/B/C terms, and satisfaction results match.
Identity and the order-two point each perform all three doublings, then both
references reject synthesis with `DivisionByZero` while allocating no inverse:
**20 auxiliary variables and 19 constraints** remain, and those prefix rows
are satisfied. The off-curve point completes synthesis with the same **21 /
20** shape but is unsatisfied in both systems at the original curve-check
row. Altering a second-doubling intermediate and, separately, the final
inverse produces the same failing row indices in the Bellman and Python
matrices.

Missing, malformed, foreign, and assignment-inconsistent point inputs reject
before this port mutates the system. The focused differential suite passed
**8 tests**; existing Spend circuit regressions passed **6 tests**. Rust
formatting and reference build, Ruff, and `git diff --check` passed. No
complete Sapling suite was run for this task, avoiding the pre-existing
synthetic-setup regression. Production Spend and Output, official parameters,
and proving gates remain unchanged.

### Strict Edwards point representation

The next prescribed unit, `EdwardsPoint::repr` in the pinned
`sapling-crypto/src/circuit/ecc.rs`, is implemented in the isolated Python
port. It calls `to_bits_le_strict` for `u` and then `v`, and returns all 255
little-endian bits of `v` followed by `u[0]`. The port reproduces Bellman
0.15's strict canonical-field comparator: bit allocations in source order,
Boolean rows, prefix-AND auxiliaries, and the final zero-times-zero
reconstruction row. It does not call production Sapling helpers.

Each Bellman/Python differential fixture contains **779 auxiliary variables
and 780 ordered constraints**, including the point witness and interpretation
(5 variables, 4 constraints). The representation itself adds **774
auxiliaries and 776 constraints**: 510 Boolean rows, 264 prefix-AND rows, and
two reconstruction rows. For the generator, negative generator, identity,
order-two point `(0, -1)`, twice-generator, and off-curve `(1, 1)`, variable
annotations/order, every assignment, all A/B/C coefficients, row labels,
representation-bit identities and values, and satisfaction results match
Bellman exactly. The off-curve fixture completes representation synthesis but
is unsatisfied at the original point-interpretation curve row.

Changing an output bit or source coordinate, and forcing the returned `v`
bits to encode the noncanonical integer equal to the field modulus, produce
the same failing row indices as the independent Bellman matrices. Missing,
malformed, foreign, and assignment-inconsistent point inputs reject before
the Python representation port mutates the system. `Point` normalizes
out-of-range integer aliases at construction; a distinct noncanonical field
element is not representable. The strict bit constraints reject an attempted
out-of-range bit encoding.

The focused reference-port suite passed **10 tests**; existing Spend circuit
regressions passed **6 tests**, and Sapling gadget regressions passed **52
tests**. Ruff, Python syntax checks, Rust formatting/build, and
`git diff --check` passed. The full Sapling suite was not run because it
includes the existing synthetic-setup regression, which conflicts with this
task's prohibition on running synthetic setup. Production Spend and Output,
official parameters, and proving gates remain unchanged.

### Fixed-base lookup and multiplication

The pinned path is `circuit::ecc::fixed_base_multiplication` in
`sapling-crypto/src/circuit/ecc.rs`, using `constants::generate_circuit_generator`
and Bellman 0.15 `gadgets::lookup::lookup3_xy`. A fixed generator has **84
windows**, each with eight ordered affine points `[0, 1, ..., 7] * gen`;
the next window base is `8 * gen`. The 252 scalar bits are little-endian and
grouped into consecutive 3-bit selectors, where bit positions contribute
weights 1, 2, and 4. Incomplete final chunks are padded with constant false.
Each lookup allocates `x` and `y`, computes `bits[1] AND bits[2]`, and emits
the ordered x/y lookup rows. The first selected point is the accumulator;
each later window is added with `EdwardsPoint::add`.

The test-only Bellman harness starts from the pinned public
`SPENDING_KEY_GENERATOR` constant and reproduces the pinned circuit table
generation sequence, exporting all **672 table points** for comparison. It
then uses Bellman's actual `lookup3_xy` and constraint system for the lookup
trace. The isolated Python port generates the corresponding tables and
reconstructs the lookup coefficient transform and ordered constraints; it
does not call production fixed-base helpers.

The full table matched coordinate-for-coordinate across all 84 windows and
eight entries. All eight selectors matched exactly in their assignments,
variables, ordered rows, and output point (**6 auxiliary variables / 6 rows**
including the three input bit Boolean constraints). Scalar fixtures covered
0, 1, 7/8/9, 63/64/65, 511/512/513, a 64-bit all-ones value, the maximum
Jubjub scalar, and a 252-bit sequence cycling all eight selectors through
all 84 windows. For every 252-bit trace, Python and Bellman matched all
**1,002 auxiliary variables and 1,002 ordered constraints**, every assignment,
label, and A/B/C coefficient, and output point. The 64-bit trace matched
**255 auxiliaries / 255 rows**. Scalar multiplication outputs also matched
independent local Jubjub group multiplication.

Changing a selector to a non-Boolean assignment and altering a selected
lookup coordinate produced the same failing row indices as the Bellman
trace. Missing, malformed, foreign, unassigned, and out-of-range witnesses
are rejected before the fixed-base helper mutates the system. The focused
isolated Spend primitive suite passed **13 tests**. Existing Spend circuit
regressions passed **6 tests**, Sapling gadget regressions passed **52 tests**,
and Rust formatting/build, Ruff, Python syntax checks, and
`git diff --check` passed. The full Sapling suite was not run because it
contains the existing synthetic-setup regression prohibited by this task.
Production Spend and Output, official parameters, and proving gates remain
unchanged.

### Variable-base Edwards scalar multiplication

The pinned implementation is `EdwardsPoint::mul` and
`EdwardsPoint::conditionally_select` in
`sapling-crypto/src/circuit/ecc.rs`. The API consumes a little-endian slice of
Boolean bits. For each bit, it reuses the input point at index zero or doubles
the preceding magnitude, conditionally selects that magnitude or the Edwards
identity, then either initializes the result or adds the selected point to the
running result. An empty slice reaches the source `result.get()?` and returns
`AssignmentMissing`; the isolated Python entry point rejects it before any
mutation.

Selection allocates `u'` then `v'`, with the source-ordered rows
`self.u * condition = u'` and
`self.v * condition = v' - (1 - condition)`. Subsequent iterations preserve
the source `double`, selection, and `add` order and labels. The isolated
implementation composes only the previously verified point witness,
doubling, and addition primitives; it does not call production multiplication
helpers or change production Spend/Output.

The Bellman 0.15 harness calls the pinned Sapling source multiplication
algorithm and exports all allocations, assignments, labels, ordered A/B/C
rows, and result coordinates. Differential cases cover scalar 0, 1, 13,
31/32, 63/64, the maximum Jubjub scalar, a 252-bit all-zero vector, and a
252-bit all-one vector. The last two exercise both conditional-selection
branches at every bit position. Identity and negative-generator bases are
also covered with mixed bit patterns.

Every full trace matched exactly: the 252-bit cases each contain **3,522
auxiliary variables and 3,521 ordered constraints** (including base
interpretation and bit Boolean constraints); the 4-bit case contains **50
auxiliary variables and 49 constraints**. Output coordinates matched the
independent Jubjub group operation for all fixtures. The 11,066 ordered-row
subtests compared labels and complete A/B/C terms; variable annotations,
indices, and assignments were compared for each fixture. Mutating a scalar
Boolean to 2 and altering a selected-point intermediate produced exactly the
same failed row indices as Bellman.

Empty, malformed, foreign, unassigned, and non-Boolean scalar inputs, as well
as foreign or inconsistent point witnesses, reject before the Python
multiplication helper allocates variables or rows. The focused variable-base
differential tests passed **3 tests** with **11,066 subtests**. The complete
isolated Spend primitive suite passed **16 tests** with **30,252 subtests**;
existing Spend circuit regressions passed **6 tests** with **76 subtests**;
Sapling gadget regressions passed **52 tests** with **273 subtests**. Ruff,
Python syntax checks, Rust formatting/build checks, and `git diff --check`
passed. The full Sapling suite was not run because it includes the
synthetic-setup regression prohibited by this task. Full Spend matrix
alignment, official parameter compatibility, parameter-to-circuit binding,
and ceremony validity remain unverified.

### Montgomery operations on the Pedersen dependency path

The pinned call path is `pedersen_hash::pedersen_hash` in
`sapling-crypto/src/circuit/pedersen_hash.rs`: each signed 3-bit lookup is
wrapped by `MontgomeryPoint::interpret_unchecked`; windows within one segment
are accumulated with `MontgomeryPoint::add`; the segment result is converted
with `MontgomeryPoint::into_edwards`; and segment results are then combined
with the already ported Edwards addition. The table-coordinate mapping is
`circuit::constants::to_montgomery_coords`. The relevant constants are
`MONTGOMERY_A = 40962` and the pinned `MONTGOMERY_SCALE` in
`circuit/constants.rs`.

The isolated Python port adds only the host-side Edwards-to-Montgomery
coordinate mapping, unchecked Montgomery coordinate representation, affine
Montgomery addition, and Montgomery-to-Edwards conversion. It preserves field
coordinates, the pinned scale, the source allocation order and row
factorization. `interpret_unchecked` deliberately performs no curve check;
the host-side table mapper accepts only on-curve Edwards `Point` witnesses,
as its upstream `ExtendedPoint` input type guarantees. The finite Montgomery
representation cannot encode the Edwards identity: the pinned mapper returns
`None`; the order-two point maps to `(0, 0)`, for which `into_edwards` fails
on its zero `y` denominator.

The Bellman test harness traces source-mirrored Bellman `AllocatedNum`/`Num`
equations for `MontgomeryPoint::add` and `into_edwards` and compares every
allocation, assignment, row label, and ordered A/B/C expression. The
`ecc` module is private in the pinned crate, so the harness reproduces those
methods from the pinned source rather than invoking the private methods
directly. The source mapping is independently mirrored for identity,
generator, negative generator, twice-generator, and order-two fixtures.

All **12 operation fixtures** matched. Successful conversions of the
generator, negative generator, twice-generator, zero-x boundary, field-edge
coordinates, and an unchecked off-curve Montgomery pair matched at **4
auxiliary variables / 2 constraints** each. The two addition-plus-conversion
fixtures matched at **9 / 5**; boundary-coordinate addition matched at
**7 / 3**. The exceptional `y = 0` conversion rejected with the same
`DivisionByZero` stage and retained **2 / 0**; `x = -1` rejected after the
`u` row and retained **3 / 1**; adding equal-x opposite points rejected
before its slope allocation and retained **4 / 0**. All retained rows were
satisfied in both systems. Generator-plus-twice-generator and
negative-generator-plus-twice-generator conversions matched the corresponding
Edwards group results. Altered addition and conversion intermediates produced
the same failing row indices as Bellman.

Missing, malformed, foreign, unassigned, inconsistent, and out-of-range
coordinate inputs are rejected before the affected operation mutates the
system. The focused Montgomery differential checks passed **3 tests** with
**48 subtests**. The complete isolated primitive suite passed **19 tests**
with **30,300 subtests**; Spend circuit regressions passed **6 tests / 76
subtests**, and Sapling gadget regressions passed **52 tests / 273 subtests**.
Ruff, Python syntax checks, Rust formatting/build, and `git diff --check`
passed. No complete Sapling suite was run.

This result verifies these Montgomery primitives only. It does not establish
Pedersen lookup parity, complete Pedersen hash parity, full Spend matrix
alignment, or official Spend parameter compatibility. Signed lookup
integration and the complete Pedersen/note-commitment relation remain
unverified.

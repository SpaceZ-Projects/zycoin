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
production ordered matrix is also 98,777 rows by 98,646 columns, but has
fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
The isolated test-only source-faithful Spend composition now matches the
pinned trace at **98,777 rows by 98,646 columns**, with matrix fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
This parity result applies only to the reference port; equal dimensions do
not establish that the production matrix is identical.

The public input order is `rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`,
`nf[0]`, `nf[1]`; ONE is the implicit column zero. The first four public
coordinates are inputized during the early key/value-commitment stages,
`anchor` is inputized after the Merkle path, and the two nullifier chunks
are inputized last. Bellman numbers public inputs separately from auxiliaries,
so those inputize calls do not insert input columns among auxiliary columns.
The production assembler allocates all seven public inputs at entry. The
isolated reference adapter preserves the pinned temporal events: `rk` after
1,029 auxiliaries, `cv` after 29,075, `anchor` after 76,806, and the two
nullifier inputs after all 98,638 auxiliaries.

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

The stage-specific sections below retain their contemporaneous evidence
limits. Phase 9.21.40 established complete test-only Spend composition and
matrix comparison for one witness; Phase 9.21.41 expands assignment and
satisfaction coverage to three independently constructed valid witnesses
while reusing the witness-independent Bellman matrix.

| Reference function or stage | ZyCoin counterpart | Port-map status |
|---|---|---|
| `Spend::synthesize`: `ak`, `ar`, `rk` | Test-only `constrain_source_faithful_spend` and isolated Edwards/fixed-base helpers | **Full trace verified** for allocation order, assignments, labels, public positions, and ordered A/B/C rows. |
| `nsk`, `nk`, `ak.repr`, `nk.repr`, IVK BLAKE2s | Test-only composition using isolated fixed-base, representation, and IVK helpers | **Full trace verified**, including the capacity-truncated IVK handoff. |
| `g_d`, non-small-order check, `pk_d = [ivk]g_d` | Test-only point, variable-base multiplication, and representation helpers | **Full trace verified** for the IVK bit handoff and source order. |
| `expose_value_commitment` | Test-only `constrain_spend_value_commitment` plus fixed-base and Edwards primitives | **Full trace verified**; standalone and composed ordered traces agree with Bellman. |
| Note contents, Pedersen note hash, `rcm` randomization | Isolated `constrain_spend_note_commitment` plus Edwards/Pedersen helpers | **Full trace verified**, reusing the upstream value and representation bits. |
| Merkle level direction, sibling selection and Pedersen hash | Test-only `constrain_spend_merkle_authentication_path` | **Full 32-level trace verified**, including direct direction-bit reuse. |
| Conditional anchor | Test-only source-order conditional-anchor helper | **Full trace verified**, including the late anchor input and both ordered rows. |
| `g^position`, `rho`, `rho.repr` | Test-only fixed-base, addition, and representation helpers | **Full trace verified** using the original 32 direction bits. |
| Nullifier `nf = BLAKE2s(nk || rho)` | Test-only `constrain_spend_nullifier_blake2s` | **Full trace verified** for allocations, assignments, labels, and ordered A/B/C rows. |
| Nullifier multipacking | Test-only `constrain_spend_nullifier_multipacking` | **Full trace verified** for the 254+2 split and final public-input positions. |
| Complete synthesis and complete matrix comparison | Test-only `constrain_source_faithful_spend` and pinned Bellman exporter | **Verified** against the retained Bellman matrix for three satisfying witnesses: exact dimensions, per-witness assignments and labels, public positions, and every ordered A/B/C row match. |

The production `constrain_sapling_spend` assembler remains a separate
implementation and was not modified. Phase 9.21.42 records its independently
synthesized matrix fingerprint and three-witness mapped-assignment audit. The
isolated source-faithful composition passed complete ordered-matrix comparison
against the retained Bellman matrix for three valid witnesses. Production
matrix identity and official parameter compatibility remain **Unverified**.

### Phase 9.21.40 — Full source-order recomposition

The test-only path follows `Spend::synthesize` and `expose_value_commitment`
in `sapling-crypto/src/circuit.rs`. One retained Bellman 0.15 trace and one
passing Python full synthesis were compared across all 98,646 variables and
98,777 ordered rows. All allocation annotations and assignments, public
input positions, row labels, and canonical ordered A/B/C expressions matched.
The Bellman TestConstraintSystem hash was
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`;
the canonical matrix fingerprint for both traces is
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
The witness satisfies both systems. Changing `Input(5)` (`anchor`) by one
fails exactly row 76,894, `anchor/enforce input is correct`, in both.

The full comparison also confirmed the source-order public-input insertion
boundaries: `rk` follows 1,029 auxiliaries, `cv` follows 29,075, `anchor`
follows 76,806, and the nullifier chunks follow all 98,638 auxiliaries.

During this comparison, the value-commitment regression exposed a
witness-dependent shortcut in the test-only fixed-base lookup's Boolean AND:
false assigned variable bits omitted Bellman's `and result` allocation and
constraint. The shortcut was removed, and the helper now preserves Bellman's
constant and negated-Boolean cases. The focused ordered value-commitment
regression then passed **1 test / 1,265 subtests**. No production circuit was
changed.

The full-export test performed one Bellman synthesis and its pinned
TestConstraintSystem hash assertion passed. The passing differential reused
the same deterministic fixture trace. The final passing differential
performed one Python full synthesis. Two earlier Python comparison attempts
also invoked full synthesis before the harness failed: one exposed quadratic
temporal-index lookups, and one used a persisted trace without allocation-event
fields. Those harness issues were fixed; the passing run uses constant-time
temporal-index maps and validates the same source-order boundaries. Thus the
work performed **one full Bellman synthesis and three Python full-synthesis
attempts**, of which one completed the exact comparison successfully.

Focused validation results: full Spend differential **1 passed** (60.09 s);
composition boundary tests **7 passed** (0.77 s); value-commitment trace
**1 passed / 1,265 subtests** (2.08 s); fixed-base regressions **2 passed /
13,427 subtests** (66.01 s); Sapling gadget regressions **52 passed / 273
subtests** (63.49 s); compatibility-manifest regressions **19 passed / 5
subtests** (0.31 s). Ruff, Python syntax checks, Rust formatting and exporter
compilation, and `git diff --check` passed.

**Task status: complete for the isolated test-only composition.** This does
not establish that the production `constrain_sapling_spend` has the same
matrix, nor does it establish official parameter compatibility, ceremony
validity, or coverage beyond the three tested valid witnesses. No production Spend or Output code,
proving gate, setup, or official parameter was changed.

### Phase 9.21.41 — Expanded full Spend witness coverage

The full source-order Python Spend path was differentially exercised for three
independently constructed satisfying witnesses. The original pinned Bellman
trace was reused without another synthesis. Each of the two additional
witnesses was independently synthesized by pinned Bellman with complete
ordered A/B/C row capture and compared directly against its Python matrix.
Each matrix has 98,777 rows, 98,646 columns, and fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
Both variant Bellman exports and Python matrices contain the same allocation
identities and order, assignments, annotations, public-input positions, and
every ordered A/B/C expression. Bellman reported each witness satisfied, and
both Python systems are satisfied. The Bellman TestConstraintSystem hash also
matched the pinned expected value
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`.

The first added witness uses value zero and alternating direction bits
(`true, false, ...`) over a 32-level path, using seed
`3157920b21844d6a77039ce125684fb2`. Its full Bellman exporter command took
31.082 seconds; Python synthesis took 49.957 seconds. The second uses
`u64::MAX` and 32 `true` direction bits, with seed
`a74c11df052e8b7319c036548922e36d`; its Bellman exporter took 28.407 seconds
and Python synthesis took 50.193 seconds. End-to-end test times were 96.982
and 94.455 seconds, respectively.

The sampled peak working set of the Bellman exporter process tree
(cargo/test descendants, excluding the Python test runner) was 563.4 MiB for
each case. The process tree was sampled at approximately 150 ms intervals, so
this is an observed peak, not a platform-level peak-RSS guarantee. Both cases
use independent fixed RNG seeds and produce different `ak`, `nsk`, `g_d`, and
`rcv` assignments from the baseline. Their complete IVK and nullifier BLAKE2s
allocation groups, note-content hash, and `nk` representation assignments
also differ from baseline.

Post-synthesis circuit-level mutations were evaluated against each variant's
independently exported Bellman matrix and assignments. Changing only public
`Input(5)` fails row 76,894 (`anchor/enforce input is correct`) in both
systems. Changing `Input(5)` and the conditional-anchor auxiliary together
leaves the conditional-root row satisfied for the zero-value case; the same
mutation fails row 76,893 (`conditionally enforce correct root`) for the
maximum-value case. Mutating `ak/u` and the first Merkle sibling also produced
identical failed-row tuples in the Python evaluator and the Bellman matrix
evaluator. These are post-synthesis witness mutations, not additional
invalid-input synthesis runs.

The two missing full-matrix variant differentials passed (2 tests); the
original baseline trace was reused and was not resynthesized. Ruff,
`py_compile`, Pylance file syntax validation, Rust formatting, and
`git diff --check` passed. An earlier zero-value test run exposed an incorrect
expectation: changing the public anchor alone is not a no-op, because the
separate input-equality row remains enforced. The test distinguishes that row
from the value-conditioned root row, and the final full-matrix runs pass the
exact failure-location assertions.

**Coverage status:** the isolated source-faithful port has exact matrix,
assignment, and satisfaction evidence for three valid witnesses, plus
post-synthesis anchor, point-coordinate, and authentication-sibling
mutations. Other witness families remain unverified. Production Spend matrix
identity, official-parameter compatibility, and ceremony validity remain
**Unverified**.

### Phase 9.21.42 — Production Spend audit against the reference

The read-only production audit measured the production matrix at 98,777 rows
and 98,646 columns, with fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
The verified pinned source matrix has the same dimensions but fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
Therefore, exact ordered matrix identity is **disproved for these captured
exports**.

The audit synthesized production once with the baseline witness. It reused
that captured production matrix (without a fresh production synthesis) for
the zero-value/alternating-direction and `u64::MAX`/all-right fixtures,
validating each production host
witness and transferring its source assignments through the reviewed v7
semantic variable map. All 98,777 production rows were satisfied under each
of the three mapped assignments. Across each fixture, all 8 public/ONE
variables and 98,637 mapped auxiliaries have matching values; one auxiliary
per implementation remains unmatched. Production column 32,621 is the
little-endian packed Merkle path position. The source's `Aux(76805)` at column
76,813 is the conditional-anchor copy of the public anchor. Production's
additional position-reconstruction row and the source's two conditional-
anchor rows remain unmatched as individual rows; Phase 9.21.43 resolves them
through explicit helper projections for the captured matrices.

Among mapped auxiliaries, 53,901 use different canonical columns and 52,520
are displaced in relative allocation order. The largest displacement is in
Merkle authentication: production allocates/range-decomposes a packed
position before path levels, while Bellman allocates each direction bit in
the corresponding path-level sequence and reuses those bits for `g^position`.
Production allocates all public inputs at entry; Bellman inputizes `rk`, `cv`,
`anchor`, and the nullifier chunks after 1,029, 29,075, 76,806, and 98,638
auxiliaries. Public positions and values nevertheless match. No mapped
private allocation annotation strings or paired row-label strings match
literally; the equation correspondence uses semantic variable identities,
not annotation or row-index equality.

The retained row correspondence pairs 98,775 of 98,777 rows without
ambiguity: 69,840 have exact A/B/C factors, 251 swap A/B, 28,351 use invertible
factor normalizations, and 333 match only after expanding `A*B-C`. Of paired
rows, 48,546 move index. These are ordering/factorization differences in the
paired equations. At the end of Phase 9.21.42, the helper projection had not
yet been integrated into a complete relation verdict; see Phase 9.21.43
below. Exact ordered matrix identity is disproved for these exports.

The focused production audit passed **1 test** in **675.458 seconds**:
one production synthesis, two reused production-matrix witness evaluations,
and two independent Bellman variant exports. The exporter now includes each
fixture diversifier for production host-witness reconstruction. No production
Spend or Output circuit, setup, parameter, or proving gate changed. Exact
production QAP/query compatibility, official-parameter binding, and
ceremony validity remain **Unverified**.

### Phase 9.21.43 — Production Spend relation equivalence

The captured production and pinned Bellman matrices have different ordered
matrices, but the same constrained relation under the documented semantic
variable map and helper projections. Of 98,777 rows, 98,775 have unique
polynomial correspondences: 69,840 exact-factor matches, 251 A/B swaps,
28,351 nonzero factor normalizations, and 333 expanded `A*B-C` matches.
The source-only anchor variable `T` is uniquely fixed by `T=A`; substituting
it into `(R-T)V=0` yields production's `(R-A)V=0`. The local-only packed
position `P` is uniquely fixed by `P=Σ(i=0..31)2^i d_i`, so it adds no
restriction beyond the source's 32 little-endian Boolean direction bits.
Together these derivations establish relation equivalence for the captured
matrices; they do not depend solely on the three tested assignments.

**Exact matrix identity is disproved for the captured exports:** both are
98,777 × 98,646, but production fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`
differs from Bellman's
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
The 48,546 moved rows, 53,901 mapped auxiliaries in different columns, all
public-input positions, and allocation-order causes are itemized in the
[implementation report's Phase 9.21.43 discrepancy table](sapling-circuit-implementation.md#phase-92143--production-spend-relation-equivalence-investigation).

This verdict applies to the captured production matrix. Production was
synthesized once; the two alternate witness assignments were evaluated
against that same matrix. Whether every fresh production synthesis emits the
same matrix remains unresolved. Exact QAP/query equivalence, official
parameter-to-circuit binding, and ceremony validity remain **Unverified**.
No production code, setup, parameter, or proving gate changed.

Focused validation passed: semantic-projection tests **8 tests / 17
subtests** in **0.013 s**; variable/row/provenance correspondence tests
**43 tests** in **0.035 s**; and pinned-Bellman Merkle/anchor differential
tests **4 tests** in **137.703 s**. Python syntax compilation and
`git diff --check` passed. Ruff reported 11 findings in unchanged audit/test
helpers; these were not modified. The 675.458-second production audit is the
retained Phase 9.21.42 result and was not rerun.

## Historical incremental porting sequence (completed)

This sequence was written before the full composition. It is retained as
implementation history; the source-order composition and complete matrix
comparison it describes are now recorded above.

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
3. Preserve the standalone nullifier multipacking trace and its 254+2-bit
   boundary checks when composing the complete Spend event order.
4. Recompose all verified components in `Spend::synthesize` order, preserving
   inputize events, the direct direction-bit handoff to `g^position`, and the
   already verified `rt` relation without skipping or duplicating rows.
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

### Signed Montgomery lookup and conditional negation

The pinned implementation is Bellman 0.15
`gadgets::lookup::lookup3_xy_with_conditional_negation`, called by
`pedersen_hash::pedersen_hash` in the pinned
`sapling-crypto/src/circuit/pedersen_hash.rs`. Its three input bits are
little-endian within a window: bits 0 and 1 choose the ordered table entry
`i = bit0 + 2*bit1`, and bit 2 is the sign bit. The Pedersen window table
contains the Montgomery coordinates of `[g, 2g, 3g, 4g]`, in that order.
Thus the signed digit is `±(1 + bit0 + 2*bit1)`, ranging from `+1` through
`+4` or `-1` through `-4`. There is no zero-magnitude encoding; selector zero
means `+1`, and selector four means `-1`.

The lookup allocates only `y` first, with assignment equal to the selected
table `y` or its field negation. It then computes `precomp = bit0 AND bit1`,
constructs the unallocated affine `x` expression, and emits one
`y-coordinate lookup` row:
`(y_lc + y_lc) * sign = y_lc - y_allocated`. The returned x coordinate is a
linear-combination-backed `Num`; the returned y coordinate is allocated.
Boolean AND constant simplifications follow Bellman's `Boolean::and`; the
all-allocated selector fixtures exercise its allocated-bit branch. The
isolated Python helper validates selectors and all four canonical table
coordinates before mutation.

The Rust reference harness calls Bellman's actual
`lookup3_xy_with_conditional_negation` against the first pinned
`PEDERSEN_HASH_GENERATORS` window, with all eight selector combinations. The
exported table’s four points match the Python Pedersen table values and order.
For each selector, Python and Bellman match exactly at **5 auxiliary
variables / 5 ordered constraints** (three input Boolean allocations/rows,
the lookup y allocation, precomp allocation/row, and signed y lookup row).
Every assignment, variable annotation/index, row label, and A/B/C term was
compared. Outputs match the table’s selected x and the sign-adjusted y.
Selectors cover every magnitude from one to four with both signs, including
the lowest/“zero bits” selector and maximum magnitude four. Altered sign,
precomp, and lookup-y assignments produce the same failing row indices as
Bellman.

Wrong selector count, wrong table length, malformed/noncanonical
coordinates, foreign, unassigned, and non-Boolean selectors reject before the
Python lookup mutates the system. The focused signed-lookup checks passed
**2 tests / 53 subtests**. The complete isolated primitive suite passed **21
tests / 30,353 subtests**; Spend circuit regressions passed **6 tests / 76
subtests**, and Sapling gadget regressions passed **52 tests / 273 subtests**.
Ruff, Python syntax checks, Rust formatting/build, and `git diff --check`
passed. The full Sapling suite was not run.

This verifies the signed lookup gadget and the tested first-window table only.
It does not establish all Pedersen generator-window values, complete
Pedersen-hash parity, full Spend matrix alignment, or official parameter
compatibility. At that earlier signed-lookup checkpoint, complete
multi-window Pedersen integration and note-commitment verification remained
unverified; see the subsequent verified sections below.

### Complete Pedersen hash path

The pinned `circuit::pedersen_hash::pedersen_hash` prepends the six constant
true bits returned by `Personalization::get_bits` for
`Personalization::NoteCommitment`, then consumes the message in three-bit
windows, padding the final window with constant-false bits. The first two
bits select one of `[g, 2g, 3g, 4g]`; the third conditionally negates its
Montgomery y coordinate. In `circuit::constants`,
`generate_pedersen_circuit_generators` maps each of the six
`PEDERSEN_HASH_GENERATORS` to 63 windows using `to_montgomery_coords`.
Within each segment, the window base advances by four doublings (`16 *
previous_base`). The complete table therefore contains **6 generators x 63
windows x 4 points = 1,512 Montgomery points**.

Each selected Montgomery point is accumulated in source order as
`selected.add(previous_segment_result)`. The segment result is converted with
`MontgomeryPoint::into_edwards`; subsequent segments are accumulated as
`converted_segment.add(previous_edwards_result)`. The isolated port in
`tests/sapling_spend_reference_port.py` composes only the previously verified
signed lookup, Montgomery addition/conversion, and Edwards addition helpers.
It remains test-only and does not change production Spend or Output.

The Rust/Bellman harness exports every generated table coordinate and traces
the complete lookup, Montgomery, conversion, and segment-addition sequence.
It uses Bellman's actual `lookup3_xy_with_conditional_negation`; the pinned
Sapling Montgomery and Edwards operations are mirrored in the test harness
because those circuit methods are private. The Python and reference tables
match coordinate-for-coordinate across all 1,512 points. Full ordered traces
also match for all cases:

| Input case | Auxiliary variables | Ordered constraints |
|---|---:|---:|
| Empty message | 7 | 7 |
| 183 zero bits (one-segment boundary) | 495 | 495 |
| 184 zero bits (next-segment boundary) | 505 | 505 |
| 184 alternating bits (multi-segment) | 505 | 505 |
| 1,128 zero bits (all generators) | 3,040 | 3,040 |
| 1,128 one bits (all generators) | 3,040 | 3,040 |

For each trace, every allocation index and annotation, witness assignment,
row label, ordered A/B/C expression, output coordinate, and satisfaction
result matched. Mutating a message bit/sign selector, lookup-y assignment,
Montgomery-addition intermediate, or final output coordinate yielded the
same failed row indices as the reference. Unassigned, foreign, malformed,
non-Boolean, out-of-range, and over-capacity inputs reject before the hash
helper allocates variables or constraints.

Focused Pedersen differential coverage passed **4 tests / 8,487 subtests**.
The combined isolated reference-port, Sapling gadget, Spend circuit, and
compatibility-manifest regressions passed **102 tests / 39,194 subtests**.
The Rust exporter was built and run by these differential tests; Rust
formatting, Ruff, Python syntax checks, and `git diff --check` passed. The
full Sapling suite was not run because it includes the prohibited
synthetic-setup regression.

This establishes parity for the complete Pedersen hash path and tested input
cases only. At this checkpoint, note-commitment parity was not yet established.
Full Spend matrix alignment, upstream Bellman full-circuit matrix equivalence,
and official parameter compatibility remain unverified. Parameter-to-circuit
binding and ceremony validity remain separately unverified.

### Source-faithful note commitment

The pinned `Spend::synthesize` in `circuit.rs` forms note contents in this
order: the 64 little-endian bits returned by
`expose_value_commitment`'s `u64_into_boolean_vec_le`, then
`EdwardsPoint::repr` for `g_d`, then `EdwardsPoint::repr` for `pk_d`.
The diversifier-derived `g_d` and `pk_d = g_d.mul(ivk)` are computed earlier
in Spend synthesis; their coordinate witnesses enter this isolated relation
as already-allocated point variables.
`repr` uses strict little-endian field decompositions and emits each point as
the 255 bits of `v` followed by the least-significant bit of `u`. Thus the
Pedersen message is exactly **576 bits**; the NoteCommitment personalization
adds six `true` bits, yielding 582 bits / 194 three-bit lookup windows. The
verified hash processes four generator segments with 63, 63, 63, and 5
windows.

After `note content hash`, Spend decomposes `commitment_randomness` (`rcm`)
with `field_into_boolean_vec_le` into the 252 little-endian Jubjub scalar
bits, multiplies them by `NOTE_COMMITMENT_RANDOMNESS_GENERATOR` using
`ecc::fixed_base_multiplication`, then adds that point to the Pedersen result
under `randomization of note commitment`. The isolated
`constrain_spend_note_commitment` in
`tests/sapling_spend_reference_port.py` composes the already verified strict
representation, complete Pedersen hash, fixed-base multiplication, and
Edwards addition helpers. It takes the prior `g_d` and `pk_d` witness
variables as inputs, matching their earlier allocation in Spend synthesis;
the reference trace includes their source witness/curve-interpretation
prefix. It validates value, randomness, point ownership, assignments, and
witness consistency before this helper allocates its note-value bits.

The Bellman 0.15 harness calls Bellman's actual `u64_into_boolean_vec_le`,
`field_into_boolean_vec_le`, strict field-bit decomposition, and fixed-base
lookup, plus the already verified Pedersen lookup path. It uses actual pinned
Sapling diversifier derivation for four distinct valid 11-byte diversifiers,
and exports the pinned note-randomness generator. The full traces match
exactly for zero, one, middle, and maximum u64 values; `rcm` zero, one, a
representative scalar, and the maximum Jubjub scalar; and varied diversified
`g_d` and `pk_d` points. Each trace contains **3,612 auxiliary variables and
3,614 ordered constraints**, including the two input point witness/curve
interpretation prefixes. All output hashes, randomized commitment
coordinates, assignments, annotation/index order, labels, ordered A/B/C
expressions, and satisfaction results matched.

Changing the high value bit, a `g_d` representation bit, a Pedersen lookup
witness, an `rcm` bit, a fixed-base lookup witness, or the final randomized
commitment coordinate yields the same failed row indices as Bellman.
Missing, malformed, foreign, unassigned, inconsistent, and out-of-range
inputs reject before the note-commitment helper changes the target system.
The focused note-commitment differential suite passed **3 tests / 18,092
subtests**. The combined isolated reference-port, Sapling gadget, Spend
circuit, and compatibility-manifest regressions passed **105 tests / 57,286
subtests**. Ruff, Python syntax checks, Rust formatting/build, and
`git diff --check` passed. The full Sapling suite was not run because it
includes the prohibited synthetic-setup regression.

This verifies the isolated note-commitment computation and tested inputs only.
It does not establish full Spend matrix alignment, upstream Bellman
full-circuit matrix equivalence, or official parameter compatibility.
Parameter-to-circuit binding and ceremony validity remain separately
unverified.

### Source-faithful Merkle authentication path

The pinned `Spend::synthesize` in `sapling-crypto/src/circuit.rs` walks the
authentication path in ascending level order. At each level it allocates the
position bit and sibling, calls Bellman's `AllocatedNum::conditionally_reverse`
on the current node and sibling, decomposes the selected left and right field
elements with non-strict `to_bits_le`, and passes their concatenated bits to
`pedersen_hash` with `Personalization::MerkleTree(level)`. The next level's
current node is the resulting hash's `u` coordinate. The personalization is
six little-endian bits of the level (`(level >> bit) & 1`); the path direction
bits are likewise consumed in least-significant-level-first order. The
conditional anchor check is a subsequent Spend stage and is outside this
isolated path helper.

`constrain_spend_merkle_authentication_path` in
`tests/sapling_spend_reference_port.py` ports this path sequence using the
verified Bellman-trace Pedersen helper. Its current leaf is supplied as an
already allocated variable, matching the source's use of the note commitment
coordinate; the fixture's initial leaf allocation is setup input, not a path
allocation. Each level preserves the source annotations and enforcement order:
direction Boolean, sibling, two conditional reversals, each side's 255
Boolean bits and reconstruction row, then the level-personalized Pedersen
hash. The helper validates leaf ownership/assignment and all path entries
before adding variables or constraints. Empty paths return the supplied leaf.
The source `Spend::synthesize` uses 32 levels; the isolated helper additionally
permits shallower paths for boundary testing and rejects depths above 32.

The test-only Bellman exporter traces all allocations, assignments, labels,
ordered A/B/C rows, satisfaction, and root values for six path cases: depth 32
all-left, all-right, alternating and mixed directions; depth 1 right; and a
depth 31 mixed path. Exact trace parity held in every case. Including the fixture's initial leaf input,
the four depth-32 traces each contain 44,193 auxiliary allocations and 44,224
ordered constraints; the depth-1 trace contains 1,382 auxiliary allocations
and 1,382 constraints; the depth-31 trace contains 42,812 auxiliary
allocations and 42,842 constraints. Mutation tests for a direction bit,
sibling, reversal result, Pedersen lookup witness, and final root produced the
same failed row indices as Bellman. Invalid, foreign, unassigned, and
inconsistent leaf inputs, plus malformed/out-of-range siblings, invalid
direction types, and excessive path depths, were rejected before the target
system changed.

The focused reference-port regression passed **31 tests / 322,301
subtests**, including all six complete ordered path traces and mutation /
pre-mutation rejection checks. The related Sapling gadget, Spend circuit, and
compatibility-manifest regression modules passed **77 tests / 354 subtests**;
together these selected suites passed **108 tests / 322,655 subtests**. Ruff,
Python syntax, Rust formatting/build, and `git diff --check` all passed. The
full Sapling suite was not run because it includes the prohibited
synthetic-setup regression. These results establish an isolated
authentication-path comparison only. The production packed-position path
was not changed; the conditional anchor stage and full Spend synthesis are not
included. Full Spend matrix alignment, upstream Bellman full-circuit matrix
equivalence, and official parameter compatibility remain **Unverified**.

### Source-faithful conditional anchor

At the pinned `sapling-crypto/src/circuit.rs` Spend anchor stage, Sapling
allocates `rt` under `conditional anchor` from the supplied anchor witness.
It then enforces the ordered row
`(cur - rt) * value_num = 0`, labeled `conditionally enforce correct root`.
Finally, `rt.inputize(cs.namespace(|| "anchor"))` allocates the public anchor
input and emits a second row labeled `anchor/enforce input is correct`:
`anchor_input * ONE = rt`. Both rows are required; the second is not folded
into the root relation.

The anchor is the fifth non-ONE public input: Bellman `Input(5)` (with
`Input(0)` reserved for ONE), following `rk.u`, `rk.v`, `cv.u`, and `cv.v`.
In ZyCoin's local R1CS layout this is public-input position 5 and index 4 in
`public_inputs()`. The local R1CS requires public inputs to be reserved before
private allocations, whereas Bellman can inputize `rt` after allocating it.
The isolated helper therefore receives the pre-reserved anchor variable from
its caller, but performs the same `rt` allocation and emits the same two
ordered equations, labels, assignments, and matrix indices. Bellman's input
and auxiliary namespaces are compared separately and mapped to the same
columns.

`constrain_spend_conditional_anchor` in
`tests/sapling_spend_reference_port.py` accepts the already allocated root
from the Merkle helper, note-value variable, and public anchor variable. It
checks ownership, private/public roles, canonical witness values, and
assignment consistency before allocating `conditional anchor/num`. This
preserves the root/value witness dependency and does not add a root
decomposition or alter the Merkle helper. The test-only Rust trace now supports
late input allocation and calls Bellman's actual `AllocatedNum::inputize`.

Six Bellman fixtures cover nonzero matching and mismatching anchors, zero
matching and mismatching anchors, the maximum field-element boundary, and a
nonzero note with a mismatching maximum-field Merkle root. All six have five
public inputs, three auxiliary allocations in the isolated context (value,
root, and `rt`), and two constraints. Python matched every ordered allocation
and assignment, input position, label, A/B/C expression, and satisfaction
result. Mutating the root, note value, public anchor, or intermediate `rt`
produced the same failure rows as Bellman. Missing/malformed, foreign,
unassigned, and out-of-range witnesses reject before system mutation.

The complete isolated reference-port suite passed **34 tests / 322,337
subtests**. The Sapling gadget, Spend circuit, and compatibility-manifest
regressions passed **77 tests / 354 subtests**. Conditional-anchor targeted
tests passed again after the final invalid-input test adjustment (**3 tests /
36 subtests**). Ruff, Python syntax, Rust formatting/build, and
`git diff --check` passed. The full Sapling suite was not run because it
includes the prohibited synthetic-setup regression. The production Spend and
Output circuits were not changed. This does not establish complete Spend
matrix alignment, upstream Bellman full-circuit matrix equivalence, or
official parameter compatibility; all remain **Unverified**.

### Source-faithful nullifier BLAKE2s

The pinned `Spend::synthesize` in `sapling-crypto/src/circuit.rs` accumulates
`nk.repr` into `nf_preimage` when it first represents `nk`, then appends
`rho.repr` after the faerie-gold position addition. Each strict point
representation is 255 little-endian bits of `v` followed by the least
significant bit of `u`. The exact 512-bit preimage is therefore
`nk.repr || rho.repr`; Bellman's BLAKE2s consumes its Boolean bits least
significant bit first within each byte. Spend calls Bellman's `blake2s` under
`nf computation` with `PRF_NF_PERSONALIZATION` (`Zcash_nf`) and retains all
256 digest bits. The subsequent `multipack::pack_into_inputs` call is outside
this isolated hash stage and is not included here.

The isolated test-only `constrain_spend_nullifier_blake2s` validates both
256-bit representations, ownership, assignment, and Boolean values before
calling the source-derived Bellman 0.15 BLAKE2s synthesis helper with the
nullifier-specific personalization and namespace. The exact differential
fixture allocates a representative generator `nk` and `rho`, including their
point witnesses and strict representations. Bellman reports no public inputs
for this isolated context; the trace compares all auxiliary identities and
positions, assignments, annotations, ordered constraints, and satisfaction.

For the retained `generator_pair` fixture, Bellman and Python matched exactly:
**22,566 rows**, **22,519 columns** (including ONE), and matrix fingerprint
`20f63b47b5102a57ea023edc7452b3f9e7004ea34a5a53e2402984c17e89ab32`.
The full differential invocation performed exactly **two circuit syntheses**:
one Bellman reference synthesis and one Python synthesis. Additional
identity, generator/negative-generator, and raw half-boundary digest vectors
were checked against independent personalized BLAKE2s outputs without circuit
synthesis. Invalid lengths, malformed representations, foreign variables,
unassigned variables, and non-Boolean values reject without changing the
system and before invoking synthesis.

The three focused nullifier tests passed (**3 tests / 11 subtests**, 14.54
seconds); the existing pinned nullifier output and personalization regressions
passed (**2 tests**, 5.07 seconds). Ruff, Python syntax checks, Rust formatting,
and `git diff --check` passed. No full gadget or Sapling suite was run.
Nullifier multipacking is separately verified in the standalone combined
trace described below. This hash-stage result does not establish full Spend
source-order composition, complete Spend matrix alignment, upstream
full-circuit Bellman equivalence, or official parameter compatibility; those
remain **Unverified**.

### Source-faithful Spend value commitment

At Sapling revision `88a7946b4a3066787776e11f0a502654167e022d` and Bellman
revision `b726862a4ece8a627e7fea486d77b502a6edbb0b` (`0.15.0`), the pinned
`src/circuit.rs::expose_value_commitment` allocates a 64-bit little-endian
`value` under `"value"`, computes its
fixed-base multiplication with `VALUE_COMMITMENT_VALUE_GENERATOR`, allocates
the Jubjub-field `rcv` bits little-endian under `"rcv"`, computes the
fixed-base multiplication with `VALUE_COMMITMENT_RANDOMNESS_GENERATOR`, adds
the two Edwards points, then calls `cv.inputize` under `"commitment point"`.
The 64-bit decomposition uses Bellman 0.15
`u64_into_boolean_vec_le`; `rcv` uses `field_into_boolean_vec_le` and its
252-bit field width. The source does not add a separate canonical-range check
for `rcv`. The fixed-base paths use the pinned Sapling 3-bit window lookup and
Edwards-addition sequence. `EdwardsPoint::inputize` allocates `u` then `v`;
each `AllocatedNum::inputize` enforces its allocated input times ONE equals
the computed coordinate. In Spend, the parent call is under
`"value commitment"`, so the reference labels include that namespace.

The test-only `constrain_spend_value_commitment` follows this sequence and
reuses only the independently verified fixed-base and Edwards helpers. A
test-only `SpendReferenceR1CS` adapter records the late public input allocations
after the auxiliary allocations, like Bellman, while mapping matrix columns
to the canonical ONE/public/auxiliary order used by the local R1CS serializer.
Thus the trace comparison checks the upstream temporal allocation order,
public positions, assignments, namespace annotations, and every ordered A/B/C
row without moving the two inputization constraints.

The retained fixture uses `value = 0x0123456789abcdef` and
`rcv = -Fr(0x5aa596c32d714ef0)`. Bellman and Python matched exactly:
**1,265 rows**, **1,266 columns** (ONE, two public inputs, and 1,263
auxiliaries), with canonical matrix fingerprint
`6b3c7e369962530b0bb495a07876b5745a5f233539557f6d8307bf17d9ebfda7`.
The differential suite performs exactly **two full circuit syntheses**: one
Bellman reference fixture and one Python synthesis. The three focused tests
passed (**3 tests / 1,276 subtests**, 2.24 seconds). They cover exact ordered
trace parity, the value and randomness bit mappings, public input positions,
and satisfaction.

Additional host-only output vectors cover zero value/zero randomness,
maximum `u64` value/zero randomness, and zero value/maximum Jubjub scalar
randomness; these checks do not invoke circuit synthesis. Invalid, missing,
Boolean-as-integer, and out-of-range values/randomness reject before
allocation or fixed-base synthesis. The isolated API has no caller-supplied
variables, so foreign-variable ownership validation is not applicable.
Full Spend event-order integration, complete Spend matrix alignment, upstream
full-circuit Bellman equivalence, and official parameter compatibility remain
**Unverified**.

### Source-faithful Spend nullifier multipacking

At Sapling revision `88a7946b4a3066787776e11f0a502654167e022d` and Bellman
revision `b726862a4ece8a627e7fea486d77b502a6edbb0b` (`0.15.0`),
`Spend::synthesize` calls `multipack::pack_into_inputs` under the
`"pack nullifier"` namespace after the nullifier BLAKE2s stage. Bellman
`gadgets/multipack.rs::pack_into_inputs` consumes the digest Boolean sequence
in order using `Scalar::CAPACITY`-sized chunks, folds each chunk little-endian
with coefficients `1, 2, 4, ...`, allocates one public input per chunk, and
enforces `packed_num * ONE = input`. For the 256-bit nullifier digest,
`Scalar::CAPACITY` is 254: all bits are consumed as a 254-bit chunk followed
by a 2-bit chunk; no digest bits are dropped.

The test-only `constrain_spend_nullifier_multipacking` validates the complete
bit sequence, ownership, assignment, and Boolean range before allocating any
public inputs or constraints. It supports both the local Sapling gadget
negated-bit wrapper and the Bellman BLAKE2s reference port's `_Negated`
wrapper, preserving each wrapper's `1 - variable` semantics. It then
allocates the packed inputs and emits the source-ordered packing rows. The
reference exporter synthesizes the nullifier hash and multipacking together,
so the differential test checks the digest-bit identities and values,
allocation identities and assignments, public positions, labels, and every
ordered A/B/C row.

The retained representative fixture includes five earlier public-input
placeholders (`rk.u`, `rk.v`, `cv.u`, `cv.v`, and `anchor`) to establish the
source positions of the packed inputs. The packed nullifier inputs are
positions **6 and 7** (one-based). Those preceding values are fixture context,
not a claim that the full Spend witness was composed. Bellman and Python
matched exactly: **22,568 rows**, **22,526 columns** (ONE, seven public
inputs, and 22,518 auxiliaries), with canonical matrix fingerprint
`d4b682f3441cc17495557468a1bfdccb053fe9800fcabb96a6f3cb97269403ab`.
The focused differential run performed exactly **two full syntheses**: one
Bellman reference trace and one Python synthesis. It passed **3 tests** with
**22,580 subtests** in **274.58 seconds**.

Host-only vectors cover all-zero, all-one, alternating LSB-first, and the
capacity boundary (bits 253, 254, and 255 set), confirming little-endian
packing and the 254+2 split without additional circuit synthesis. Invalid
lengths, malformed sequences, foreign and unassigned variables,
non-Boolean variables, and invalid literal bits were rejected before public
input allocation or constraint mutation. The Python differential also
compares satisfaction and confirms one invocation each of the nullifier
BLAKE2s and multipacking synthesis functions. This establishes only the
standalone combined nullifier-hash/multipacking fixture; complete Spend
event-order integration, complete Spend matrix alignment, upstream
full-circuit Bellman equivalence, and official parameter compatibility remain
**Unverified**.

The shared temporal-column mapping also passed the value-commitment regression
(**3 tests / 1,276 subtests**, 2.38 seconds). The compatibility-manifest tests
passed (**19 tests / 5 subtests**, 0.29 seconds). Ruff, Python syntax checks,
Rust formatting/build checks, and `git diff --check` passed; the full Sapling
gadget suite was not run.

### Phase 9.21.44 — Fresh production Spend synthesis

The test-only alignment regression freshly synthesized the pinned baseline
witness and the existing `zero-value-alternating` witness in separate
production R1CS instances. Both fresh systems had **98,777 rows × 98,646
columns**, production matrix fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`, and
all **98,777 rows satisfied**. Each live assignment was checked against the
pinned reference through the established semantic map and helper projections.
The alternate fixture had value zero and directions `(true, false) * 16`;
its freshly exported Bellman trace fingerprint was
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.

The fresh baseline and alternate production traces had the same complete
serialized structure SHA-256
`af27c2ab4d8423b3315b96f2cf8f24fda1c1442bd0c28796bd22222fcc56c493`,
including variable names/order and ordered labeled A/B/C expressions. Their
assignment hashes differed as expected:
`3360c2f3e562f7ce1e9bb67c21cdf1d54354679ff8f7a08e99618cf312ae7bd6`
(baseline) and
`c2bb7870d3e608643d1d8caaad1f99b802a37c3bf2cdd6754a36fa6a0437d367`
(alternate). Public positions were identical (SHA-256
`3675d2e5277c442f6e1848a82b011ecb75c3a6d11aa0468ba4d5f73c1826fa07`):
`rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`, `nullifier_chunk_0`, and
`nullifier_chunk_1` occupy positions 1–7. Combined trace hashes were
`829f1f4dcaf9968ebb00c4098358746dd7ea2c6493a0b164cd1cefe05a77a01a`
(baseline) and
`620da3f15b477cc53a07e88c8e3209963ab6d461093963bdc2307aac8c14a65a`
(alternate).

The original raw production trace was not persisted, so byte-for-byte
comparison to that trace is unavailable. Instead, both fresh matrices match
its recorded production fingerprint and match each other's complete structure;
the fresh alternate's mapped assignments and satisfied rows were checked
against the independently exported Bellman matrix. The crosswalk covers 8
public/ONE variables and 98,637 auxiliaries; 53,901 mapped auxiliary columns
differ and 52,520 are displaced in relative order, consistent with the
documented captured-matrix mapping. This verifies reproducibility only for
these two fresh executions, not arbitrary witnesses or all executions.

The focused fresh-synthesis test passed **1 test in 481.933 seconds**. Within
that run, the two production synthesis calls took **11.697 s** and **6.561 s**,
and the Bellman variant export took **31.023 s**. The semantic-projection
probes passed **8 tests** and the row/variable correspondence probes passed
**29 tests** (0.016 s and 0.006 s, respectively). Exact ordered matrix
identity remains disproved; captured-matrix relation equivalence remains
established under the documented mapping. QAP/query equivalence, official
parameter-to-circuit binding, and ceremony validity remain **Unverified**.
No production circuit, Output, setup, parameter, or proving gate changed; no
synthetic setup regression was run.

### Phase 9.21.45 — Production Spend QAP and official-query audit

This QAP comparison is for the pinned baseline witness, not a proof over all
witnesses. The production matrix fingerprint is
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`; the
pinned Bellman matrix fingerprint is
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
Both contain 98,777 constraints and 98,646 variables. The QAP domain is
131,072 (98,785 rows including eight input rows plus 32,287 padding rows).
The variable map matches all 8 ONE/public values and 98,637 auxiliaries.
Upstream `Aux(76805)` is the conditional-anchor helper `T=A`; local column
32,621 is packed position `P=Σ(i=0..31)2^i d_i`. These helper projections
support equivalence of the captured constraint relations, but do not by
themselves give a query-coordinate transformation.

The independent Bellman and production QAP vector fingerprints are:

| Vector | Bellman SHA-256 | Production SHA-256 |
|---|---|---|
| A evaluations (131,072) | `22c6662cbe967cb57bc36d05ebf3e81a32d3baa20bf222c0cf5581afd52993b6` | `daca49ab7a9dd2819f40d4b48e94509d78d24ad2fb4846062865cd5f9491fe1a` |
| B evaluations (131,072) | `3169179e3f69d5755671e0f634789dbb3faaa2f7a6025779a6f2ac2240729e71` | `2430c5198e3c39c85dfda8256feb6fa822c40cca983c37dd510cbd1f89cdf198` |
| C evaluations (131,072) | `df2e6de104f3acc367abee83ead55f275670a0e13720044e0d166465948dd872` | `f8efb2f3246022e9cbd1cbbdd551167f9d3d5ab8570d9b8fd273afae2c5d50a9` |
| A coefficients (131,072) | `663ab1569c323f13cc1fd96163b330c8231f3fcb6521cdfa444b49474b03e0c6` | `ae3bf8a74b4d63fb70b10f8257b16c478d4830c70f67e106ca88a59102e8a856` |
| B coefficients (131,072) | `b3b5f5a4504131db6fb1ac5fb00a66592448a6e5a59eec1494231db9faaed7ff` | `8a1504707c0e31a28e1af71c58067bf9baff8d64b74d0359942c5738da46e2c7` |
| C coefficients (131,072) | `6e064cc613e33f7e57ca5183826352c25f2f0410e5ad7f59391cf7e35679880b` | `5dbc6116cbaa3eafca1b792deb0ce0603be484ec052e6fdcb979d3d05aca74c6` |
| H quotient coefficients (131,071) | `27d57fc5eae604c210feda073ee1befcb73a776ef6bf4b08ba25d00314037a55` | `a98ecf083b7660a04fd59fc887e7799cf96c1e0cf5e4cd898690340125850862` |
| H evaluations (131,072) | `b7ee1b2f7f49704446fb4acdc4dcf8e9a859ebeddcd9994d1aa2ec5a3023bb7d` | `04d75e396d3c01478d7de835da712c7a10eecdec070fd79a0781d60ee30f65c7` |

All eight canonical vectors differ for this satisfying assignment. Bellman's
independent quotient-divisibility check and ZyCoin's independent 2n
coset-FFT check pass. Bellman 0.15 also recomputed the quotient from ZyCoin's
exact A/B/C evaluation vectors and reproduced ZyCoin's H coefficient and
evaluation hashes. Thus the H difference is upstream of quotient arithmetic:
the A/B/C QAP inputs differ due to row ordering and factor representation,
not H indexing or an identified quotient implementation defect.

The official file has SHA-256
`8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13`.
Its 437,707 ordered points were compared byte-for-byte with the pinned
Bellman loader in section order IC, H, L, A, B_G1, B_G2; canonical point
encoding and parser curve/subgroup checks passed. IC has ONE followed by the
seven public inputs. H indexes quotient coefficients in ascending degree.
L follows upstream `Aux(0..98637)` order; `Aux(76805)` is supplied by the
anchor projection, while local packed position column 32,621 is reconstructed
from direction bits. A/B query scalar mappings use the pinned sparse-index
map (`183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08`).
The six section digests, counts, and direct-mapping accumulation results are:

| Section | Points | Ordered point-section SHA-256 | Direct mapped accumulation |
|---|---:|---|---|
| IC | 8 | `9d05cfaa8f5cdb11cc8694e73ad76a2c541c94e0648d533089b80941a04f0d7b` | Equal for the baseline witness |
| H | 131,071 | `a8f3a93e8e5f144557701e66acbfdc751002e7a3302b5ad365fc7a342ce1437e` | **Different** |
| L | 98,638 | `afb42dbab478d8f3a571cbe038dee6a0d61da1ef8359c9931d264bcf170b97b6` | Equal for the mapped witness scalars |
| A | 85,390 | `a26b506e2e525246c12d590342f13794a3d1199986d17f067d67dae2a05286d9` | Equal for the baseline witness |
| B_G1 | 61,300 | `ac2dc83a3aee7f8d82c7b562b1838ada266ba73969b52159c41e6994c48196a7` | Equal for the baseline witness |
| B_G2 | 61,300 | `334580c04c7acb927b0bf3c192c8909cc99d8201bd45a20ce41e06f2b789d8fe` | Equal for the baseline witness |

The uncompressed H accumulation hashes are Bellman
`a95259f4792a7727f33efa3eb466b5a1481f06c494182ffd091e46ef39bfd7fe` and
production coefficients against the official H points
`1336802122c751934174ee3689fc8b140240b85e1ab4142a019ed611461742c7`.
Cross-accumulating either coefficient vector against either independently
decoded official H sequence gives the same respective result, ruling out
point decoding, ordering, and MSM implementation as the cause. The five
matching sections are witness-specific accumulations using the mapped
assignment and the same official point vectors; they do not prove equality
of query vectors or a circuit binding. H coefficient order is ascending
degree 0–131,070; the omitted degree-131,071 coefficient is zero.

**Conclusion:** canonical QAP vectors are not equal for the pinned
satisfying witness. The available row map records 48,546 moved rows, 251
A/B swaps, 28,351 nonuniform factor normalizations, 333 expanded
`A*B-C`-only matches, and the two helper projections. This explains why
relation equivalence does not imply equality of the interpolated A/B/C
polynomials, but a complete transformation of all QAP/query coordinates
has not been established. Under the direct official-query mapping, the H
accumulation is concretely incompatible for this witness. Overall
official-parameter-to-production-circuit binding and ceremony validity
remain **Unverified**; no Spend proof was generated and the proving gate
remains closed. The missing Phase-1 artifact and ceremony-era setup/source
evidence prevent an independent binding conclusion.

**Smallest next step:** reuse one existing alternate valid Spend witness to
compare all eight Bellman/production QAP vectors and mapped helper
coordinates, checking whether this observed vector difference is
witness-specific. That would add empirical coverage only. Establishing
equivalence still requires a complete symbolic transformation of the
row-domain, factor, and variable/query coordinates (including `T` and `P`),
or a separate trusted setup bound to the production matrix. No production
change or proving-gate change is justified by the current evidence.

Focused verification: the six-section query test passed **1 test in
1,166.468 s**; Bellman's six-vector accumulation took **202.154 s**.
Its exact-filtered Bellman baseline exporter passed **1 Rust test in
26.68 s**. The QAP comparison's exact-filtered Bellman exporter passed
**1 Rust test in 26.14 s**.
Parameter-query mapping and compatibility-manifest tests passed **32 tests
with 5 subtests in 9.123 s**. The combined QAP/row tests ran **20 tests in
132.582 s**: 19 passed and one failed only on the fresh JSON trace SHA-256
(`e6cbc946b55d0362baf7b45b03a2ad85554e6c874320b30c06693e135ce2f1c2`)
versus the retained digest
(`a39e4d2d815dca24eead67996d94732dc9a12b13ac3f1c4881f5e5dadddf8feb`).
The upstream TestConstraintSystem hash, assignment hash, matrix fingerprint,
and all eight QAP-vector hashes matched their pins; the cause of the
byte-level export digest difference is unresolved because the earlier raw
export is not retained. The run included 3 passing transformation subtests.
The pinned Rust exporter was explicitly filtered to the baseline fixture
because its unfiltered variant test requires an additional environment
variable. No code, fixture, parameter, setup, or proving gate was changed,
and no synthetic setup regression was run.

### Phase 9.21.46 — Alternate-witness Spend QAP comparison

The `zero-value-alternating` witness was independently synthesized by pinned
Bellman and fresh production synthesis. The Bellman assignment fingerprint is
`2fbecf40aaa9dbfcf6476fc68354a5d69550edcc1057aa29d3945a6856484370`; the
production assignment fingerprint is
`a54bfbcdaf8d53b65d4617f24878e8b5ad6507dff04455571e1466f730f12a95`.
The assignment map matched all 8 ONE/public values and 98,637 auxiliary
values. As in the baseline comparison, upstream `Aux(76805)` is projected
from the anchor and local packed position column 32,621 is reconstructed
from the little-endian path directions. The production synthesis was
satisfied and retained 98,777 rows by 98,646 columns, with matrix fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
The independently verified pinned Bellman matrix remains 98,777 by 98,646,
fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
The QAP domain is 131,072.

| Canonical QAP vector | Elements | Bellman SHA-256 | Production SHA-256 |
|---|---:|---|---|
| A evaluations | 131,072 | `ed48c295ddf77151a35a204a36cfc4af44b699608c29883f6b06943cbca4812d` | `f9ad06b02fee3b77a26d58d7b745120c219d65d284ee7499297d12da43f4f4e7` |
| B evaluations | 131,072 | `fb939d73fa877d1557765af2a7f138822435591d094800b375a0f83b6cd2e75c` | `1c037eff849c4ed30ed051ab29daba97d83cdec7cb25447351b230adbdc68067` |
| C evaluations | 131,072 | `586c928a885ecd15f5a5848d8aa9e1b00c7b8bf18c03ef7c46a9518bb75de535` | `14edd1999e02847740ac6666ce0e0522b8d2978d0b12eb680290eae7e507e183` |
| A polynomial coefficients | 131,072 | `8df1793a251d9b2b134ae1de1943d110c90924a229057e1fcdd0c2667744c861` | `3de5a4bc3f61b62587cb78b8b79c52299c24e207b5fbf2a09094877112bfcdb9` |
| B polynomial coefficients | 131,072 | `34a7ec0db0c5e32e0e1b337cc15d7be240d6d975234a158835eee01e62c9907a` | `01c2aff0c44f558c4afbc19a6aa4ee82fad04d91362b918521610684ea401c1c` |
| C polynomial coefficients | 131,072 | `1680ffc16088a76605ce35b6c0a76d7393da6baaf51d9c5f25f0a3fbc1734c8d` | `0910bcc0225aeca315db54845efff73c5f7565ef8b11ce36380d1901c9757e1e` |
| H quotient coefficients | 131,071 | `38d0b98546ba107791f1e4c77670d9e6b76f8ceef4d246de3a180d7c024f8bed` | `604aaeb55a719031c41b15c30193bd469210584ed40e02e73a220ad8bfa5075f` |
| H evaluations | 131,072 | `a5ac5c823e94310619df3744b43dd7eed47b8ed2a5df619f14b6c742d90d83db` | `62dc36d14ff35033b51f074b39703ea3656b9f455e286ad189594101e1560f49` |

All eight Bellman/production vector pairs differ, and both implementations'
eight alternate-witness hashes differ from their corresponding retained
baseline-witness hashes. Thus the vector values vary with the witness, while
the observed all-eight cross-implementation mismatch persists across both
witnesses. Bellman's quotient divisibility check and production's independent
2n coset-FFT quotient identity both pass. Bellman 0.15 independently
recomputed H from the production A/B/C evaluations and reproduced the
production H coefficient hash
`604aaeb55a719031c41b15c30193bd469210584ed40e02e73a220ad8bfa5075f`
and evaluation hash
`62dc36d14ff35033b51f074b39703ea3656b9f455e286ad189594101e1560f49`.
This confirms the production quotient calculation for this witness; it does
not transform the Bellman QAP into the production QAP.

Using the official H points, Bellman's alternate-witness H accumulation
SHA-256 is
`cb5a744efe825173a2b85da7cd2da193cc4462d1c2f85410c9d9981ffa7a73d2`;
the production-coefficient accumulation is
`d3ff0c5ff484fbf25d87e8df5d76d463f833db5ac7f90c819e3e98dccec956bc`.
The direct H-query mismatch therefore persists. This run accumulated all
six official sections but did not compare the other five production
accumulations for this alternate witness. It establishes neither a complete
symbolic query-coordinate transformation nor official
parameter-to-production-circuit binding; both remain **Unverified**.

The focused alternate test passed **1 test in 386.41 s**. Its measured
stages were Bellman export 37.356 s (1 Rust test passed in 26.39 s), Bellman
QAP derivation 33.274 s, production synthesis 7.435 s, production QAP
derivation 21.991 s, and Bellman H cross-check/query accumulation 257.443 s
(the Rust accumulator reported 204.451 s for all six sections). The
baseline raw JSON trace digest was not investigated or regenerated; its
cause remains unresolved because the prior raw export is unavailable.
No production circuit, arithmetic, Output, setup, parameter, or proving gate
was changed, and no synthetic setup regression was run.

### Phase 9.21.47 — Symbolic Spend residual and query transformation audit

This read-only audit reuses the captured 98,777 × 98,646 matrices, v7
variable map, row correspondence, and helper equations. No witness
synthesis was repeated. Let `F^U_i(x)=A^U_i(x)B^U_i(x)-C^U_i(x)` be an
upstream row residual and `F^L_j(x)` its mapped production residual, with
common semantic variables identified by the retained variable map. The
captured crosswalk supplies these exact finite-field identities:

| Paired rows | Count | Identity and rank |
|---|---:|---|
| Native factors, A/B swaps, and nonzero factor normalizations | 98,442 | `F^U_i = α_i β_i F^L_j`, where the two local factors map to the upstream A/B factors with nonzero scales `α_i, β_i` and either same or swapped orientation. The row-wise 2×2 factor map has rank 2; the C map has rank 1. |
| Expanded `A*B-C` matches | 333 | `F^U_i = F^L_j`; scale is exactly 1 for every recorded row. This is an identity of the expanded quadratic residual, not an established linear map of its separate A, B, and C factors. |

For the 98,442 factor-matched rows, writing local factors as `(a,b,c)`,
the upstream factors are `(αa, βb, αβc)` in the same orientation and
`(αb, βa, αβc)` in the swapped orientation. Equivalently, the A/B blocks
are `diag(α,β)` or `[[0,α],[β,0]]`; their determinants are respectively
`αβ` and `-αβ`, nonzero in the scalar field. The recorded profiles reduce
modulo the field modulus to residual scales `αβ=-1` on 18,818 rows and
`αβ=1` on the other factor-matched rows. Together with the 333 unit-scale
expanded identities, the 98,775 paired residual rows therefore form a
permutation followed by nonzero diagonal scaling: rank 98,775 and zero
kernel on that paired block. The matching/pairing fingerprint remains
`f502b0f22dece3829d6e2e1e198ca8d98d82e233e9eb1a4dcded3a399f6ae17d`.

The two remaining source rows and two production rows admit a useful exact
helper-coordinate derivation. Denote the public anchor by `A`, source-only
conditional-anchor auxiliary by `T`, final Merkle root by `R`, note value
linear form by `V`, path direction bits by `d_i`, and production packed
position by `P`. Set
`S=Σ(i=0..31)2^i d_i` and make the full ambient variable substitution
`P = T + S - A`, leaving every common variable unchanged. Its inverse is
`T=P-S+A`; hence this change of coordinates has full rank 98,646 and zero
kernel. The source residual pair and production residual pair become:

```text
f_root   = (R - T)V
f_anchor = A - T
g_root   = (R - A)V
g_position = P - S

[g_root, g_position]^T = [[1, -V], [0, -1]] [f_root, f_anchor]^T
```

The helper residual matrix has determinant `-1`, so it is invertible at
every field assignment; the full 98,777-row residual map is pointwise
full-rank after row pairing and permutation. However, the off-diagonal entry
`-V` depends on the witness. It is not a fixed `GL(98,777, F)` row operation.
This proves a constructive relation-preserving coordinate/residual
transformation for the captured constraints, while explaining why relation
equivalence does not supply the constant row transformation used by a
standard QAP basis change.

For a complete domain of size `N=131,072`, let `W` be the evaluation matrix
at the Bellman roots and `W^-1` its interpolation map. If all factor rows
were covered by a fixed row transform `R_A,R_B,R_C`, then coefficient
vectors would transform as `a^U_j=W^-1 R_A W a^L_j` (and analogously for
B and C), augmented by the variable-coordinate map. The crosswalk proves
this only on the 98,442 factor-matched rows. It proves residual equality
but not a component-wise `R_A,R_B,R_C` for the other 333 rows. The helper
block adds a witness-dependent row operation. Consequently a complete
fixed linear transformation of the variable-indexed A/B/C QAP polynomial
families has **not** been established. The exact coefficient identities
available for H are only
`H^U(X;x)=(A^U(X;x)B^U(X;x)-C^U(X;x))/Z(X)` and
`H^L(X;x)=(A^L(X;x)B^L(X;x)-C^L(X;x))/Z(X)` for satisfying assignments.
Both quotient identities pass, but no witness-independent invertible matrix
mapping the H coefficient vectors follows from the residual identities.
Equality of residuals at constraint roots alone cannot determine these
quotients: the two numerator polynomials may differ by a multiple of `Z`.
The observed all-eight-vector differences and independent Bellman
reproduction of production H for two witnesses are consistent with this
analysis, but do not prove or disprove every possible symbolic map.

#### Official query-section conclusions

The official sections contain IC 8, H 131,071, L 98,638, A 85,390,
B_G1 61,300, and B_G2 61,300 points. The pinned file provides group
elements evaluated at the ceremony's secret point, not the underlying
toxic-waste scalars or polynomial values. In standard notation the sections
encode `A_j(τ)/δ` in G1, `B_j(τ)/δ` in G1 and G2, `H_k=τ^k Z(τ)/δ` in G1,
`L_j=(βA_j(τ)+αB_j(τ)+C_j(τ))/δ` in G1, and
`IC_j=(βA_j(τ)+αB_j(τ)+C_j(τ))/γ` in G1 for the public coordinates.

| Section | Transformation conclusion |
|---|---|
| IC | **Unresolved.** Public-variable identities agree, but a full transform of the combined public query polynomial `(βA_j+αB_j+C_j)/γ` is not available. |
| H | **Unresolved.** The domain and monomial H basis shape are shared, but the coefficient-coordinate transformation is unknown. The direct H accumulation differs for both tested witnesses; this is not proof that no symbolic transform exists. |
| L | **Unresolved.** The dense private query coordinates require the full variable, A/B/C, and helper-coordinate transformation; the helper substitution mixes T, the anchor, and path bits. |
| A | **Unresolved; partial G1 route exists.** The 98,442 factor-matched rows have explicit fixed row-wise A/B maps, including swaps, and A and B_G1 are both G1 sections. No complete transformed polynomial/query-coordinate matrix covers the 333 expanded rows and helper block. |
| B_G1 | **Unresolved; partial G1 route exists.** As for A, the matched row maps can cross-mix A and B in G1, but there is no complete transformation for every variable/query coordinate. |
| B_G2 | **Unresolved with a concrete section gap.** The recorded swapped factor maps require an A contribution when transforming B. The official file has B_G2 but no A_G2 section; G1 points cannot be linearly combined into G2 points. No complete transformation using only the available sections is established. This is a limitation of the demonstrated map, not a proof that every conceivable construction is impossible. |

If a complete constant-field query-coordinate matrix were derived, same-group
query points could be transformed using public linear combinations, without
recovering toxic waste. The present witness-specific accumulations and the
exact residual identities do not provide that matrix. In particular, the
missing A_G2 coordinates cannot be inferred from A_G1/B_G1 points alone by
the established group operations. Exact reproduction of the pinned Bellman
QAP would let the official sections be used in their existing coordinates;
using the unchanged production QAP instead requires either a complete
symbolic six-section transformation or a separately trusted setup bound to
that production matrix.

The Groth16 verifier checks the pairing equation
`e(π_A,π_B)=e(αG1,βG2)·e(IC(x),γG2)·e(π_C,δG2)`, where `IC(x)` is the
public IC accumulation and the proof's `π_A`, `π_B`, and `π_C` include their
respective A/B/H/L contributions. The residual transformations prove the
captured zero sets agree, but do not give transformed query points and proof
accumulators that make both sides of this verifier equation equal. Thus
Groth16 verification-equation preservation under a production-to-Bellman
query conversion remains unverified; the witness-specific matching
accumulations are not a substitute.

**Conclusion:** the captured constraint relations have an explicit
full-rank, pointwise residual transformation, but it contains a
witness-dependent helper-row operation and does not induce a demonstrated
fixed invertible A/B/C/H QAP or six-query transformation. QAP/query
transformation is **Unresolved**, not disproven. No parameter-to-circuit
binding or ceremony-validity conclusion changes; both remain
**Unverified**, and Spend proving remains gated.

**Smallest justified next step:** using only the retained full matrix and
correspondence exports, attempt an exact all-variable polynomial-coordinate
derivation for A/B/C, including explicit factorizations for the 333
expanded rows and a compatible treatment of the helper block. Test whether
it yields constant coefficient maps and whether B_G2 can be produced from
the available official sections. If it cannot, exact Bellman matrix
reproduction or a production-bound trusted setup is the supported path.
Focused algebraic and query-mapping regressions passed **28 tests with
8 subtests in 9.48 s**. No synthesis was repeated; no production code,
Output, setup, parameter, or proving gate changed, and no synthetic setup
regression was run.

### Phase 9.21.48 — Complete expanded-row factor identities

This follow-up used only the retained row-correspondence artifact
(`44a14939955a9a82a24f4013bb0b9144a1810b648d6e4d9d3643117330b58ecc`);
no witness or circuit synthesis was repeated. A test-only verifier expanded
and checked every A/B/C polynomial in all 333 previously classified
expanded-residual pairs. The complete terms, row indices, annotations,
derived identities, and raw residual scales are preserved in
[the factor-identity certificate](sapling-spend-expanded-row-factor-identities.json),
whose SHA-256 is
`be5f65ef3c902b9f2cc707856c0cba4b910efa724680a6989d8abf692cd6b3f8`.
The verifier cross-checks the certificate digest and all 333 exact
finite-field residual and factor identities.

The 333 pairs divide into three exact, witness-independent factor formulas.
Let `U_A,U_B,U_C` denote upstream factors and `L_A,L_B,L_C` the mapped local
factors:

| Rows | Count | Exact factor identity | Raw `F_U/F_L` |
|---|---:|---|---:|
| `pk_d` selection | 251 | `U_A=L_B+ONE`, `U_B=L_A`, `U_C=L_C+L_A`; expansion gives `F_U=F_L`. | `+1` |
| Merkle/scalar linear constraints | 74 (64 Merkle path reconstruction, 10 scalar-representation rows) | `U_A=U_B=0`, `U_C=-L_A`, `L_B=ONE`, `L_C=0`; hence `F_U=F_L=L_A`. | `+1` |
| Unit-B affine rows | 8 | `U_A=λL_A+u`, `U_B=L_B=ONE`, `U_C=λL_C+u`, with `L_C=0` and `u=U_C`; four rows have `λ=+1`, four `λ=-1`. | four `+1`, four `-1` |

Thus 329 raw residuals have scale `+1` and four have scale `-1`. The earlier
“333 unit-scale” count compared *normalized expanded-polynomial signatures*;
it did not establish the raw equation scale. That earlier field is corrected
in the compatibility manifest and explicitly qualified as normalized.
The 74 C-to-A cases are valid residual identities but their row-local map
from the three local factors to the three upstream factors has rank 1, not
3. Accordingly, the identities do not establish an invertible per-row
three-factor coordinate change.

The other 98,442 matched rows retain their existing nonzero diagonal or
anti-diagonal A/B scale maps, with `C_U=αβL_C` and rank-2 A/B blocks.
Together the 98,775 paired residuals are related by a row permutation and
nonzero row scaling: rank 98,775, kernel zero. The raw `-1` rows above are
already included in this count.

The full variable map remains: 8 public/ONE coordinates and 98,637 common
auxiliaries map directly; for the two unmatched helper coordinates, with
`S=Σ(i=0..31)2^i d_i`, use `P=T+S-A` and inverse `T=P-S+A`. This is a
linear bijection on the 98,646-coordinate ambient assignment space, rank
98,646, kernel zero. It accounts for every variable and every row when
combined with the two helper-row factor formulas:

```text
source root:   U_A = L_root_A - L_position_A, U_B = L_root_B, U_C = 0
source anchor: U_A = A, U_B = ONE, U_C = A + L_position_A
```

The helper residual identities remain
`f_root=g_root-V*g_position` and `f_anchor=-g_position`, represented by
`[[1,-V],[0,-1]]`. This is pointwise invertible (rank 2, zero kernel,
determinant `-1`) but still witness-dependent through `V`. The explicit
factor equations therefore improve the coverage of the proposed
transformation; they do not turn this residual operation into a constant
row matrix.

#### Polynomial coordinates, query sections, and verification equation

The certificate now supplies exact factor formulas for every paired row,
and the helper substitution supplies formulas for the remaining rows.
Their coefficients are fixed and witness-independent, but the certificate
does **not** by itself establish an invertible, full-domain polynomial
coordinate transformation. In particular, 74 row-local factor maps are
rank-deficient; the helper residual map is assignment-dependent; and the
expanded formulas include cross-factor terms and fixed `ONE`/variable
shifts. No complete transformed coefficient matrices for A, B, C, or H
were derived, and no global rank/kernel proof for a six-section query
coordinate matrix is available. The normalized signature equality from the
prior phase cannot fill that gap.

| Official section | Phase 9.21.48 conclusion |
|---|---|
| IC | **Unresolved.** Public-variable identities and the variable bijection are known, but no complete transformation of the combined `(βA+αB+C)/γ` query coordinates is derived. |
| H | **Unresolved.** The eight-vector direct-identity mismatch persists in the retained baseline and alternate-witness evidence. No witness-independent H-coefficient map or compatible H-query map has been established. |
| L | **Unresolved.** The variable mapping is complete, but no transformation of the combined private `(βA+αB+C)/δ` coordinates is established. |
| A | **Unresolved.** Exact row-factor formulas now cover all constraints, but the corresponding full polynomial/query-coordinate matrix and any required shift coordinates have not been constructed. |
| B_G1 | **Unresolved.** The same missing full polynomial-coordinate map applies; a row-local factor identity is not a group-query mapping. |
| B_G2 | **Unresolved.** The known A/B-swapped rows require A_G2 contributions in the direct construction, while the official sections do not expose A_G2. This does not disprove every possible alternative transformation. |

Therefore the complete production-to-Bellman polynomial/query transformation
is **Unresolved**, not established or disproven. In particular, the
available data do not establish transformation rank, kernel, invertibility,
and compatibility for all six sections, nor do they establish preservation
of `e(π_A,π_B)=e(αG1,βG2)e(IC(x),γG2)e(π_C,δG2)`. No inference is made about
parameter-to-circuit binding or ceremony validity; both remain
**Unverified**, and Spend proving remains gated.

**Smallest evidence-supported next step:** use the retained complete matrices
and this certificate to construct the explicit global A/B/C coefficient
operators over the 131,072-point domain, including the ONE/variable shift
columns and helper rows; compute their exact rank and kernel; then derive
whether the induced H and six query-section coordinates can be formed from
the official points, especially B_G2 without A_G2. If those exact operators
cannot yield query points, the evidence-supported alternatives remain exact
Bellman matrix reproduction or a separately trusted setup bound to the
production relation.

Verification: the new focused certificate test passed **1 test and 333
subtests in 0.31 s**. No witness synthesis, production change, Output change,
setup/parameter change, proving-gate change, or synthetic setup regression
was performed in this phase.

### Phase 9.21.49 — Global Spend QAP and query-coordinate audit

This read-only derivation uses the retained production and pinned Bellman
matrices, variable correspondence v7, row correspondence, and the complete
expanded-row factor certificate. No Spend witness or Spend circuit synthesis
was performed. The selected query-mapping test module also ran its existing
Output-only QAP rebuild regression (8.04 s). The retained
matrix fingerprints remain production
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9` and
Bellman
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
The 98,777 × 98,646 matrices therefore remain distinct. The retained row
mapping fingerprint is
`f502b0f22dece3829d6e2e1e198ca8d98d82e233e9eb1a4dcded3a399f6ae17d`;
the variable mapping fingerprint is
`26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656`.

#### One global fixed A/B/C factor operator

Let `m=98,777`, `n=98,646`, and write each constraint matrix as an
`m × n` coefficient matrix. Let `x_U` be the pinned-reference assignment
coordinates and `x_L=M x_U` the local coordinates. The map `M` is identity
on the 8 public/ONE and 98,637 common auxiliary coordinates, with
`P=T+Σ(i=0..31)2^i d_i-A` for the two unmatched helpers. Its inverse is
`T=P-Σ(i=0..31)2^i d_i+A`; thus `M` has rank 98,646 and zero kernel.

Stack the local matrices as
`Q_L=[Q_A,L; Q_B,L; Q_C,L] ∈ F^(3m×n)`. The paired-row order, factor
scalings, factor swaps, 333 expanded-row identities, and two helper rows
define a fixed sparse `R ∈ F^(3m×3m)` and a fixed variable-shift matrix
`S ∈ F^(3m×n)` such that

```text
Q_U = R Q_L M + S
```

`R` includes the recorded row permutation. This equation is coefficient
identity over the whole assignment space, not a witness-specific fit. The
98,442 ordinary factor-matched rows were checked directly against all
retained A/B/C terms: **98,442 verified, 0 mismatches**. Their maps are:

```text
same orientation:     U_A=αL_A, U_B=βL_B, U_C=αβL_C
swapped orientation:  U_A=αL_B, U_B=βL_A, U_C=αβL_C
```

All their two-factor blocks are invertible. Exact observed profiles are
69,840 identity rows; 251 unsized swaps with `α=β=1`; 18,754 swapped
normalizations `α=-1, β=1`; 9,533 swapped normalizations
`α=2, β=(p+1)/2`; and 64 same-orientation normalizations `α=-1, β=1`,
where `p` is the scalar-field modulus. In every case `U_C=αβL_C`.

The other paired rows use the verified formulas:

| Class | Count | `R` block and shift | Factor-block rank |
|---|---:|---|---:|
| `pk_d` selection | 251 | `U_A=L_B+ONE`, `U_B=L_A`, `U_C=L_C+L_A` | 3 |
| Linear-to-C | 74 | `U_A=U_B=0`, `U_C=-L_A`, `L_B=ONE`, `L_C=0` | 1 |
| Unit-B affine | 8 | `U_A=λL_A+u`, `U_B=L_B=ONE`, `U_C=λL_C+u`, `L_C=0`; four `λ=1`, four `λ=-1` | 3 |

The two helper rows are included by cross-row factor equations:

```text
source root:   U_A=L_root_A-L_position_A, U_B=L_root_B, U_C=0
source anchor: U_A=A, U_B=ONE, U_C=A+L_position_A
```

`S` contains the explicit `ONE`, `u`, anchor, and ONE shifts in these
identities. The extended map is fixed; the entries of `S` are coefficients
of named variables, not witness values. The `u` vectors and every term for
the 333 rows are retained in the
[factor certificate](sapling-spend-expanded-row-factor-identities.json).

The exact ranks for this constructed operator are:

| Operator | Domain → codomain | Rank | Kernel | Left nullity |
|---|---:|---:|---:|---:|
| Factor-only `R` | 296,331 → 296,331 | 296,180 | 151 | 151 |
| Extended `[R S]` | 394,977 → 296,331 | 296,182 | 98,795 | 149 |

The ranks follow from the row blocks: `R` has rank
`3·98,442 + 3·251 + 74 + 3·8 + 3 = 296,180`. The helper pair contributes
rank 3 in `R` and rank 5 after its two independent anchor/ONE shifts are
included. The 74 C-to-A rows each lose two factor coordinates; the source
root C coordinate in the helper pair is identically zero. The augmented
operator therefore remains non-surjective and non-invertible. These are
ranks of the extended factor-coordinate operator with factor and appended
variable coordinates treated as independent—not the rank of the assignment
map `M`, and not a proof that no different global operator could exist.

#### Induced A/B/C evaluation vectors and polynomials

For each factor side `t∈{A,B,C}`, partition `R` into `m×m` blocks `R_ts`
and `S` into `m×n` blocks `S_t`. For every upstream-coordinate assignment
`x_U`, the constraint-row evaluations are exactly

```text
q_U,t(x_U) = Σ(s∈{A,B,C}) R_ts Q_L,s M x_U + S_t x_U
```

so the A, B, and C evaluation-vector transformations are fixed, linear in
`x_U`, and valid for arbitrary assignments. Their transformations include
cross-side terms (A may depend on local B or C) and fixed shift terms; they
are not three independent diagonal scalings.

The standard Spend QAP has `N=131,072`, 98,777 constraint rows, 8 input
dummy rows, and 32,287 zero-padding rows. Let `E` embed the constraint rows
into the first `m` evaluation slots, `D_U,t` hold the unchanged dummy-input
rows and padding, and `W[i,j]=ω^(ij)` be the invertible domain evaluation
matrix. The complete coefficient-family equation for each factor is

```text
P_U,t = W^-1 ( E ( Σ_s R_ts Q_L,s M + S_t ) + D_U,t )
```

and the local family is `P_L,s=W^-1(E Q_L,s+D_L,s)`. This is the induced
fixed forward polynomial-coordinate formula for A/B/C, including all
constraint rows, public-input coordinates, helpers, and padding. It is
non-invertible on the factor-coordinate space: interpolation by `W^-1`
cannot recover the 149 missing constraint-factor coordinates. This derives
the forward A/B/C transformation; it does not yield an inverse mapping from
the available official query points to the local query points.

#### H quotient and the helper residual obstruction

For satisfying `x_U`, define the source factor polynomials by the preceding
operator and then

```text
A_U(X;x)=Σ_j x_U,j P_U,A,j(X)
B_U(X;x)=Σ_j x_U,j P_U,B,j(X)
C_U(X;x)=Σ_j x_U,j P_U,C,j(X)
H_U(X;x)=quo_(Z)(A_U(X;x)B_U(X;x)-C_U(X;x)),  Z=X^N-1
h_eval_U=W H_U
```

This gives the exact H evaluations and coefficients as a quadratic
construction from the fixed A/B/C operators. It is not a fixed linear map
`H_U=T_H H_L`. The direct identity map is disproved by the retained baseline
and `zero-value-alternating` comparisons, whose H vectors and official H
accumulations differ. No other fixed H-coordinate matrix has been proved or
disproved. Quotient divisibility applies to satisfying assignments; an
arbitrary assignment can have a nonzero remainder.

The helper term `-V` can be removed from the *factor operator* by the fixed
cross-row A/C equations above, but not from a constant linear transformation
of the two residual coordinates. With source residuals
`f_root=(R-T)V`, `f_anchor=A-T` and local residuals
`g_root=(R-A)V`, `g_position=P-S`, the exact relation is

```text
[g_root,g_position]^T = [[1,-V],[0,-1]] [f_root,f_anchor]^T
g_root = f_root - V*f_anchor
g_position = -f_anchor
```

The 2×2 map has pointwise rank 2 and determinant `-1`, but its off-diagonal
coefficient varies with `V`; no constant helper-only residual matrix can
represent it over the assignment space. The fixed factor construction
generates the same product through `U_A(root)=L_A(root)-L_A(position)`.
Thus the witness-dependent residual coefficient is explained, not
reinterpreted as a fixed residual-row operation. The factor construction
remains rank-deficient as quantified above.

#### Official query sections and Groth16 equation

The official file has IC 8, H 131,071, L 98,638, A 85,390, B_G1 61,300,
and B_G2 61,300 points. The existing direct-accumulation evidence remains
witness-specific: five non-H sections match under direct mapping for the
baseline fixture; H differs for both baseline and alternate fixtures. These
observations do not establish query-vector equivalence.

| Section | Global-map result |
|---|---|
| IC | **Unresolved.** Public coordinates retain their identities, but no complete map of the combined `(βA+αB+C)/γ` group points is derived. |
| H | **Unresolved.** The QAP quotient is computable by the quadratic formula above, but no fixed linear H-query operator is established; identity accumulation fails for both retained witnesses. |
| L | **Unresolved.** The private `(βA+αB+C)/δ` coordinates have no proven group-point transform under the extended, non-invertible factor map. |
| A | **Unresolved.** The fixed forward A polynomial map is derived, but the official source A_G1 section cannot be inverted through the rank-deficient global factor map; C_G1 is not provided as a separate section. |
| B_G1 | **Unresolved.** No complete inverse map from the official A_G1/B_G1 points handles the missing factor coordinates and shifts. |
| B_G2 | **Unresolved.** The direct inverse construction for swapped rows requires A_G2 points. The official file has B_G2 but no A_G2 section, and G1 points cannot supply G2 points. |

Public linear combinations could implement a known same-group query matrix,
but the required inverse maps and group points are not available. In
particular, the official L/IC points combine A, B, and C using toxic setup
scalars; the file does not expose a standalone C query or those scalars.
The rank deficiency is an obstruction to inverting this constructed
factor operator, not a proof that every possible transformation is
impossible.

The required verification equation is
`e(π_A,π_B)=e(αG1,βG2)e(IC(x),γG2)e(π_C,δG2)`. No complete transformation of
the A/B/H/L/IC query contributions or proof coordinates is available, so
preservation of either side of this equation is **Unresolved**. The public
input indices are preserved, but that alone does not preserve the IC
accumulation. Parameter-to-circuit binding and ceremony validity remain
**Unverified**.

**Conclusion:** a complete, witness-independent *forward* A/B/C coefficient
operator is established in the form `Q_U=R Q_L M+S`, and it accounts for all
rows and variables. It is not invertible (factor rank 296,180 of 296,331;
extended rank 296,182), and it does not establish a fixed linear H map or
any of the six official group-query mappings. The requested complete global
QAP/Groth16 transformation is therefore **Unresolved**, not established or
disproven.

**Smallest justified next step:** attempt an exact full-span query-coordinate
map that accounts for the 149-dimensional constraint-factor cokernel,
produces the needed A_G2 and L/IC combined contributions from available
public points, and supplies a fixed H-coordinate operator. If no such map
can be derived from the retained data, the supportable path is exact
Bellman-matrix reproduction or a separately trusted setup bound to the
production matrix. No toxic-waste recovery, parameter binding, or ceremony
validity can be inferred from this algebra.

The retained 98,442-row factor check passed with **0 mismatches in 2.513 s**.
The focused algebraic and query-mapping suite passed **50 tests and 346
subtests in 9.89 s**. `compileall`, JSON parsing, targeted Ruff E4/E7/E9/F,
and `git diff --check` passed. No Spend synthesis, production change, setup
change, parameter change, proving-gate change, or synthetic setup regression
was performed. The final focused rerun excluded the existing Output-only QAP
rebuild test and passed **49 tests and 346 subtests** (1 deselected) in
**1.97 s**.

### Phase 9.21.50 — Spend factor-map kernel and quotient spaces

This exact finite-field analysis reuses the retained factor identities,
variable map, and two helper equations; no Spend synthesis was performed.
Use row-major factor coordinates `(row,A/B/C)` for both local input factors
and upstream output factors, followed by upstream variable coordinates for
the augmented operator. All arithmetic is in the BLS12-381 scalar field.
The canonical sparse-basis encoding, shapes, ranks, and SHA-256 fingerprints
are recorded in the
[compatibility manifest](sapling-circuit-compatibility-manifest.json) and
recomputed by the focused kernel-certificate test.

The 98,442 ordinary factor blocks, 251 `pk_d` blocks, and 8 unit-B affine
blocks are invertible. Each of the 74 linear-to-C blocks has
`R_i=[[0,0,0],[0,0,0],[-1,0,0]]`, rank 1, right kernel
`span(e_B,e_C)`, and left kernel `span(e_A,e_B)`. The two-row helper block,
with local columns `(root A/B/C, position A/B/C)` and upstream rows
`(root A/B/C, anchor A/B/C)`, is

```text
R_h = [[1,0,0,-1,0,0],
       [0,1,0, 0,0,0],
       [0,0,0, 0,0,0],
       [0,0,0, 0,0,0],
       [0,0,0, 0,0,0],
       [0,0,0, 1,0,0]]
```

Its rank is 3, right kernel is `span(e_rootC,e_positionB,e_positionC)`,
and left kernel is `span(e_rootC,e_anchorA,e_anchorB)`. Thus
`dim ker(R)=dim ker(R^T)=74*2+3=151`; the block ranks sum to
`3*98,442 + 3*251 + 74 + 3*8 + 3 = 296,180`.
The helper coordinates are local root row 76894, local position row 32701,
upstream root row 76893, and upstream anchor row 76894. The 74 linear-to-C
row coordinates are taken directly from the 333-row certificate.
The 151 right-kernel directions are exactly lost input factor directions;
the 151 left-kernel directions are output linear functionals that vanish
throughout `im(R)`.

The two helper variable shifts add two independent output directions modulo
`im(R)`: the public anchor shift in helper anchor-A and the `ONE` shift in
helper anchor-B. The other helper anchor-C shift is in the image of `R`;
the `pk_d` and unit-B affine shifts also lie in the images of their
full-rank blocks. The helper augmented block is the displayed `R_h` with
columns for public anchor and `ONE` appended; its exact rank is 5, versus 3
for `R_h`. Therefore
`rank([R S])=296,182`, `dim ker([R S])=394,977-296,182=98,795`, and
`dim ker([R S]^T)=296,331-296,182=149`. The two added rank directions are
explained by the actual affine helper shifts, not a row-map provenance
anomaly.

The augmented right-kernel basis consists of the 151 embedded `ker(R)`
vectors and one vector `(z_j,e_j)` for each variable coordinate `j` except
`ONE` (index 0) and public anchor (index 5). For each such coordinate,
`z_j` is zero except at unit-B rows, where its local A and C entries are
`-u_j/lambda`; this cancels `S e_j` because `lambda` is nonzero. The two
excluded coordinates have independent nonzero projections into the helper
cokernel. The augmented left-kernel basis consists of the 148 linear-to-C
left-null vectors plus helper root-C; the two helper anchor-A/B null
directions are removed by those shifts. These compact generators produce
all four bases; each vector was directly multiplied by the applicable
operator or transpose modulo the field. Rank-nullity and their distinct
pivot coordinates prove independence and completeness. The four basis
fingerprints are `97a958fd…80003`, `c93683bd…e14f5`,
`060132ce…c02db`, and `3e57545e…4ed1`, respectively; the manifest stores
the full SHA-256 values and canonical basis specification.

The quotient-space result is exact but does not restore full-space
invertibility:

```text
F^296331 / ker(R)  --R--> im(R)                 is a bijection (dimension 296180)
F^394977 / ker([R S]) --[R S]--> im([R S])      is a bijection (dimension 296182)
```

Neither image is the full 296,331-dimensional output factor space; the
cokernel dimensions are 151 and 149. Thus the fixed forward A/B/C
coefficient formulas remain valid and witness-independent, while recovering
arbitrary local factor coordinates from upstream coordinates is impossible
through this operator. Whether `ker(R)` intersects the particular span of
the retained local QAP coefficient-family columns was not evaluated here;
the ambient rank alone does not settle injectivity on that restricted span.
Interpolation on the `N=131,072` domain is invertible, so it preserves these
factor-space rank and image conclusions; it neither supplies the missing
directions nor an inverse query map.

No fixed H-coordinate transformation follows from these kernel results.
For satisfying assignments the uniform construction is

```text
H_U(X;x) = quo_(X^N-1)(
  [Σ_s R_As F_L,s(X;M x) + S_A x]
  [Σ_s R_Bs F_L,s(X;M x) + S_B x]
  - [Σ_s R_Cs F_L,s(X;M x) + S_C x]
)
```

where `F_L,s(X;M x)` are the local A/B/C polynomials. This fixed, assignment-
uniform quadratic formula recomputes upstream H from local factor families
and `x`; it is not a fixed linear coordinate map from `H_L` alone, and it
does not imply a Groth16 H-query transform. Quotient divisibility is only
guaranteed for satisfying assignments. The two retained witness mismatches
disprove only the direct identity map, not all fixed maps on a restricted
image.
The six official sections IC, H, L, A, B_G1, and B_G2 remain
**Unresolved**; no complete map preserving the Groth16 verification
equation has been derived. In particular, a forward polynomial-family map
does not provide missing group-query coordinates or prove
parameter-to-circuit binding.

**Conclusion:** the established factor map does induce a complete,
witness-independent *forward A/B/C* transformation and an isomorphism
between the corresponding quotient domain and image. The requested complete
QAP/H/Groth16 transformation is **Unresolved**, not established or
mathematically obstructed by the kernel alone.

**Smallest justified next step:** compute the exact intersection of
`ker(R)` with the column span of the retained local A/B/C coefficient-family
matrix, and test for a fixed restricted left inverse. This is a read-only
finite-field calculation on retained matrices; it requires no synthesis.
Only if that restricted map is injective should work proceed to an exact H
quotient-coordinate map and all six group-query sections.

Verification: the focused factor-kernel, QAP, expanded-factor, query-mapping,
and compatibility suite passed **40 tests and 346 subtests**, with one
Output-only QAP rebuild test deselected, in **5.02 s**. The kernel test took
**3.21 s** and directly checked the four sparse bases, their fingerprints,
and helper ranks 3 and 5. Compile checks, JSON parsing, targeted Ruff E4/E7/E9/F,
and `git diff --check` passed. No Spend synthesis, production or Output
change, setup/parameter change, proving-gate change, or synthetic setup
regression was performed. After the final report/manifest edits, the kernel
and compatibility-manifest rerun passed **20 tests and 5 subtests in
3.24 s**.

### Phase 9.21.51 — Restricted inverse on the Spend QAP factor-family span

This phase uses only the retained production matrix, row correspondence,
factor-identity certificate, and variable map. No Spend synthesis or
production circuit change was performed. All linear algebra is exact over
the BLS12-381 scalar field.

Let `Q_L` be the stacked local A/B/C factor-coefficient matrix, with
row-major `(constraint,A/B/C)` factor coordinates and one column per
production variable. It has shape `296,331 × 98,646`, 564,245 nonzeros,
rank 98,646, and fingerprint
`28f61fae36f26c92e5bdd0be365db771a232ca9e6a32d0a9aac90e5dfd168d7c`.
The fixed factor operator gives `R Q_L`, shape `296,331 × 98,646`, with
564,324 nonzeros, rank 98,646, and fingerprint
`5f0d1f2527be2ec5423093d5ee46569f72fa28a513aaffa6616f3cb4e7c63b4e`.
Consequently,

```text
dim(ker(R) ∩ col(Q_L))
  = rank(Q_L) - rank(R Q_L)
  = 98,646 - 98,646
  = 0.
```

The empty intersection basis has canonical fingerprint
`5ca8a26614342463c1a25680db98966b1fb6e8a70fcef19cbeb485e2865a0318`.
This proves injectivity of `R` on the actual retained coefficient-family
span, not on the ambient 296,331-dimensional factor space. It does not
contradict the ambient 151-dimensional kernel characterized in Phase
9.21.50.

The exact restricted left inverse is provided in sparse factorized form:

```text
K = Q_L U Pi T^-1 P
U = I - E_(5,32621),   U^-1 = I + E_(5,32621)
T = P (R Q_L) U Pi
```

`Pi` orders the 98,646 columns by ascending pivot factor-coordinate; `P`
selects those pivot rows. `T` is lower triangular, has 241,795 nonzeros,
determinant 1, and fingerprint
`d06444c75adac3c8a0ce47134e9e32ad00421e53dd48598e4a87a4ef77b9da75`.
The `U` fingerprint is
`a38c44d96d24a3677f57310bfe5f412cf13d5a6ca03e49955a414c08a9b332a7`;
the pivot-row and column-permutation fingerprints are
`116bc7e9c3b72161c0524b308bfdee4735b97b3eb03d372e7402880a2abdc19c`
and `b03871a688dd72efaef50f8a8dfce150ef23f819a5ee61f151a830c63f17c295`.
The complete factorized-operator fingerprint is
`105b77e87dc07bccdbbd0ccfbf36fc4e094957d4ddc712a1f3e6f3718d9be87e`.

The rank certificates use a first-pivot minor of determinant 1 for `Q_L`
and a single exact column reduction for `R Q_L` (column 32,621 reduces
against column 5 at pivot coordinate 230,679 with scale 1). The triangular
identity `P (R Q_L) U Pi = T` was directly verified over all 98,646
coefficient-family columns. Since `T` has nonzero diagonal and `U`, `Pi`
are invertible, this establishes `K R Q_L = Q_L`; the construction
therefore recovers every vector in `col(Q_L)` from its image under `R`.
It is a factorized inverse certificate, not a materialized dense 296,331
square matrix and not a left inverse on arbitrary factor vectors.

The affine identity from Phase 9.21.49 is
`Q_U = R Q_L M + S`, where `M` is the established variable bijection and
`S` contains helper shifts. The inverse must be applied after subtracting
the offsets:

```text
K (Q_U - S) = K R Q_L M = Q_L M.
```

The public-anchor and `ONE` helper shifts are retained in `S` and must not
be dropped or absorbed into `R`. This exact affine application follows from
the retained all-row factor identities and the directly verified
restricted-left-inverse identity. The reusable computation is
[sapling_spend_factor_span.py](../tests/sapling_spend_factor_span.py);
input artifact hashes, component fingerprints, and checks are recorded in
the [compatibility manifest](sapling-circuit-compatibility-manifest.json).

For QAP coefficient families, apply the inverse interpolation transform,
remove the agreed dummy/padding coordinates, subtract `S`, then apply `K`.
This yields a fixed, witness-independent inverse on the retained A/B/C
family span. The ambient factor map remains singular, and this result does
not identify the canonical production and Bellman matrix rows or assert
equality of their eight previously compared witness-specific canonical QAP
vectors. It also does not give a fixed linear map from `H_L` to `H_U`:
the quotient still must be constructed from the transformed A/B/C
polynomials and assignment, and divisibility is guaranteed only for
satisfying assignments.

No map has been established for the official `IC`, `H`, `L`, `A`,
`B_G1`, or `B_G2` query vectors. In particular, a restricted scalar
coefficient-family inverse does not provide missing group-query
coordinates, establish query-vector transformations, or demonstrate
preservation of the Groth16 verification equation. Parameter-to-circuit
binding and ceremony validity remain **Unverified**.

**Conclusion:** the restricted A/B/C coefficient-family inverse is
**Established** for the retained production span, with zero kernel
intersection and a directly checked exact sparse factorization. Complete
polynomial H and six-section Groth16 query compatibility remain
**Unresolved**; full matrix/QAP identity is not claimed.

**Smallest justified next step:** derive exact induced coordinate
transformations for the official query vectors from this restricted
coefficient map, including the affine/helper offsets and all six sections,
and verify preservation of the combined Groth16 verification equation.
If group-query coordinates cannot be derived from the retained setup
material, exact Bellman matrix reproduction or a production-bound trusted
setup remains necessary.

Verification: the retained-input certificate generator reproduced the
rank, intersection, sparse inverse, and fingerprints, directly checking the
triangular identity across all 98,646 columns in **8.093 s**. Focused
regressions passed: factor-kernel/restricted-inverse **2 tests in 2.991 s**,
QAP transformations **7 tests in 0.005 s**, and compatibility manifest
**19 tests in 0.127 s** (28 tests total). Python compileall, Pylance syntax
checks for both changed Python files, manifest JSON parsing, targeted Ruff,
and `git diff --check` passed. No Spend synthesis was run.

### Phase 9.21.52 — Restricted Spend H-coordinate transformation assessment

This phase assesses whether the restricted factor inverse from Phase 9.21.51
induces a fixed linear transformation of H quotient coordinates. It reuses
the retained factor map, variable/helper correspondence, and recorded
baseline/alternate QAP fingerprints. It performs no Spend synthesis and
does not touch any official query points.

For `N=131,072`, let `W` be the evaluation matrix on the retained root order,
`E` embed the 98,777 constraint rows, and `D_t` supply the eight unchanged
input-dummy entries and zero padding. With `x_L=M x_U`, the exact A/B/C
polynomial-family relation is

```text
P_L,s = W^-1 (E Q_L,s + D_L,s)
P_U,t = W^-1 (E (Σ_s R_ts Q_L,s M + S_t) + D_U,t),
          t,s ∈ {A,B,C}.
```

Thus `W` is invertible on all 131,072 A/B/C coordinates, and the restricted
factor inverse recovers the 98,646-column local family after inverse
interpolation, removal of dummy/padding entries, and subtraction of `S`.
This is the exact witness-independent A/B/C transformation. `K` itself acts
on the stacked `296,331` row-factor coordinates; it is not an operator on
the `131,071` H coefficients.

For a satisfying assignment define

```text
A_U(X;x)=Σ_j x_U,j P_U,A,j(X)
B_U(X;x)=Σ_j x_U,j P_U,B,j(X)
C_U(X;x)=Σ_j x_U,j P_U,C,j(X)
H_U(X;x)=(A_U(X;x)B_U(X;x)-C_U(X;x))/(X^N-1),
```

and analogously for the local system with `x_L=M x_U`. The exact quotient
coordinate relation established by the factor map is therefore the fixed
quadratic recomputation

```text
h_U(x_U) = quotient_N(
  [Σ_j x_U,j P_U,A,j] [Σ_j x_U,j P_U,B,j]
  - Σ_j x_U,j P_U,C,j
).
```

The same-domain evaluation coordinates are `W h_U`; H uses ascending
coefficient order `0..131,070`, while its evaluation vector has 131,072
entries. Divisibility is guaranteed only for satisfying assignments.

A fixed linear H-coordinate map would be a matrix
`T_H ∈ F^(131071×131071)` satisfying
`h_U(x_U)=T_H h_L(M x_U)` for every satisfying assignment. For an identity
over the full assignment space, this requires every degree-at-most-two
coefficient vector of the upstream quotient to equal `T_H` times the
corresponding local vector (linear terms can be homogenized using the fixed
`ONE` coordinate). The restricted inverse establishes no such tensor
factorization: it recovers the three factor families before their
multiplication and quotient, not the result of that nonlinear operation.
The exact coefficient-tensor factorization test has not been performed, so
existence or nonexistence of a separate fixed `T_H` remains **Unresolved**.
Accordingly, no H-map rank, kernel, invertibility result, or fingerprint is
claimed.

The helper residual identity
`[g_root,g_position]^T=[[1,-V],[0,-1]][f_root,f_anchor]^T` has a
witness-dependent `-V` coefficient and rules out a constant helper-only
residual-row map. The already established fixed cross-row A/B/C operator
and affine matrix `S` account for the helper factors. The `-V` term is
therefore a proven obstruction to that narrow residual map, but has not been
shown to be the sole obstruction to a linear H-coordinate transformation.
More generally, multiplication of the transformed A/B factors creates
quadratic mixed terms; applying `K` before that multiplication does not
reduce them to a linear operation on `H_L`.

The retained baseline fingerprints record Bellman/production H coefficients
`27d57fc5…4037a55` / `a98ecf08…850862` and H evaluations
`b7ee1b2f…23bb7d` / `04d75e39…30f65c7`. The
`zero-value-alternating` record gives coefficients
`38d0b985…24f8bed` / `604aaeb5…fa5075f` and evaluations
`a5ac5c82…d90d83db` / `62dc36d1…1560f49`. In both recorded cases, the
Bellman and production H vectors differ, which disproves the identity map
only; it does not disprove another linear map. These are retained
fingerprints, not raw vector exports. In particular, the alternate-QAP test
writes its trace and QAP vectors into a `TemporaryDirectory` cleaned at
teardown. This phase did not independently recompute the raw baseline or
alternate vectors and did not repeat synthesis. Therefore the requested
baseline/alternate verification is limited to the exact previously recorded
fingerprints.

**Conclusion:** the restricted A/B/C inverse induces an exact
witness-independent quadratic recomputation of upstream H from transformed
A/B/C factors and the assignment. A fixed linear H-coordinate
transformation is **Unresolved**—neither established nor disproven. The
retained witness hashes reject the identity map only. The H-query
point transformation and Groth16 verification equation were not assessed,
as required because no fixed linear H map has been established.

**Smallest justified next step:** derive a sparse exact representation of
the local and upstream symmetric quadratic coefficient families for H, then
solve the finite-field factorization equation for a single
`131,071×131,071` `T_H`. A successful solve needs direct rank/kernel and
all-coefficient verification; a failure needs an exact inconsistency
certificate. That symbolic test can decide existence without witness
synthesis. If baseline/alternate empirical checks are still required,
recover the prior raw QAP exports; the current saved hashes alone are not
sufficient to replay those vector comparisons.

Verification: focused factor-kernel/H-assessment tests passed **3 tests in
3.216 s**, QAP transformation regressions passed **7 tests in 0.012 s**, and
compatibility-manifest regressions passed **19 tests in 0.128 s** (29 total).
Python compileall, Pylance syntax, manifest JSON parsing, targeted Ruff, and
`git diff --check` passed. No Spend synthesis or query-point transformation
was run.

### Phase 9.21.53 — Exact coefficient-tensor criterion for a Spend H map

This phase makes the existence test precise over the BLS12-381 scalar field.
It uses the retained QAP matrix exports, factor certificate, and variable
map; no circuit synthesis or setup/query operation was performed.

For `N=131,072`, write the ascending-degree factor polynomials as
`A(X;x)=Σ_{r=0}^{N-1}a_r(x)X^r` and
`B(X;x)=Σ_{s=0}^{N-1}b_s(x)X^s`. For `0≤k<N-1`, Euclidean division by
`Z=X^N-1` gives the exact quotient-coordinate formula

```text
h_k(x) = [X^(N+k)] (A(X;x)B(X;x)-C(X;x))
       = Σ_(r+s=N+k) a_r(x)b_s(x).
```

`C` has degree below `N` and therefore does not enter the high-degree
quotient coefficients; it enforces divisibility for satisfying assignments.
The evaluation vector is `W h`, with a zero coefficient at degree `N-1`
before the 131,072-point FFT.

Fix `ONE=1` and let the other 98,645 coordinates be `w`. Each `a_r` and
`b_s` is affine-linear in `w`; consequently `h(w)` has degree at most two.
Let `C_L` and `C_U` denote the matrices whose rows are the 131,071 quotient
coordinate polynomials and whose columns are the 4,865,565,981 monomials of
degree at most two, after applying `x_L=M x_U` to the local family. A single
fixed linear map exists on the full affine assignment space **if and only
if**

```text
C_U = T_H C_L
equivalently rowspace(C_U) ⊆ rowspace(C_L)
equivalently rank([C_L; C_U]) = rank(C_L).
```

This is the necessary-and-sufficient finite-field tensor-factorization
condition. The satisfying-assignment-only question is weaker: every
coordinate of `h_U-T_H h_L` must vanish on the entire satisfying-assignment
set. The baseline and alternate fingerprints alone cannot establish that
condition or a full-space tensor factorization.

The retained files contain the baseline local and Bellman matrix/witness
exports and the factor certificates, but not materialized `C_L`/`C_U`
tensors or raw alternate QAP vectors. A dense representation would contain
`637,734,598,695,651` field entries (over 20 PB at 32 bytes per entry).
No structured exact row-space solver or coefficient-tensor reduction has
been run, and no exact finite-field counterexample has been found. Thus
existence remains **Unresolved**, not established or disproven. No
`T_H`, rank, kernel, image, invertibility result, or fingerprint is claimed.
The factor-family inverse remains valid only on its 98,646-dimensional
retained A/B/C span and supplies no missing H tensor certificate.

The helper residual `-V` is an obstruction to a constant helper-only
residual-row map, but `C` does not appear in the quotient coefficient formula
above. The `-V` term is not itself a demonstrated obstruction to H tensor
factorization; the factorization differences in the A/B families and their
mixed quadratic terms must be tested directly.

**Conclusion:** the exact necessary-and-sufficient condition is recorded,
but the requested existence computation is **Unresolved**. The previously
recorded baseline and `zero-value-alternating` hashes still disprove only
the identity map. The official H query points and Groth16 verification
equation were not examined.

**Next justified step:** implement a structured exact finite-field
row-space/factorization test for `C_U` versus `C_L`, exploiting the
high-convolution and sparse A/B coefficient operators rather than
materializing the tensors. Return either a verified `T_H` representation or
an exact row-space inconsistency certificate. For the satisfying-set-only
claim, separately certify vanishing modulo the complete R1CS solution
variety. Only if a fixed `T_H` is established should its action on official
H query points be considered.

Verification: factor-kernel/H-tensor assessment passed **3 tests in
3.071 s**, Spend QAP transformations **7 tests in 0.006 s**, generic Groth16
QAP math **11 tests in 0.006 s**, and compatibility manifest **19 tests in
0.148 s** (**40 tests total**). Compileall, Pylance syntax, JSON, targeted
Ruff, and `git diff --check` passed. No synthesis or query-point operation
was run. The tensor factorization itself remains **Unresolved** and was not
counted as a passed computation.

### Phase 9.21.54 — Structured exact Spend H-map algorithm assessment

This phase evaluates exact full-affine algorithms from the retained sparse
local and Bellman matrix exports, row correspondence, and factor certificates.
It performs no circuit synthesis, Bellman export, setup operation, or
H-query-point analysis. The existence decision remains **Unresolved**; no
solver or certificate is claimed.

For `N=131,072`, define the coefficient vectors of the interpolated A and B
polynomials by affine forms `a_r(z)` and `b_s(z)`, where `z` contains the
fixed `ONE=1` coordinate and all 98,645 free assignment coordinates. Every
high-degree quotient coefficient is exactly

```text
h_k(z) = sum_(r+s=N+k) a_r(z)b_s(z),  0 <= k < N-1.
```

Reindexing `i=N-1-r` gives
`h_k=sum_(i=0..N-2-k) a_(N-1-i)b_(i+k+1)`. This is a shifted
cross-correlation (anti-diagonal convolution) in the *polynomial-degree
indices*. It proves a triangular convolution structure for each quadratic
form, with `N-1-k` factor products in coordinate `k`. It does not imply that
the monomial-coordinate tensor is globally Toeplitz/Hankel or low rank:
its entries also contain the retained A/B variable coefficient vectors.
The `C` family is absent from these high coefficients because its degree is
below `N`; it remains necessary for divisibility on satisfying assignments.

The retained matrices confirm sparse evaluation-domain factor inputs, not a
sparse expanded H tensor. The local export has A/B/C term-occurrence counts
`258,843 / 118,737 / 186,665`; the Bellman export has
`312,166 / 99,918 / 212,492`. Maximum terms in one local A/B/C row are
`577 / 64 / 235`, and in one Bellman row `688 / 64 / 256`. The factor
coefficient sequences are obtained by exact inverse FFT of these row
evaluations (with Bellman's dummy input rows). No retained artifact verifies a
further sparse, low-rank, Kronecker, or shared-subspace decomposition of the
full quadratic coefficient tensors. The 333 expanded factor identities and
the restricted inverse concern the A/B/C factor coordinates; neither is an
H-tensor factorization.

Exact-method assessment:

| Method | Exact full-affine decision? | Bottleneck / certificate |
|---|---|---|
| FFT/convolution evaluation | Evaluates `h(x)` exactly for a supplied assignment in `O(N log N)` field operations; does not decide tensor row-space inclusion. | It probes only homogenized rank-one monomial inputs. Deterministic interpolation over all pairs would require processing 4,865,565,981 monomials, each with a 131,071-coordinate output, absent additional structure. |
| Structured `C`/`C^T` products | The formula gives exact implicit products. Lift monomial weights to a symmetric matrix `Q` on the homogeneous coordinates (duplicating each off-diagonal monomial weight); then `(C Q)_k` is a sum of bilinear contractions `a_r^T Q b_s` over `N(N-1)/2 = 8,589,869,056` anti-diagonal pairs. General dense `Q` has no verified low-rank representation. | `C^T y` has 4,865,565,981 field coordinates (at least 155.7 GB at 32 bytes each). The formulas are exact, but do not give a feasible matrix-free Krylov product or independently checkable inclusion certificate. |
| Incremental sparse/block elimination | A deterministic scan of every monomial column would decide the stacked-matrix rank condition over the exact field. | It must visit up to 4,865,565,981 columns. A dense basis over the 262,142 stacked output coordinates can require about 2.20 TB at 32 bytes per entry; evaluation sparsity is not a certificate that elimination remains sparse. |
| Symbolic polynomial identity / factorization | A proposed `T_H` can be checked by proving equality of every quadratic coefficient, including constant and linear terms. An exact inconsistency certificate could prove nonexistence. | No compressed candidate for `T_H` or exact identity engine is derived. A dense `T_H` contains 17,179,607,041 field entries (about 549.7 GB); direct coefficient verification remains infeasible without further structure. |

These are algorithmic limits of the investigated representations, not a
mathematical proof that a map does or does not exist. Random sampling,
floating-point rank, and witness fingerprints were not used as substitutes
for an exact decision. No bounded deterministic algorithm with practical
resource bounds and a verifiable output certificate was established, so no
partial solver was added.

The satisfying-assignment question is separate. Its exact domain is the
finite-field set of all mapped assignments with `ONE=1` satisfying every
retained R1CS equation on both sides (with the established helper projections).
The restricted-domain condition is that every coordinate of
`h_U(x)-T_H h_L(Mx)` vanish on that entire set, equivalently on its complete
finite-field vanishing ideal. The retained one- and two-witness fingerprints
do not characterize that set; no ideal-membership computation was attempted.

**Conclusion:** the degree-index convolution reduction is established, but
the full affine row-space inclusion computation and the satisfying-domain
question remain **Unresolved**. No exact transformation, counterexample,
rank, kernel, or tensor fingerprint is claimed. No H-query-point work was
performed.

**Smallest justified next step:** derive and independently verify a
compressed representation for the bilinear coefficient contractions that
supports exact arbitrary-monomial-space elimination (or a structurally
restricted candidate `T_H` with an exact all-coefficient identity check).
Until such a representation has explicit memory/time bounds and a
certificate verifier, retain the unresolved status rather than launching a
full tensor scan.

Verification: the focused factor-kernel, Spend QAP transformation, and
compatibility-manifest tests passed **29 tests in 3.140 s**. `compileall`,
manifest JSON parsing, targeted Ruff for the modified test, and
`git diff --check` passed. No factorization, witness synthesis, or query-point
transformation was run; none is counted as a passing computation.

### Phase 9.21.55 — Production migration feasibility for the source-faithful Spend circuit

This is a read-only integration audit. The isolated source-faithful circuit
is feasible to migrate in principle, and doing so would remove the need to
transform H coordinates from the current production matrix. It is not a
drop-in module move: allocation/index semantics, public witness validation,
and the exported assembly shape must be bridged. No implementation or
expensive synthesis/export was performed in this phase.

**Evidence.** The source-faithful test port matches the pinned Bellman matrix
for three valid witnesses, including complete ordered A/B/C rows, labels,
allocation identities and assignments, public positions, and satisfaction.
The expected matrix is 98,777 rows by 98,646 columns with fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
The current production assembler has the same dimensions but fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
Thus retaining the production matrix would require the unresolved QAP/H
transformation; synthesizing the source-faithful matrix instead would make
the circuit-side H coordinates direct, subject to independent QAP and
parameter checks below.

#### Isolated component inventory and corresponding production code

The test-only implementation is
[`tests/sapling_spend_reference_port.py`](../tests/sapling_spend_reference_port.py);
the current assembler is
[`src/sapling_spend_circuit.py`](../src/sapling_spend_circuit.py).

| Isolated component/helpers | Current production counterpart / migration concern |
|---|---|
| `SpendReferenceWitness`, `SpendReferenceAssembly`, `SourceOrderedConditionalAnchorResult`, and `constrain_source_faithful_spend` | `SaplingSpendWitness`, `SaplingSpendAssembly`, and `constrain_sapling_spend`; the public dataclasses and returned fields differ. |
| Result/witness records: `EdwardsPointWitnessVariables`, `MontgomeryNumberWitness`, `MontgomeryPointWitness`, `SignedLookupWitness`, `PedersenHashResult`, `NoteCommitmentResult`, `ValueCommitmentResult`, `MerkleAuthenticationResult`, `ConditionalAnchorResult`, `IvkBlake2sResult`, `NullifierBlake2sResult`, and `NullifierMultipackingResult` | Internal source-port contracts for returning allocated handles, witness points, and digest/multipacking bits; production needs a deliberate mapping to the existing `CircuitPoint`, gadget result, and `SaplingSpendAssembly` types. |
| `SpendReferenceR1CS`: temporal `alloc_public`, public-position and auxiliary-index maps, canonical-column mapping, source matrix serialization | `R1CS` requires all public inputs before private allocations and indexes QAP assignments by canonical variable order. The test adapter preserves Bellman event order but is not directly consumable by `QAP.from_r1cs`. |
| Edwards/Montgomery conversion and point helpers: `spend_edwards_to_montgomery_coordinates`, `allocate_spend_montgomery_point`, `constrain_spend_montgomery_add`, `constrain_spend_montgomery_into_edwards`, `constrain_spend_edwards_point_witness/double/add/not_small_order/repr`, and point/LC validation helpers | `src/jubjub.py` supplies point arithmetic; `src/sapling_gadgets.py` supplies generalized point allocation, representation, arithmetic, and validation. Source-specific witness encodings, formulas, labels, and row order still need porting or exact reuse proof. |
| Fixed-base and variable-base multiplication: scalar-bit allocation, `spend_fixed_base_tables`, cached tables, `_constrain_spend_lookup3_xy`, `_spend_boolean_and`, signed Boolean handling, `constrain_spend_fixed_base_mul`, `constrain_spend_edwards_point_mul`, and select helpers | Production fixed-base/scalar-multiplication gadgets exist in `src/sapling_gadgets.py`; preserve source window order, table selection, Boolean allocations, and error checks without changing shared Output behavior. |
| Scalar/Boolean helpers: `_spend_circuit_bit_value`, `_constrain_spend_unchecked_field_bits`, `_reuse_or_allocate_spend_bits`, `_reuse_spend_bits`, `_spend_boolean_value`, `_spend_boolean_lc`, `_constrain_spend_strict_field_bits`, `_is_spend_fixed_base_base`, `_validate_montgomery_number`, and `_montgomery_lc` | These encode source-specific bit types, canonicality, preconstrained-bit reuse, Montgomery witness validation, and table behavior; retain tests for ownership, malformed inputs, and rejection before mutation. |
| Spend Montgomery Pedersen: `spend_pedersen_montgomery_tables`, signed lookup coefficient/expression helpers, `constrain_spend_signed_montgomery_lookup`, `constrain_spend_pedersen_hash` | Production Pedersen helpers/tables are in `src/sapling_gadgets.py`. The source-faithful form is specific to Bellman's signed three-bit Montgomery lookup and must remain isolated from Output unless exact parity is established. |
| Value and note commitments: `constrain_spend_value_commitment`, `_constrain_spend_unchecked_field_bits`, `constrain_spend_note_commitment`, bit reuse/allocation helpers | Production `constrain_sapling_value_commitment` and `constrain_note_commitment`; exact source order and reuse of value/representation bits are required. |
| Merkle and anchor: `constrain_spend_merkle_authentication_path`, `constrain_spend_conditional_anchor`, `constrain_spend_source_order_conditional_anchor` | Production `constrain_merkle_authentication_path` and `constrain_sapling_conditional_anchor`; source allocates direction bits in path order, reuses them for position multiplication, and inputizes the anchor late. |
| IVK/nullifier hashing and public packing: `constrain_spend_ivk_blake2s`, `constrain_spend_nullifier_blake2s`, `constrain_spend_nullifier_multipacking`, bit readers and output wrappers | Production `constrain_sapling_ivk`, `constrain_sapling_nullifier_hash`, and `constrain_sapling_nullifier_multipacking` exist. The isolated port calls `tests.bellman_blake2s_reference` for Bellman-exact allocation/coalescing, so this test dependency must be replaced with a production-safe implementation before shipping. |
| `_validate_spend_reference_witness`, `_spend_point_witness`, `_inputize_spend_point`, and private Montgomery/Boolean helpers | Production `_prepare_witness` is stricter and validates derived key, diversifier, commitment, path position, nullifier, and public-input consistency before mutation. Keep the existing admission contract rather than substituting the smaller reference validator. |

The isolated implementation imports production `R1CS`, `Point`, scalar
constants, bit primitives, and `sapling_fixed_base_generator`; it also
imports `CircuitBit`/`_NegatedBit` and Bellman-specific negated bits from
production and test-only modules, respectively. It has no production-safe
standalone API today. The full comparison harness and witness extraction live
in `tests/test_sapling_spend_reference_port.py`; the Rust exporter and pinned
Bellman/Sapling dependencies live under
`tests/reference/sapling-output-qap/`. They are test infrastructure, not
runtime dependencies. `setup.py` packages `src` as the `zycoin` package but
does not package `tests` as an importable runtime package.

#### Exact production replacement requirements and blockers

1. Retain the current public `SaplingSpendWitness` contract and run
   `_prepare_witness`-equivalent admission before mutating the caller's
   system. The test port's smaller witness contains only `ak`, `ar`, `nsk`,
   `g_d`, value/openings, path, and anchor; it does not accept or validate the
   production witness's `nk`, `ivk`, diversifier, `pk_d`, note commitment,
   randomized key, value commitment, position, nullifier, or seven public
   inputs.
2. Preserve the existing `constrain_sapling_spend` callable and
   `SaplingSpendAssembly` attributes (including relation counts and exposed
   variable handles), or introduce an explicit API transition. The reference
   assembly has different field names and does not expose every production
   result.
3. Preserve Bellman's temporal allocation and inputization events while
   producing canonical columns: implicit ONE at 0; public positions 1–7 in
   order `rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`, `nullifier_chunk_0`,
   `nullifier_chunk_1`; then auxiliaries. The reference inserts `rk` after
   1,029 auxiliaries, `cv` after 29,075, `anchor` after 76,806, and nullifier
   chunks after all 98,638 auxiliaries. A direct `SpendReferenceR1CS` cannot
   simply be passed to the production QAP: its temporal variable storage
   indices differ from the canonical indices assumed by `QAP`.
4. Preserve all 98,777 ordered rows, 98,646 columns, labels, A/B/C terms,
   assignments, and the expected fingerprint above. Do not equate relation
   equivalence or a matching row count with matrix equality.
5. Keep the existing parameter parser and six-section query layout. The
   recorded official Spend sections are IC=8, H=131,071, L=98,638,
   A=85,390, B_G1=61,300, B_G2=61,300; the public-input order and all
   437,707 canonical point encodings already match the pinned Bellman loader.
   The remaining A-query identity for the source conditional-anchor
   auxiliary must not be fabricated or conflated with local variable
   allocation.

With an exact source matrix, the production-to-Bellman H transformation is
unnecessary: both sides use the same ordered R1CS and variable/query
coordinates, so QAP construction is direct. This conclusion is only about
removing a coordinate transform. It does **not** establish that the official
parameter ceremony was generated from this exact matrix. The parameter file
has no circuit identifier; Phase-1 and ceremony-era setup evidence are still
missing. Matrix equality, parser compatibility, parameter-to-circuit binding,
and ceremony validity remain separate claims.

#### Component migration plan

1. **Production-safe circuit logic:** move the source-specific Montgomery,
   Pedersen, source-order value/note commitment, Merkle/anchor, fixed-base,
   and nullifier composition into a Spend-local `src` module. Remove all
   imports from `tests.*`; preserve the production witness admission and
   public function/dataclass contracts. Do not alter shared Output gadgets
   merely to deduplicate code.
2. **Allocation/index adapter:** promote the temporal-input adapter only as
   a production-internal staging backend. After synthesis, canonicalize its
   public/auxiliary identities and remap every LC and returned assembly
   variable into the caller's ordinary fresh `R1CS`, so existing QAP,
   assignment, and public-input APIs remain valid. Verify transaction-like
   behavior: invalid inputs and failed staging must leave the caller's
   system unchanged. Avoid changing generic `R1CS` ordering rules used by
   Output.
3. **Differential instrumentation:** retain the current test port or a
   frozen independent equivalent, exact row/label/assignment comparator,
   mutations, and report fixtures under `tests/`. Keep these out of runtime
   imports and wheel contents.
4. **Bellman reference tooling:** retain the pinned Rust exporter and
   `Cargo.lock` as test-only tooling. Do not add a Rust/native production
   dependency or regenerate the expected matrix fingerprint from the
   implementation under test.
5. **Witness and proof interfaces:** preserve the rich production witness
   validation, public input order, `SaplingSpendAssembly` surface, and the
   generic seven-input `verify_sapling_spend_proof` interface. There is no
   production `prove_sapling_spend` API today; this migration must not add
   one, enable Spend proving, or change readiness gates.

#### Risks and required verification stages

- **Allocation and labels:** rerun the source trace comparison for every
  allocation event and all ordered row expressions; labels and allocation
  order are significant for the pinned matrix even when relations are
  algebraically equivalent.
- **Witness-dependent behavior:** exercise baseline, zero-value/alternating
  path, and maximum-value/all-right path; verify conditional-anchor behavior
  and that direction bits are reused exactly. Add malformed, out-of-range,
  mismatched-derived-field, non-fresh-system, and before-mutation rejection
  cases from the production contract; retain foreign-owner checks at
  individual gadget boundaries.
- **Performance and memory:** the source port's prior full synthesis took
  about 50 seconds per witness; canonical staging/remapping adds memory and
  runtime and must be measured before adoption.
- **Output/shared primitives:** run the existing Output production/recorder
  and gadget regressions. Prefer Spend-local helpers; any shared-helper
  change requires unchanged Output matrices and fingerprints.
- **Parameter/QAP separation:** after exact matrix parity, compare complete
  QAP A/B/C/H vectors and direct accumulations for IC, H, L, A, B_G1, and
  B_G2 using the unchanged official parser. Keep parameter-to-circuit
  binding and ceremony validity **Unverified**.

Recommended gates and measured historical runtime guides (not rerun here):

| Stage | Required gate | Prior observed runtime |
|---|---|---:|
| Reusable component trace regressions | Existing isolated gadget/reference trace suite, then production API validation tests | 63.49 s for the previously recorded 52-test/273-subtest Sapling gadget regression; not a migration run |
| Full matrix parity | Independent Bellman export and candidate production synthesis for at least three valid witnesses; compare all variables, positions, labels, ordered rows, assignments, satisfaction, and fingerprint | Baseline differential 60.09 s; the two boundary-witness end-to-end runs 96.982 s and 94.455 s, about 4.2 minutes total |
| QAP and official query use | Compare QAP vectors and all six direct official-query accumulations; do not use synthetic setup | Existing official Spend accumulation regression took 1,152.794 s (~19.2 min) |
| Packaging and cross-circuit regression | Verify no test/Rust imports at runtime; run Output and public-input/API regressions | Must be measured after migration |

**Feasibility verdict:** technically feasible, because the isolated
implementation already meets the pinned matrix target on three witnesses.
It is **not ready for production replacement** until the temporal-input to
canonical-R1CS/QAP bridge, richer witness validation, return-type compatibility,
and production-safe Bellman-exact BLAKE2s path are resolved and the full
verification stages pass. No code was changed, Spend proving remains gated,
and official parameter-to-circuit binding and ceremony validity remain
**Unverified**.

### Phase 9.21.56 — Source-faithful Spend temporal-to-canonical allocation bridge

Added the isolated test-only mapping in
[`tests/sapling_spend_temporal_mapping.py`](../tests/sapling_spend_temporal_mapping.py).
It takes the source `SpendReferenceR1CS` allocation event order as immutable
input, keeps ONE at index 0, maps temporal public handles to canonical
positions 1–7 in their inputization order, then maps auxiliary `Aux(i)` handles
to columns `8+i`. Canonical target construction allocates public handles
before auxiliaries, satisfying ordinary `R1CS` and `QAP` ordering without
changing the source system or its expressions. Every row is copied in source
order with its original label; each A/B/C linear combination is rebuilt only
with remapped handles. The returned mapping also remaps nested result records
and assembly handles.

The bridge fails closed for invalid ONE position/assignment, duplicate or
missing allocations, inconsistent public/auxiliary bookkeeping, incorrect
public annotation order, invalid canonical-column metadata, and foreign or
missing handles. Focused tests cover these rejection cases, deterministic
mapping, source immutability, remapped assignments, ordered A/B/C expressions,
labels, and the canonical QAP public/auxiliary boundary.

#### Exact retained-trace verification

The retained pinned Bellman trace records 98,777 rows, 8 inputs including ONE,
and 98,638 auxiliaries. Public inputization occurred at temporal allocation
events 1,030, 1,031, 29,078, 29,079, 76,811, 98,644, and 98,645. These map,
respectively, to canonical columns 1–7; all auxiliaries map in their Bellman
`Aux(i)` allocation order to columns 8–98,645. The retained trace also records
the satisfying baseline assignment. The source export SHA-256 is
`b9a1bab4df36059e3c324cd07c0baa96062501bc266cf46005ab0d7c35751046`; the
allocation-provenance export SHA-256 is
`a39e4d2d815dca24eead67996d94732dc9a12b13ac3f1c4881f5e5dadddf8feb`.

The opt-in regression streamed the retained matrix rows, reconstructed all
98,646 temporal allocation handles and assignments, and applied the bridge's
linear-combination remapper to every A/B/C expression. All 296,331 remapped
expressions exactly matched an independent conversion from Bellman's
`Input(i)`/`Aux(i)` identities. Row order and counts matched; the canonical
matrix fingerprint was exactly
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`
(98,777 × 98,646). The handle map was one-to-one and all mapped witness
assignments agreed. No Bellman exporter or full Spend synthesis was rerun.

**Verification result:** the test-only allocation bridge is independently
verified against the retained full Bellman matrix for this pinned trace and
assignment. This does not migrate or replace production Spend. Production
witness/API compatibility, production staging/commit behavior, all-witness
invariance, official parameter-to-circuit binding, ceremony validity, QAP
query compatibility, and Spend proving remain separate and unverified.

#### Phase 9.21.56 verification

- Focused bridge regressions: **7 passed, 1 opt-in test skipped** in 0.003 s.
- Retained full-trace bridge regression: **1 passed** in 1,213.888 s
  (20 min 13.888 s); no synthesis or Bellman export was performed.
- Targeted Ruff and `compileall` passed. `git diff --check` is recorded after
  the report updates in the final task verification.

### Phase 9.21.57 — Source-faithful Spend witness validation

Added fail-before-allocation validation to the isolated
`_validate_spend_reference_witness`. The valid synthesis path, allocation
order, bit decompositions, equations, labels, and enforcement order are
unchanged.

#### Validation inventory and source boundary

| Witness item | Host validation | Circuit relation retained | Pinned-source / remaining boundary |
|---|---|---|---|
| `ak` authorization point | Must be a `Point` with integer canonical coordinates, on Jubjub, non-small-order, and in the prime-order subgroup. | Edwards curve and non-small-order checks remain in the R1CS. | Pinned fixture obtains it through subgroup-typed `SpendValidatingKey` / `ProofGenerationKey`; production witness preparation also requires subgroup membership. No separate `ask` is present in `SpendReferenceWitness`. |
| `ar`, `nsk`, `rcv`, `rcm` | Exact Python integers in `[0, jubjub::Fr)`. | Existing 252-bit little-endian decompositions and Boolean/reconstruction or scalar-multiplication constraints are unchanged. | Their field types in the pinned implementation are canonical by construction; no byte-encoding fields are supplied here. |
| Note value | Exact integer in `[0, 2^64)`. | Existing 64 value bits and range/commitment constraints remain. | Both the pinned `NoteValue::from_raw` and production preparation use the unsigned 64-bit range. |
| `g_d` diversifier base | Same canonical point, curve, non-small-order, and prime-subgroup checks as `ak`. | Existing curve and non-small-order rows remain. | Pinned payment addresses derive `g_d` from a valid diversifier; this isolated witness contains only `g_d`, not the diversifier bytes, so their group-hash correspondence cannot be checked here. Production has and checks the diversifier. |
| Authentication path | Exactly 32 tuple entries; every sibling is an exact canonical circuit-field integer and every direction is exactly `bool`. | Existing position-bit Boolean constraints, path ordering, and per-level Pedersen relations remain. | The pinned fixture supplies a 32-level path of canonical `Scalar` siblings and Boolean directions. Position is derived from the directions, not an independent isolated-witness field. |
| Anchor | Exact canonical circuit-field integer. For nonzero value, independently recompute the note and Merkle root and require the supplied anchor to match before allocation. For zero value, a different anchor remains allowed. | The conditional-anchor equation and late public inputization remain unchanged; when value is zero the source relation does not force root equality. | This matches the pinned equation `(root - anchor) * value = 0` and production's nonzero-anchor check. |
| `nk`, `ivk`, `pk_d`, value/note commitments, Merkle root, `rho`, nullifier digest and packed chunks | Not independent fields of `SpendReferenceWitness`; no duplicate caller-supplied values can be inconsistent. The nonzero anchor is checked against the locally derived root. | Existing derivation, bit, hash, and public-input constraints produce these values. | The full production witness API does carry additional derived values and validates their consistency; that API is outside this isolated witness type. |

Point subgroup validation is deliberately host-side input admission, not a
replacement for the circuit's existing curve and non-small-order constraints.
It follows the pinned typed inputs and production's authorization-key
preparation. Tests include a valid on-curve, non-small-order point outside the
prime subgroup and confirm that it is rejected. Point encodings are not fields
of this witness API; callers provide `Point` objects, whose coordinates are
checked directly.

#### Verification

Focused validation and composition tests: **7 passed**. They cover scalar and
value bounds, point type/canonicality/curve/small-order/subgroup checks,
malformed paths and directions, mismatching nonzero anchors, and the valid
zero-value/mismatching-anchor case. Each invalid complete-witness call is
asserted to leave the R1CS at one ONE variable and zero constraints.

The retained baseline Bellman trace was synthesized through the updated
source-faithful entrypoint: **1 passed in 63.890 s**, including all ordered
rows/assignments and unchanged matrix dimensions and fingerprint (98,777 rows,
98,646 columns,
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`).
Previously verified three-witness Bellman parity remains the circuit-level
baseline. The two alternate full exports were not rerun; their pinned Rust
fixture constructors use subgroup keys and valid diversifier-derived bases,
canonical field scalars, 32 canonical path siblings/directions, and anchors
computed from those paths. The new host tests also admit zero and maximum
64-bit values. No Bellman exporter was run for this task.

Targeted Ruff and `compileall` passed. Production Spend and Output, parameters,
readiness gates, and proving were not changed. Remaining gaps include the
missing diversifier bytes and source key material in the isolated API, derived
field parity beyond retained witnesses, and production integration; witness
validation alone does not establish production readiness.

### Phase 9.21.58 — Source-faithful Spend generic Groth16 adapter

Added the test-only adapter in
[`tests/sapling_spend_groth16_adapter.py`](../tests/sapling_spend_groth16_adapter.py).
It accepts only the pinned source R1CS and a complete source assembly, checks
the seven public handles and their order, component-to-public-handle
consistency, ownership and completeness of nested handles/expressions, the
pinned system shape, and source-R1CS satisfaction. It then uses the verified
temporal-to-canonical bridge to remap the assembly, checks the canonical
matrix fingerprint, and builds the existing generic `QAP` and `QAPAssignment`
with implicit ONE, seven ordered public inputs, and 98,638 auxiliary values.
The generic QAP independently validates the complete assignment.

On the retained pinned baseline trace, the adapter produced the exact
98,777-row, 98,646-variable canonical matrix with fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
The assignment matched ONE/public/auxiliary values from the retained trace;
QAP domain size was 131,072. The generic A/B/C evaluation and polynomial
interfaces ran, and FFT of each returned polynomial reproduced its domain
evaluations. This verifies the adapter-to-generic-QAP interface for this
retained circuit and witness; it is not an independent Bellman QAP comparison.

Adapter boundary tests reject wrong API types, duplicate or reordered public
handles, foreign handles, incomplete assembly data, and inconsistent
component public-input references. The full-trace adapter regression passed
**1 test in 2,439.190 s** using the retained JSON trace and one complete
Python source-faithful Spend synthesis; no Bellman export was performed.
Adapter boundary plus temporal-mapping suites
passed **13 tests with 1 opt-in test skipped** in 0.004 s, and the generic QAP
suite passed **11 tests** in 0.007 s. Targeted Ruff, `compileall`,
`git diff --check`, and adapter-file Pylance diagnostics passed.

The broad Spend reference-port suite also ran: **68 tests, 12 skipped, 1
error** in 191.954 s. The error is the existing IVK vector test accessing
`ivk_blake2s_vectors`, which its default setup does not initialize; that test
body and fixture setup were not changed here.

Compatibility is established only at the test-only assembly → canonical R1CS
→ generic QAP-assignment boundary. The adapter imports the test-only reference
port and allocation bridge and is not production-safe as-is. It does not load
official parameters, expand or authenticate compact query sections, assemble
proof elements, or verify proofs. Parameter/circuit binding, ceremony
validity, production API compatibility, and proving readiness remain
**Unverified**. No production Spend or Output code, parameters, setup, or
readiness gate changed.

### Phase 9.21.59 — Spend BLAKE2s host dependency separation

The test-only source-faithful Spend witness admission path now uses the
production-safe `bytes_to_bits_le` and `make_blake2s_witness` helpers from
[`src/blake2s_gadget.py`](../src/blake2s_gadget.py) for IVK host derivation.
It hashes `ak.encode() || nk.encode()` using the 32-byte BLAKE2s digest and
the exact eight-byte `Zcashivk` personalization, then interprets the digest
little-endian and retains its low 251 bits. A focused test checks the helper
call's preimage and personalization and compares its digest with
`hashlib.blake2s`. No separate host-side nullifier digest is used by this
admission path; nullifier derivation remains a circuit operation.

The circuit constraint path still calls the independent test-only
[`tests/bellman_blake2s_reference.py`](../tests/bellman_blake2s_reference.py)
transcription for IVK and nullifier synthesis. The existing production circuit
helper is not an exact drop-in for source-mode synthesis. A direct IVK
comparison with 512 preconstrained input bits and output materialization
disabled produced 21,518 rows and 21,473 variables on each side, with equal
assignments, but the ordered matrix serialization differed. The first
A/B/C difference was at row 614: production used A=`2*column 530`,
B=`column 581`; the source transcription used A=`2*column 581`,
B=`column 530`. The first constraint-label difference was also immediate:
production used `computation of ivk block[0] final round[0] ...`, while the
source transcription used the slash-separated
`computation of ivk/final block/round 0/mixing invocation 1/...` annotation.
The source path's complemented-XOR operand ordering and exact annotations
must be retained; the matrix fingerprint alone would not capture the label
difference. Therefore circuit constraints were not migrated and no new hash
implementation was added.

Focused host-IVK tests passed **2 tests in 17.500 s**. Production helper
vector/matrix regressions passed **4 tests in 9.128 s**. Source-faithful IVK
vector/trace tests passed **2 tests in 7.443 s**, nullifier tests passed
**2 tests in 6.179 s**, and nullifier multipacking trace/vector tests passed
**2 tests in 7.319 s**. The retained source component results include:
IVK, 22,566 rows × 22,519 columns,
`5953027d2a1b56fcfc57ef3432083b7c800a9db7693a7f88bfc8a353e9c68b69`;
nullifier, 22,566 × 22,519,
`20f63b47b5102a57ea023edc7452b3f9e7004ea34a5a53e2402984c17e89ab32`;
and nullifier multipacking, 22,568 × 22,526,
`d4b682f3441cc17495557468a1bfdccb053fe9800fcabb96a6f3cb97269403ab`.
The full 98,777-row Spend circuit was not re-synthesized: no circuit
constraint code changed, and the retained full matrix fingerprint remains
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`;
this phase did not independently remeasure that full fingerprint.

The existing `ivk_blake2s_vectors` missing-setup error is independent of the
hash-helper change. The test class initializes that mapping only in the
`SAPLING_IVK_REFERENCE_ONLY=1` setup branch; the default setup branch does
not, while the vector test still runs. The IVK vector/trace tests pass in the
reference-only environment. No fixture or setup branch was changed to hide
the default-suite error.

Targeted Ruff, `compileall`, `git diff --check`, and Pylance syntax checks
passed. Pylance reported only unused-local warnings in the touched Python
files; the warnings were unrelated to this change. Host-side hashing now
uses the production-safe helper, but the circuit-level test-only dependency
remains necessary for exact ordered matrix and annotation parity. This does
not establish Spend production migration, official parameter binding,
ceremony validity, or proving readiness.

### Phase 9.21.60 — Source-ordered BLAKE2s circuit gadget

Added the production-safe pure-Python
[`src/sapling_blake2s.py`](../src/sapling_blake2s.py) gadget and routed the
isolated Spend IVK and nullifier circuit wrappers through it. The module
depends only on ZyCoin's R1CS and production BLAKE2s bit/witness primitives.
It preserves the pinned source's `MultiEq` batching, result-bit allocation
and Boolean enforcement, slash-separated annotation paths, and complemented
XOR operand ordering. `tests/bellman_blake2s_reference.py` remains an
independent test-only comparison implementation; the Spend circuit module no
longer imports it or its `_Negated` type.

The existing production `src.blake2s_gadget.py` mismatch was traced to
source-specific synthesis details, not merely labels or dimensions. In the
matched 512-bit IVK comparison, the first production variable name differed
at column 513 and the first label at row 512. The first ordered matrix
difference was row 614: the generic production helper emitted
A=`2*column 530`, B=`column 581`; the source order is A=`2*column 581`,
B=`column 530`. The pinned transcription swaps the backing variables in
that XOR equation when the left bit is complemented and source annotations
are enabled. Its `/result bit .../boolean` and `/xor constraint` labels also
differ from the generic helper's bracket/space labels. The new module ports
these source-mode allocation, row, and annotation rules without changing the
existing general-purpose BLAKE2s gadget.

An independent raw-IVK gadget comparison now matches the retained Python
transcription's complete serialized system, assignments, outputs, and
satisfaction result, including row 614 and all labels/ordered A/B/C rows:
21,518 rows × 21,473 columns, fingerprint
`d91d1c41a11f9305476ae41a2b71714c21f97b0952b7a1352f5bfac40207fa7a`.
Retained Bellman-trace tests independently verified the integrated IVK
component at 22,566 × 22,519 with fingerprint
`5953027d2a1b56fcfc57ef3432083b7c800a9db7693a7f88bfc8a353e9c68b69`,
and the nullifier component at the same dimensions with fingerprint
`20f63b47b5102a57ea023edc7452b3f9e7004ea34a5a53e2402984c17e89ab32`.
Those comparisons check variable identities/order and assignments, every
annotation, every ordered A/B/C expression, and satisfaction against the
retained trace. No new Bellman export was needed.

Host-side IVK admission still uses `make_blake2s_witness`; its focused
integration test passed. IVK and nullifier digest-vector tests passed in
their reference-only setup branches. Existing nullifier multipacking tests,
production BLAKE2s regressions, adapter boundary tests, and negated-bit
handoff tests also passed. The default IVK vector-test setup still raises
`AttributeError` because it does not initialize `ivk_blake2s_vectors`;
only the reference-only setup branch does. This independent setup defect was
reproduced without changing fixtures.

The complete 98,777 × 98,646 Spend matrix was **not re-synthesized or
reverified** in this phase. Its retained fingerprint remains
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`, but
this is not a new whole-circuit measurement. The BLAKE2s circuit dependency
is now production-safe and exact for the verified IVK/nullifier components;
the broader Spend circuit, assembly, and Groth16 adapter remain test-only.
Official parameter binding, ceremony validity, and Spend proving readiness
remain **Unverified**.

Verification: raw IVK system differential **1 passed in 3.02 s**; retained
IVK trace/vector/invalid-input tests **3 passed**; retained nullifier
trace/vector/invalid-input tests **3 passed**; multipacking tests **3 passed
with 22,580 subtests**; production BLAKE2s regressions **19 passed with 52
subtests**; adapter boundary tests **5 passed**; host IVK helper integration
**1 passed**. Targeted Ruff, `compileall`, `git diff --check`, and new-module
Pylance diagnostics passed. Existing unused-local Pylance warnings in test
files were left unchanged.

### Phase 9.21.61 — Full Spend verification after BLAKE2s migration

The fresh baseline comparison used the retained
`sapling-spend-reference.json` artifact, whose header identifies pinned
Sapling `88a7946b4a3066787776e11f0a502654167e022d`, Bellman
`b726862a4ece8a627e7fea486d77b502a6edbb0b`, the pinned fixture iteration 0,
and matching upstream/observed Bellman test-system hash
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`.
The full-composition test freshly synthesized the isolated Python Spend
circuit and compared it with this trace. It checked the complete temporal
allocation order and identities, all assignments, public-input positions and
values, every annotation and ordered A/B/C expression, and satisfaction.
The canonical adapter then matched fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127` at
**98,777 rows × 98,646 columns**, with 98,638 auxiliary variables, seven
public inputs, and the expected 131,072-element QAP domain. The test also
compared the adapted assignment and public/auxiliary values, checked QAP
evaluation/polynomial consistency, and matched the failure row for a
tampered anchor. The end-to-end baseline test passed in **2,159.62 s**.

The two variant Bellman JSON traces were not present among the retained raw
artifacts, so the variant comparisons generated fresh test-only exports from
the same pinned revisions; no setup parameters were generated. Both fresh
traces independently matched the Python full synthesis, including allocation
identities/order, assignments, public inputs, labels, ordered A/B/C rows,
satisfaction, and the same canonical matrix fingerprint:

| Witness | Bellman export | Python synthesis | Result |
|---|---:|---:|---|
| Zero-value, alternating path directions | 29.584 s | 53.848 s | Exact full-matrix match |
| Maximum-value, all-right path directions | 28.413 s | 47.284 s | Exact full-matrix match |

Both variant tests also matched the pinned invalid-assignment failure rows.
Together, the baseline and two variants freshly verify the isolated
source-faithful Spend matrix after the BLAKE2s gadget migration. Only the
baseline test exercised the generic QAP adapter; the two variant tests
verified full circuit matrices and witness behavior without rebuilding the
adapter/QAP.

The missing default IVK vector initialization was a separate test setup bug:
the default combined reference export already contained the vectors, but its
`setUpClass` path initialized only IVK cases. It now indexes those vectors in
the default path as well. The default vector test passed (**1 test, 4
subtests**); no reference fixtures or assertions changed.

Focused verification passed: IVK trace/vector/invalid-input tests (**3
passed, 14 subtests**); nullifier trace/vector/invalid-input tests (**3
passed, 11 subtests**); multipacking trace/vector/invalid-input tests (**3
passed, 22,580 subtests**); BLAKE2s, temporal-mapping, and adapter-boundary
tests (**31 passed, 1 skipped, 56 subtests**). Targeted Ruff,
`compileall`, and `git diff --check` passed. Pylance reported no issues in
`src/sapling_blake2s.py`; the test module retained only its pre-existing
unused-local warnings.

This verifies the isolated test-only circuit against the pinned Bellman
reference for three valid witnesses, not production Spend replacement,
official parameter-to-circuit binding, ceremony provenance, or proving
readiness. Those remain **Unverified**. No production Spend or Output circuit
implementation was changed.

### Phase 9.21.62 — Formal production Spend migration readiness audit

**Decision: Not ready to replace production Spend or use the official Spend
parameters for proving.** The isolated source-faithful circuit has strong,
fresh full-matrix parity evidence, but it is still test-only; the current
production circuit has a different matrix, the production adapter and
parameter/query binding are incomplete, and ceremony validity is not
established. This was a read-only audit. It did not rerun full Spend
synthesis, regenerate an official query export, create setup data, or produce
a proof.

#### Evidence and current boundary

- The retained Phase 9.21.61 comparisons verify the source-faithful composer
  against pinned Sapling `88a7946b4a3066787776e11f0a502654167e022d` and
  Bellman `b726862a4ece8a627e7fea486d77b502a6edbb0b` for three valid
  witnesses. They compare allocation identities/order, assignments, public
  inputs, labels, ordered A/B/C expressions, satisfaction, and the canonical
  matrix fingerprint
  `cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`
  (**98,777 rows × 98,646 columns**). Only the baseline also exercised the
  test-only generic QAP adapter.
- The current production circuit fingerprint remains
  `f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
  The source-faithful fingerprint difference is affirmative evidence that
  the current production circuit is not the exact pinned ordered matrix; it
  is not evidence that either circuit is unsatisfied or that the official
  parameters match the source-faithful one.
- Production exposes `SaplingSpendWitness`,
  `SaplingSpendAssembly`, and `constrain_sapling_spend` from
  `src/sapling_spend_circuit.py`. The source-faithful composer,
  `SpendReferenceWitness`/`SpendReferenceAssembly`, temporal allocation
  bridge, and Groth16 adapter are in `tests/`. The source witness is not a
  drop-in replacement for the production witness: production accepts and
  cross-checks additional derived values and public inputs. The bridge and
  adapter also rely on concrete/private R1CS state, so they are not yet a
  production-safe API boundary.
- `src/sapling_blake2s.py` is pure Python and production-safe as a module, but
  production Spend still imports the generic `src.blake2s_gadget`; it does
  not use the source-ordered gadget. Moving the test composer into `src`
  without separating the reference harness and stabilizing these helper
  boundaries would therefore not complete the migration.
- The designated `sapling-spend.params` file was present at audit time;
  its size is **47,958,396 bytes** and its SHA-256 was freshly checked as
  `8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13`.
  Retained parameter-compatibility evidence verifies Bellman 0.15 parser and
  point-encoding compatibility, file integrity, and section counts
  (IC=8, H=131,071, L=98,638, A=85,390, B_G1=61,300, B_G2=61,300). This
  establishes byte/format evidence only, not a circuit identifier or
  ceremony-to-matrix binding.
- The retained query-index artifact
  `tests/fixtures/sapling_spend_parameter_query_index_mapping.json`
  fingerprints the structural mapping as
  `183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08`.
  Its production-correspondence columns leave upstream `Aux(76805)`
  unresolved in both L and A. In the source-faithful canonical layout that
  identity maps to column 76,813 (`ONE` + seven public inputs + `Aux(76805)`),
  but no production sparse-query expander or source-specific official-query
  comparison has been verified. Historical full-vector accumulation results
  on the current production QAP include an H mismatch; they cannot be
  transferred to the source-faithful matrix.

#### Migration gates

| Gate | Status | Evidence | Required to pass |
|---|---|---|---|
| Pinned source and source-faithful circuit relation | **Verified, scoped** | Three full-matrix comparisons match the pinned source; the baseline also passes the test-only canonical QAP adapter. | Preserve the pinned source, full ordered-matrix comparisons, and witness coverage in the production migration regression suite. |
| Current production circuit equivalence | **Blocked** | Production fingerprint `f3451e63…e983e5b9` differs from the verified source-faithful fingerprint `cdb472ea…c929a127`. | Integrate the source-faithful relation behind the existing production API, then prove exact parity before switching the implementation. |
| Production module/API and dependency boundary | **Blocked** | Composer, temporal bridge, and adapter are test-only; witness/assembly structures differ; bridge uses concrete/private R1CS state. Production still uses the generic BLAKE2s gadget. | Extract only circuit/runtime code to `src`, retain exporters/fixtures as test-only, normalize the existing public witness, and preserve the existing function and assembly contracts without new runtime dependencies. |
| Witness validation and failure lifecycle | **Partially Verified** | Production preflights scalar/point/path/public-input consistency. A same-length nullifier is compared to the constrained PRF only after substantial R1CS mutation. The independent verifier also requires nonzero IVK and unconditional anchor equality, unlike production's `ivk >= 0` and conditional nonzero-value anchor check. | Move nullifier consistency into preflight or make failed assembly atomic; decide and test the verifier policy differences before sharing it as an admission validator. |
| Canonical allocation and generic QAP adapter | **Partially Verified** | Temporal-to-canonical mapping and baseline QAP assignment/evaluation pass in tests. No production adapter exists; the two alternate witnesses did not rebuild the QAP adapter. | Promote a stable canonical bridge/adapter and test complete variable identities, assignments, public-input order, satisfaction, and QAP evaluation for all retained witnesses. |
| Official parameter bytes and serialization | **Verified, format only** | Current file SHA-256 and size checked; retained Bellman 0.15 parser comparisons and query-section counts pass. | Keep the digest pin and strict point/section validation; do not treat parsing or matching dimensions as circuit binding. |
| Official query mapping to the source-faithful circuit | **Unverified** | Query identities/counts are retained, but the current-production mapping leaves `Aux(76805)` without a local column; no source-specific sparse expansion or complete official-query accumulation was demonstrated. | Establish a source-canonical sparse-index map, expand compact queries with exact identity positions, and independently compare every required query section against the exact source circuit. |
| Parameter-to-circuit binding and ceremony validity | **Blocked** | The file hash pins bytes only. The Phase-1 artifact and complete authenticated ceremony transcript/exact ceremony-era circuit binding are unavailable in the retained evidence. | Obtain and independently validate the complete provenance/transcript and evidence that the final query sections were generated for this exact matrix, or keep these parameters unusable for Spend. |
| Proving/verification integration and secret handling | **Blocked for production Spend proving** | Generic QAP/proof/verification APIs exist, but proof assembly needs dense queries and caller-supplied `r,s`; Spend has no authenticated parameter loader/query expander/proving wrapper. No Spend proof was generated. Python constant-time behavior and reliable zeroization are not established. | Separately establish authenticated parameters and query expansion, secure randomness and key lifecycle, proof/verification compatibility, and side-channel/secret-handling policy. Keep Spend proving disabled until then. |

#### Confirmed findings and assurance gaps

1. **Confirmed relation/API gap:** the current production matrix and the
   source-faithful matrix have different fingerprints. The exact source
   relation is verified only in the isolated path; production replacement
   has not occurred.
2. **Confirmed failure-lifecycle gap:** `_prepare_witness` validates nullifier
   type/length and public packing before allocation, but
   `constrain_sapling_spend` compares the supplied bytes with the constrained
   nullifier output after circuit construction has already mutated the
   caller's R1CS. A caller must discard that R1CS on failure. This audit
   identified the ordering from code and did not rerun a full synthesis for
   this failure case.
3. **Confirmed verifier-policy difference:** `verify_spend_reference_witness`
   requires `0 < ivk < 2^251` and always checks anchor equality; production
   `_prepare_witness` permits zero IVK and only requires anchor equality for
   nonzero value. This is an API consistency issue to resolve, not evidence
   of a demonstrated exploit or a reason to alter circuit equations.
4. **Assurance gaps:** file integrity, Bellman-compatible serialization,
   matrix parity, and a passing test-only QAP adapter do not prove official
   parameter binding or ceremony validity. Generic proof assembly does not
   generate randomness or authenticate query provenance, and Python does not
   provide a constant-time/zeroization guarantee.

#### Proposed production boundaries

- Keep `src/sapling_spend_circuit.py` as the compatibility boundary: retain
  `SaplingSpendWitness`, `SaplingSpendAssembly`, and
  `constrain_sapling_spend`; perform all witness normalization and
  cross-checks before mutating the caller's R1CS.
- Put the source-ordered Spend composition in a private production module
  (for example, `src/sapling_spend_source.py`) that consumes only validated
  production witness data and production-safe Python gadgets, including
  `src.sapling_blake2s`. It must not import `tests`, reference exporters, or
  fixture helpers.
- Keep allocation/QAP conversion on a stable production API. Prefer
  canonical allocation that preserves source auxiliary order and inserts
  public-input enforcement rows at their original source points; do not copy
  the test bridge's direct access to private R1CS internals. Any alternative
  temporal bridge must expose a supported mapping contract and independently
  pass the same ordered-matrix tests.
- Keep parameter parsing separate from circuit synthesis. The existing
  generic parser may continue validating Bellman serialization, but a
  source-specific query expander/authenticated parameter wrapper must not be
  treated as available until the sparse map and ceremony evidence pass their
  gates. Reference exporters and retained artifacts remain test-only.

#### Recommended implementation sequence

1. Keep the existing production Spend and proving gate unchanged. Freeze the
   source-faithful matrix, witness, and allocation evidence as migration
   baselines.
2. Extract the source-faithful runtime composer and required pure-Python
   helpers into a production module. Keep pinned Bellman exporters,
   comparison code, fixtures, and reference-only adapters under `tests/`.
3. Adapt the existing `SaplingSpendWitness` into the source composer only
   after all current redundant-field checks pass. Preflight the derived
   nullifier before backend mutation (or provide atomic assembly), and
   preserve `SaplingSpendAssembly`, public-input order, labels, and failure
   behavior.
4. Use a production-safe canonical allocator/adapter that preserves the
   source auxiliary order and inserts public-input equality rows at their
   source enforcement points. Resolve `Aux(76805)` against the
   source-canonical layout; do not silently reuse the incomplete
   production-correspondence columns.
5. Run exact full-matrix regressions for all three witnesses, including
   allocations, assignments, labels, ordered A/B/C expressions, satisfaction,
   and QAP behavior. Also rerun the unchanged Output and Spend compatibility
   regressions; retain rollback to the current implementation until all pass.
6. Treat official parameter/query use as a separate gate: validate complete
   provenance and ceremony evidence, then verify every source-specific
   query section and its sparse index mapping. If that evidence cannot be
   obtained, do not use the existing official parameters for the migrated
   Spend circuit.
7. Keep proving disabled until parameter authentication, secure randomizer
   generation, proof/verification integration, and secret-handling assurance
   pass independently.

Bounded verification during this audit passed: **58 passed, 1 skipped, 89
subtests** in 76.31 seconds across temporal mapping, adapter boundaries,
Spend witness verification/preflight, QAP, proof, verification, and
parameter-stream parser tests. The official parameter compatibility export
and complete Spend synthesis were not repeated. Targeted Ruff,
`compileall`, and `git diff --check` passed. Pylance reported no diagnostics
in the production Spend, BLAKE2s, temporal-mapping, or adapter files; the
source-reference composer retained one existing unused-local warning.
No production code, circuit, parameter, or proving gate changed in this
audit.

### Phase 9.21.63 — Production Spend nullifier preflight

The nullifier comparison now happens in `_prepare_witness`, before the first
R1CS mutation. After the existing host checks derive and validate `nk`,
note commitment, position, and `rho`, preflight computes BLAKE2s-256 with
personalization `Zcash_nf` over `nk.encode() || rho.encode()` and compares
those bytes with `witness.nullifier`. This reuses the already-derived
`expected_nk` and `rho.rho`; it does not change hash parameters or replace
the circuit constraints. Jubjub representation bits used by the circuit are
the little-endian 255-bit `v` representation followed by `u` parity, which
packs to the same compressed point bytes. The existing pinned witness
confirmed that this host preflight digest equals its circuit nullifier.

The comparison preserves the existing `R1CSError` message,
`Sapling Spend nullifier does not match constrained PRF`. It runs before
public inputs are allocated, variables/assignments are appended, or
constraints are enforced. The previous post-hash `bits_to_bytes_le` check was
removed; the circuit BLAKE2s and nullifier multipacking constraints remain
unchanged.

The focused regression supplies a different 32-byte nullifier and matching
packed public chunks, so the nullifier relation is the inconsistent field.
It snapshots serialized R1CS structure (rows, labels, ordered expressions,
and allocation names), variable identities, every assignment, public-input
count and values, private-allocation state, and freshness. The call raises
the expected error and the entire snapshot remains identical. A valid
assembly then succeeds on that same `R1CS`: **98,777 rows**, **98,646
variables**, seven public inputs, satisfied constraints, and unchanged
production fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.

#### Related verifier validation differences

1. **IVK:** `verify_spend_reference_witness` requires
   `0 < ivk < 2^251`; production `_prepare_witness` allows
   `0 <= ivk < 2^251`. The production path checks the IVK derivation but
   does not reject the zero result or the resulting identity `pk_d`.
   `src/addresses.py` requires a nonzero 251-bit IVK and rejects an identity
   Sapling transmission key, so zero is outside the accepted payment-address
   API/protocol boundary. Production assembly can therefore admit the
   mathematically possible zero-IVK/identity-key case if the truncated hash
   derives zero. This rare edge is **not fixed here**. A separate change
   should reject zero IVK and identity `pk_d` in host preflight, with focused
   admission tests, without changing the circuit relation.
2. **Anchor:** `verify_spend_reference_witness` always requires the supplied
   anchor to equal the computed root. Production only requires equality when
   `value != 0`, matching the pinned conditional relation
   `(root - anchor) * value = 0`. A mismatched anchor at zero value is
   therefore accepted by production and satisfies this circuit relation;
   the circuit does not establish whether an anchor is a recognized tree
   root. Do not tighten the circuit or weaken the independent verifier in
   this change. If transaction-level Sapling policy requires root membership
   for zero-value spends, enforce it separately at that higher-level
   boundary; this assembly audit does not establish that policy.

Focused validation passed: **7 tests and 53 subtests** in 83.80 seconds,
covering nullifier preflight/system reuse, malformed witness inputs,
upstream host-admission rules, nonfresh-system rejection, and the independent
Spend verifier. Targeted Ruff, `compileall`, Pylance diagnostics for the
changed Python files, and `git diff --check` passed. No circuit equations,
Output code, parameters, proving gates, or independent verifier behavior
changed.

### Phase 9.21.64 — Reject zero-IVK identity transmission keys

`_prepare_witness` now rejects `expected_ivk == 0` and an identity
`expected_pk_d` before comparing or accepting the supplied transmission key.
It reuses the already-derived `expected_ivk` and
`expected_pk_d = expected_g_d.multiply(expected_ivk)`; no key/hash derivation
is duplicated. The predicate matches the existing Sapling address boundary:
`derive_payment_address` requires `0 < ivk < 2^251`, and
`SaplingPaymentAddress` rejects the identity transmission key. The check runs
inside `_prepare_witness`, before the first R1CS mutation (`alloc_public`),
and does not change witness fields, serialized assignments, or circuit
constraints.

The regression forces the otherwise rare derived-zero case by substituting a
zero BLAKE2s digest only during that negative preflight call; it supplies
`ivk=0` and the identity transmission key. The error is deterministic and
the before/after R1CS snapshot remains equal for serialization (rows, labels,
ordered expressions, and allocation names), variables, assignments, public
inputs, private-allocation state, and freshness. A valid witness then
assembles successfully on that same system, is satisfied, and retains the
production fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`
(98,777 rows, 98,646 variables, seven public inputs). All **10 pinned Spend
witness iterations** passed `_prepare_witness`; the pinned IVK vector also
passed.

Zero-value anchor semantics are unchanged: production still follows the
pinned conditional anchor relation, and the independent verifier was not
modified. Whether a transaction must separately prove that an anchor is a
recognized Merkle root remains a transaction-boundary requirement, not a
new R1CS constraint in this change.

Focused validation passed: **9 tests and 63 subtests** in 161.05 seconds.
Targeted Ruff, `compileall`, Pylance diagnostics for both changed Python
files, and `git diff --check` passed. No Output code, independent verifier,
official parameters, proving gates, or circuit equations changed.

### Phase 9.21.65 — Sapling Spend anchor membership preflight

Added `SaplingCommitmentTree.require_root_in_history()` and
`SaplingTreeScanResult.validate_spend_anchor(anchor)`. The guard rejects
non-32-byte and noncanonical Sapling field encodings, rejects roots absent
from the available tree history, and returns a current or retained
historical root unchanged. The scan-result method fails explicitly when its
tree state is unavailable. `witness_for()` validates the generated current
anchor before returning its witness. These APIs do not take note value and
do not alter Spend circuit constraints or conditional zero-value anchor
semantics.

The existing tree retains every prefix root and defines no expiration or
stale-root window. A retained historical root therefore passes local
membership validation; an absent root is rejected as unknown/not retained.
The scanner's endpoint-provided block data and tree sizes are only
consistency-checked, not independently authenticated against consensus.
Consequently this is a local tree-state preflight, not a consensus acceptance
proof.

Repository audit confirmed that Sapling transaction construction,
serialization, proving, signing, and broadcast are not implemented. The
preflight is exposed at the closest existing tree-aware Spend-witness
boundary, but no transaction builder currently calls it; end-to-end
transaction-output rejection before serialization/proving/broadcast cannot
be verified until such a builder exists. No transaction output or external
side effect is produced by this validator.

The focused tree/scanner, existing zero-value conditional-anchor, and
production Spend satisfaction regressions passed (**10 tests**). Ruff's
targeted `--select F` check passed. The default targeted Ruff check still
reports 21 existing findings in these files; none are in the added logic and
they were left unchanged. `compileall` and `git diff --check` passed.
Pylance reported no diagnostics in the changed production source files; the
test module retains its existing unused-parameter warnings. No circuit,
transaction serialization, network, or storage layer was added.

### Phase 9.21.66 — Transaction-independent Spend witness validation

Added `validate_sapling_spend_witness(witness, tree_state)` to the existing
Spend circuit module and re-exported it from `src.sapling`. The function
requires an explicit `SaplingTreeScanResult`; missing context fails closed.
It calls the existing `_prepare_witness` once, reusing its scalar and point
validation, key derivation checks, note/value commitment derivation,
conditional anchor handling, public-input checks, and BLAKE2s nullifier
comparison. No second IVK or nullifier derivation implementation was added.

The API also checks that the scan starts at activation, its retained output
count agrees with tree size, the current tree root agrees with root history,
and the selected output/position/commitment agree with the tree. It requires
both the path-computed root and declared anchor to occur in retained history.
For nonzero value, `_prepare_witness` continues to require path-root equality
with the anchor. For zero value, the two roots may differ but each must be in
the supplied local history; no circuit equation changed. The validator is
read-only and returns no transaction bytes.

This boundary does not authenticate endpoint-provided roots against
consensus, define expiry, establish note non-spent status, or validate
transaction balance/proof/signature. The repository still has no Sapling
transaction construction, serialization, proving, signing, or broadcast API.
The function is a reusable preflight for a future builder, not a transaction
builder or proving gate.

Focused validation covers current and retained roots, unknown and malformed
anchors, absent/inconsistent tree context, invalid path structure, nullifier
mismatch, zero-IVK and identity-key rejection, zero-value conditional-anchor
semantics, and no R1CS mutation (**4 new tests**, in addition to the prior
tree/scanner and production Spend regressions). The combined focused suite
passed **15 tests** in 116.6 seconds. Targeted Ruff, `compileall`,
`git diff --check`, and Pylance diagnostics for all three changed Python
files passed with no diagnostics.

### Phase 9.21.67 — Fail-closed Sapling note spent-status verification

Added `verify_sapling_note_spent_status()` to `src.scanning`. It accepts a
validated `SaplingNote`, nullifier-deriving key, positioned output, and its
complete `SaplingTreeScanResult`, and derives the nullifier with the existing
`derive_sapling_nullifier()`. Using the configured Lightwalletd
`GetBlockRange` capability and LWP v0.6.0+ shielded-range response, it scans
from the note's creation block through the captured tip. It requires exact
height coverage, predecessor/block hash continuity, well-formed 32-byte
Sapling nullifiers, and a stable reported tip.

The result distinguishes `SPENT`, `UNSPENT`, and `UNKNOWN`. `SPENT` means the
nullifier appeared in the validated endpoint range; it is not independently
consensus-authenticated. An absent nullifier is `UNSPENT` only after complete
coverage and explicit caller opt-in with `trust_backend_for_unspent=True`.
The default is `UNKNOWN` for negative results. Unsupported capability,
protocol mismatch, a scan over the configured bound, incomplete or malformed
responses, chain-tip inconsistencies, and backend failures also yield
`UNKNOWN`. The API does not include mempool coverage or make transaction
safety claims.

Pinned LWP v0.6.0 defines `GetBlockRangeNullifiers` but deprecates it in favor
of `GetBlockRange`; neither configured ZEC nor BTCZ currently declares the
dedicated method. The scanner uses `GetBlockRange` with no pool filter, as the
protocol specifies the default shielded-pool response. ZEC mainnet has
verified Sapling parameters, while BTCZ mainnet remains partial; both
Lightwalletd and compact-block endpoint capabilities are unverified. No
current endpoint is trusted for negative evidence by default.

Focused spent-status, nullifier-vector, tree/scanner, and Spend-validation
regressions passed **18 tests**. Targeted Ruff (`E4,E7,E9,F,I`),
`compileall`, Pylance diagnostics for `src/scanning.py` and its new test
module, and `git diff --check` passed.

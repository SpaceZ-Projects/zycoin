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

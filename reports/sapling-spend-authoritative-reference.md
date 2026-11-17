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
implementation and was not modified. Its production matrix fingerprint and
official-parameter binding are not inferred from the test-only result. The
isolated source-faithful composition passed complete ordered-matrix comparison
against the retained Bellman matrix for three valid witnesses. Independent
Bellman constraint-row exports for the two added witnesses, production Spend
matrix equivalence, and official parameter compatibility remain
**Unverified**.

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
trace remains the full matrix reference: 98,777 rows, 98,646 columns, and
matrix fingerprint
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
For each added case, a separate pinned Bellman `Spend::synthesize` run
exported all input/auxiliary identities, allocation events, annotations, and
assignments with constraint-row capture disabled. The Python path was then
fully synthesized and compared against the retained Bellman matrix and that
case's Bellman assignments. This avoids repeating a witness-independent
98,777-row Bellman export; it is not a claim that Bellman rows were separately
re-exported for either variant.

The first added witness uses value zero and alternating direction bits
(`true, false, ...`) over a 32-level path. Its Python full synthesis took
45.849 seconds in the final passing run. The second uses `u64::MAX` and 32
`true` direction bits; its Python full synthesis took 42.750 seconds. Both
cases use independent fixed RNG seeds and produce different `ak`, `nsk`,
`g_d`, and `rcv` assignments from the baseline. Their complete IVK and
nullifier BLAKE2s allocation groups, note-content hash, and `nk`
representation assignments also differ from baseline. Both preserve the
98,777-row / 98,646-column matrix and the fingerprint above. Allocation event
order, all variable identities and assignments, annotations, public-input
positions, every ordered A/B/C expression, and satisfaction results matched.

Post-synthesis circuit-level mutations were evaluated against the same
Bellman matrix and each case's independently exported assignments. Changing
only public `Input(5)` fails row 76,894 (`anchor/enforce input is correct`) in
both systems. Changing `Input(5)` and the conditional-anchor auxiliary
together leaves the conditional-root row satisfied for the zero-value case;
the same mutation fails row 76,893 (`conditionally enforce correct root`) for
the maximum-value case. Mutating `ak/u` and the first Merkle sibling also
produced identical failed-row tuples in the Python evaluator and the Bellman
matrix evaluator. These are post-synthesis witness mutations, not additional
invalid-input synthesis runs.

Final focused results: the retained baseline differential passed again
(1 test); the two added witness differentials passed (2 tests); and the
composition-boundary regressions passed (7 tests). The full Python synthesis
timings for the added witnesses are reported separately above. Ruff,
`py_compile`, Pylance file syntax validation, Rust formatting, and
`git diff --check` passed. An initial zero-value run exposed an incorrect test
expectation: changing the public anchor alone is not a no-op, because the
separate input-equality row remains enforced. The test now distinguishes that
row from the value-conditioned root row, and both variants pass the exact
failure-location assertions.

**Coverage status:** the isolated source-faithful port has exact matrix,
assignment, and satisfaction evidence for three valid witnesses, plus
post-synthesis anchor, point-coordinate, and authentication-sibling
mutations. Other witness families and independent full Bellman matrix exports
for the added witnesses remain unverified. Production Spend matrix identity,
official-parameter compatibility, and ceremony validity remain
**Unverified**.

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

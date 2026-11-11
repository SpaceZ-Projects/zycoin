# Sapling circuit implementation status

## Purpose and scope

Phases 9.20 through 9.20.2 investigate the exact Sapling Spend and Output
circuits, add a pure-Python R1CS foundation over ZyCoin's BLS12-381 scalar
field, and implement reusable bit, Jubjub, Pedersen, note-commitment, and
Merkle authentication-path gadgets. Phase 9.20.4 adds a constrained BLAKE2s
primitive and Sapling IVK/nullifier hash interfaces. Phase 9.20.5 adds a
reusable constrained fixed-base Jubjub multiplication gadget. Phase 9.20.6
adds standalone constrained value-commitment synthesis. Neither circuit was
Bellman-compatible in that initial baseline. Later Output alignment and
parameter-audit results are summarized below; trusted parameter-to-circuit
binding, proving readiness, and a Sapling spending API are not established.
Phase 9.20.7 adds standalone constrained nullifier multipacking.

**Current Output status (Phase 9.21.32):** the pinned Output fixture has an
exact ordered 7,827-row/7,827-column A/B/C and variable-assignment match,
and an independent Bellman 0.15 QAP reference matches three satisfying
witnesses. A test-only Bellman 0.15 loader and ZyCoin's production Python
parameter parser now agree byte-for-byte, in order, for all 32,016 official
Output query and IC points. Phase 9.21.29 established deterministic
test-only Python-to-Bellman proof interoperability. Phase 9.21.30 adds a
production-facing pure-Python API restricted to the exact pinned Output
parameters: two proofs generated for the pinned witness with OS-backed
randomizers differed and were accepted by Python and independent Bellman
0.15 verification. The focused security audit found and fixed an API misuse
gap that let `dataclasses.replace` reconfigure the supposedly opaque
parameter object; proving and verification now reject altered or uninitialized
objects. This verifies the API behavior for the tested witness and misuse
cases only; ceremony-to-circuit binding, ceremony validity, arbitrary-witness
security, Spend compatibility, and full production readiness remain
Unverified.

**Parameter trust boundary (Phase 9.21.32):** the production loader accepts
only the compiled whole-file SHA-256/BLAKE2b-512, length, format, and section
pins, and its parameter object cannot be reconfigured through supported API
use. This establishes exact file integrity relative to the pins; official
Output designation is supported by the recorded upstream source provenance.
The Bellman comparison establishes parser compatibility. Bellman's parameter
encoding has no circuit identifier, matrix fingerprint, or query labels, so
neither those pins nor matching counts establish key-to-matrix binding.
Circuit binding and transcript validity remain **Unverified**. The
`phase1radix2m13` initial Powers-of-Tau file, an exact ceremony-era Output
circuit/setup reproduction, and independent Phase-2 verification against
both are unavailable. Production use remains gated pending those artifacts
and exact final-parameter comparison to the pinned Output matrix. Regression
tests reject a same-length modified parameter file and a wrong digest even
when format and section counts match. The authentic Python proof/Bellman
verification regression remains passing; matrix and query-mapping
fingerprints are unchanged.

**Phase 9.21.31 security audit:** the parameter-object substitution finding
is fixed, with negative tests for altered parameter hashes, query objects,
verification keys, and uninitialized objects. The API review also rechecked
hash-pinned loading, witness satisfaction before randomness, named canonical
public inputs, proof-point validation, generic error handling, and the
test-only Bellman verifier. Ceremony validity, general parameter-to-circuit
binding, constant-time behavior, and memory zeroization remain Unverified;
see the security-audit entry in the Groth16 readiness report.

**Authentic Output MSM validation (Phase 9.21.27):** all five authentic
proving-query sections were accumulated with the optimized MSM after streaming
the hash-pinned official parameter file through the production parser. Full
results matched independently partitioned optimized accumulations; affine
double-and-add comparisons matched at both ends of manageable subsets.
Sparse A/B reconstruction, H coefficient ordering, L auxiliary ordering, and
scalar/window boundary checks passed. This is authentic-query MSM validation,
not full-vector independent oracle equivalence, proof construction, ceremony
validity, or production readiness.

**Complete authentic Output accumulation status (Phase 9.21.28):** all five
full proving-query accumulations and the six-term IC/public-input accumulation
match independent Bellman 0.15 results exactly. Bellman constructed its own
QAP quotient from the pinned ordered matrix and witness and applied the
independently loaded authentic points according to the checked sparse-index
map. Negative scalar, point-order, sparse-index, and public-input-order
mutations all changed the result. This establishes accumulation equivalence
only; proof generation, query-to-circuit binding, ceremony validity, and
production readiness remain Unverified.

**Current Spend correspondence status (Phase 9.21.34):** the v7 test-only
semantic mapping covers 8 public/ONE variables and 98,637 of 98,638
auxiliaries. The row artifact still pairs 98,775 of 98,777 constraints with
zero ambiguity. An independent algebraic audit establishes that the two
unmatched anchor formulations have the same projected relation and that the
local packed-position reconstruction is a redundant uniquely satisfiable
auxiliary relation. Together with the matched-row polynomial comparisons,
this supports semantic equivalence of the pinned exported R1CS relations
under the accepted role mapping and auxiliary projection. This is not a
formal source-level proof or a claim that arbitrary production synthesis
paths have been independently verified. Exact ordered Spend matrix alignment
and Groth16 compatibility remain **Unverified**.

**Spend QAP/query status (Phases 9.21.34–35):** both complete deterministic
assignments satisfy their respective matrices, mapped helper correspondence
is explicit, and independent quotient-divisibility checks pass. The
transformation audit accounts for row permutations, A/B swaps, nonuniform
factor normalizations, 333 expanded-relation-only matches, and the unmatched
conditional-anchor/packed-position helpers. Those transformations support
the projected relation but do not preserve the canonical QAP vectors: all
eight vectors differ. No exact transformation of the variable-indexed
QAP/query basis has been established. Semantic relation equivalence is
evidence-supported for the pinned exports but is not a formal source-level
proof; exact QAP equivalence, proving-query compatibility, parameter-to-
circuit binding, and ceremony validity remain **Unverified**.

**Spend circuit-specific setup status (Phases 9.21.36–37):** the local setup
identity is the 98,777-row, 98,646-column matrix with fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`,
seven public inputs in the recorded order, and 98,638 auxiliaries. Bellman-
style QAP construction adds eight dummy input rows and pads 98,785 rows to
domain size 131,072. Existing QAP/FFT, point, MSM, proof assembly, and
verification components are reusable, but no production setup generator or
parameter writer exists; the parser validates Bellman 0.15 serialization
without binding its points to this circuit. The official Spend parameters
must not be treated as local-circuit queries. A new, independently verifiable
circuit-specific ceremony would require an exact local setup hash and a
complete verified contribution chain. The existing official transcript still
cannot be independently verified because its required `phase1radix2m17`
artifact and exact ceremony-era setup evidence are unavailable. Phase
9.21.37 now demonstrates a full-size, explicitly insecure test-only setup;
its public toxic-waste values must never be treated as secure parameters.
Local parameter compatibility, ceremony validity, and Spend proving remain
**Unverified**; no production Spend proof was generated and no production
gate changed.

**Current authentic-parameter audit status (Phase 9.21.25):** the streaming
pure-Python parser individually validated prime-order subgroup membership for
all 469,709 authentic Spend and Output query points, in addition to canonical
encoding and curve membership. No query point was rejected. For Output, all
32,016 decoded point encodings and their section order exactly match the
points loaded independently by Bellman 0.15; the matrix-derived compact A/B
index mapping and existing fingerprints are unchanged. This establishes
parser-to-Bellman query serialization equality, but not an independent
derivation of authentic point values from the Output circuit. Both appended
suffixes match the documented `phase2` 0.2.2 serialization envelope (97
contribution records), but full cryptographic ceremony verification is
blocked by missing Phase-1 setup artifacts and exact ceremony-era circuit
reproductions. Ceremony validity, Spend query-to-circuit compatibility,
Python Spend proving, and production readiness remain **Unverified**.

### Phase 9.21.33 — Independent Spend parameter point compatibility

The test-only Bellman 0.15 exporter and production Python parser matched
every canonical IC and query-point encoding in order: 437,707 points total,
including the eight IC entries and 437,699 proving-query entries. The
official file was
47,958,396 bytes with SHA-256
`8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13` and
BLAKE2b-512
`8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c`.
The Bellman export SHA-256 was
`3fe887db75a587c1067286902fc8c2d96865ef3fe251a2bbaa1d22460d8c5685`.
This verifies parser/serialization compatibility only; it does not establish
Spend query-to-circuit binding or proving-key compatibility with the local
Spend matrix. Phase 9.21.34 separately generated a coherent Bellman assignment
and complete QAP for the deterministic fixture. Ceremony validity remains
**Unverified** because `phase1radix2m17` and the exact ceremony-era Spend
circuit/setup source are unavailable.

### Phase 9.21.34 — Independent Sapling Spend QAP compatibility

The test-only pinned Bellman 0.15 runner independently synthesized the
Sapling Spend circuit at `sapling-crypto` revision
`88a7946b4a3066787776e11f0a502654167e022d` and computed its complete QAP
from the deterministic satisfying fixture. The fixture is pinned upstream
Spend test iteration 0, generated with `XorShiftRng` seed
`5862be3d763d318d17db37325406bce5`; the Python fixture independently
reconstructs that generator sequence. The Bellman TestConstraintSystem
assertion was `d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`.
It reported 8 inputs including ONE, 98,638 auxiliaries, 98,777 constraints,
98,785 rows after dummy input rows, 32,287 padding rows, and domain size
131,072. The exported trace was 199,292,445 bytes with SHA-256
`a39e4d2d815dca24eead67996d94732dc9a12b13ac3f1c4881f5e5dadddf8feb`.

The Bellman assignment SHA-256 is
`429887b2897ce1ee6f4bf9707c7e28158ce66dc9ba9789dff708ce02a0fc3e57`;
the local assignment SHA-256 is
`4ca277581c10a4e20d576a787b771a9c36bbf9b0e26d3b920ef3ea66fd2b45a3`.
All 8 public/ONE values and all 98,637 semantically mapped auxiliaries agree.
The remaining upstream auxiliary `Aux(76805)` is explicitly retained as the
conditional-anchor helper equal to the public anchor, rather than assigned a
fabricated local column. Local variable 32,621 is the separately derived
packed Merkle-position helper, equal to the value reconstructed from the 32
direction bits. Both complete assignments satisfy their respective circuits.
The local matrix fingerprint is
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`; the
upstream matrix fingerprint remains
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
The query-map fingerprint remains
`183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08`.

The complete Bellman and local QAP calculations independently produced A, B,
and C evaluations; A, B, and C polynomial coefficients; quotient polynomial
coefficients; and H evaluations. All eight canonical vector fingerprints
differ:

| QAP vector | Bellman 0.15 SHA-256 | ZyCoin SHA-256 |
|---|---|---|
| A evaluations | `22c6662cbe967cb57bc36d05ebf3e81a32d3baa20bf222c0cf5581afd52993b6` | `daca49ab7a9dd2819f40d4b48e94509d78d24ad2fb4846062865cd5f9491fe1a` |
| B evaluations | `3169179e3f69d5755671e0f634789dbb3faaa2f7a6025779a6f2ac2240729e71` | `2430c5198e3c39c85dfda8256feb6fa822c40cca983c37dd510cbd1f89cdf198` |
| C evaluations | `df2e6de104f3acc367abee83ead55f275670a0e13720044e0d166465948dd872` | `f8efb2f3246022e9cbd1cbbdd551167f9d3d5ab8570d9b8fd273afae2c5d50a9` |
| A coefficients | `663ab1569c323f13cc1fd96163b330c8231f3fcb6521cdfa444b49474b03e0c6` | `ae3bf8a74b4d63fb70b10f8257b16c478d4830c70f67e106ca88a59102e8a856` |
| B coefficients | `b3b5f5a4504131db6fb1ac5fb00a66592448a6e5a59eec1494231db9faaed7ff` | `8a1504707c0e31a28e1af71c58067bf9baff8d64b74d0359942c5738da46e2c7` |
| C coefficients | `6e064cc613e33f7e57ca5183826352c25f2f0410e5ad7f59391cf7e35679880b` | `5dbc6116cbaa3eafca1b792deb0ce0603be484ec052e6fdcb979d3d05aca74c6` |
| Quotient coefficients H | `27d57fc5eae604c210feda073ee1befcb73a776ef6bf4b08ba25d00314037a55` | `a98ecf083b7660a04fd59fc887e7799cf96c1e0cf5e4cd898690340125850862` |
| H evaluations | `b7ee1b2f7f49704446fb4acdc4dcf8e9a859ebeddcd9994d1aa2ec5a3023bb7d` | `04d75e396d3c01478d7de835da712c7a10eecdec070fd79a0781d60ee30f65c7` |

Bellman's quotient divisibility check passed using its independent 2n FFT
identity check. ZyCoin's quotient passed an independent 2n coset-FFT
identity check. These results verify each implementation's QAP arithmetic
for this witness, not equality between the local and upstream canonical QAP
vectors. The observed vector differences are consistent with their different
matrix formulations/order. Phase 9.21.35 traces them to moved row indices,
A/B swaps and normalizations, expanded-equation-only rows, and the explicit
helper projection; it quantifies their effect on the witness vectors. The
precise compatibility blocker is the absence of a validated transformation
of all variable-indexed QAP polynomials and the resulting proving queries.
The vector differences alone do not establish semantic incompatibility. The
parameter point-serialization match from Phase 9.21.33
does not establish that the official proving queries bind to the local
matrix. No Spend proof was generated and no production Spend path or proving
gate was changed.

Validation: `python -m unittest tests.test_sapling_spend_qap_compatibility`
passed all 5 tests in 161.213 seconds. The tests pin the source revisions,
trace and assignment hashes, matrix/query fingerprints, all eight QAP vector
hashes, full satisfaction, helper correspondence, and both quotient checks;
negative cases reject altered public inputs, an invalid witness, an incorrect
variable map, and a corrupted QAP fingerprint. The combined regression
`python -m unittest discover -s tests -p 'test_sapling*.py'` passed all 195
Sapling tests with 1 skipped in 1,487.275 seconds, including Spend and Output
circuit, QAP, parser, and compatibility-manifest regressions.

### Phase 9.21.35 — Spend QAP transformations and proving-query semantics

This audit uses the saved Spend row-correspondence artifact
`44a14939955a9a82a24f4013bb0b9144a1810b648d6e4d9d3643117330b58ecc`,
the v7 variable correspondence, the deterministic iteration-0 witness, and
the independent QAP results from Phase 9.21.34. The row artifact pairs 98,775
rows without using ordinal or witness satisfaction as identity: 69,840 rows
have identical A/B/C factors, 251 are A/B swaps, 28,351 have invertible
factor normalizations, and 333 match only after expanding `A*B-C`. Of the
paired rows, 48,546 move to a different index and 50,229 retain the same
index. There are no ambiguous matches, but two rows on each side remain
unmatched.

The 333 expanded-only matches are 251 `pk_d` selection relations, 64
Merkle-path left/right relations, and 18 other curve, representation, public
input, and nullifier-packing relations. All 333 expanded polynomials match
with unit scale. This proves equality of those row equations after expansion;
it does not give a factor-by-factor transformation for their A, B, and C
query polynomials. On the pinned satisfying assignment, 332 of those 333
matched rows have different A/B/C factor-value triples despite the same
expanded equation.

The 28,351 factor-normalized rows use nonzero, but nonuniform, profiles:

| Count | Orientation | Local factor scale for upstream A | For upstream B | Local C scale |
|---:|---|---:|---:|---:|
| 18,754 | swapped | `p-1` | `1` | `p-1` |
| 9,533 | swapped | `2` | `(p+1)/2` | `1` |
| 64 | same | `p-1` | `1` | `p-1` |

For each normalized row, the relation-preserving rule is
`A' = sA*A`, `B' = sB*B`, `C' = sA*sB*C`. The witness-level checks verified
all 28,351 scale equations. 23,529 normalized rows changed their A/B/C value
triple for this witness; 4,822 happened to have identical triples at these
particular values. The separate 251 A/B-swap rows also preserve each row
product while swapping the A and B query contributions.

The unmatched helper structures are not ordinal substitutions. Upstream
rows 76,893 and 76,894 impose `(R-T)*V=0` and `public_anchor*ONE=T`, where
`T=Aux(76805)`. The local circuit projects out `T` to impose
`(R-public_anchor)*V=0`; it also has the unmatched row 32,701 reconstructing
the packed Merkle position at local column 32,621 from the 32 direction bits.
The local conditional-anchor row is 76,894. This supports the documented
existential relation projection, but it does not supply a one-to-one
variable/query map: `T` is the anchor, while local column 32,621 is the path
position.

For the same satisfying witness, the mapped row evaluations differ by
same-index position in 45,434 of 131,072 A entries, 47,272 B entries, and
29,010 C entries; 50,181 constraint rows differ in at least one A/B/C value.
After interpolation, every coefficient differs in each of the 131,072-entry
A, B, and C vectors. All 131,071 quotient coefficients and all 131,072 H
evaluations differ. Independently reconstructed upstream vector hashes match
the Bellman reference hashes from Phase 9.21.34. Both quotient identities
still pass.

These are distinct claims:

| Claim | Status |
|---|---|
| Semantic relation equivalence | Evidence-supported for the pinned exports under the accepted variable map and helper projection; not a formal source-level proof. |
| Exact canonical QAP equivalence | **Unverified**; all eight vectors differ. |
| Proving-query compatibility | **Unverified**; no complete transform for A/B G1/G2, IC, and L queries has been established. |
| Parameter-to-circuit binding | **Unverified**; point serialization compatibility does not bind parameters to this QAP. |
| Ceremony validity | **Unverified**; required Phase-1 and exact setup-era artifacts are unavailable. |

Row permutation preserves the conjunction of row equations but changes their
placement in the Lagrange basis. A/B swaps and row-wise factor normalization
preserve row zero sets but change factor polynomials and therefore do not
establish equality of Groth16 queries. Expanded `A*B-C` equality also does not
determine the factor vectors. The common domain size gives both circuits the
same generic H-query basis shape (`tau^k * Z(tau) / delta`), but the
witness-specific H coefficients differ, and that fact says nothing about
compatibility of the circuit-specific A/B/IC/L queries.

The precise blocker is the absence of a complete, validated transformation
of every variable-indexed QAP polynomial and helper coordinate into the
pinned setup's proving-query basis. The parameter file contains setup points
at the ceremony's secret evaluation point, not the underlying polynomials or
toxic-waste scalars. A single witness's QAP vectors can reject direct
identity, but cannot provide that transformation or rule out accidental
point equality at the hidden setup point. Further evidence would require a
complete row-domain and variable-space transform with a proof of its effect
on all A/B/IC/L query coordinates, or an independently verified setup rerun
for the local matrix and point-by-point comparison. No Spend proof was
generated and no production code, parameter pin, or proving gate changed.

Validation: `python -m unittest tests.test_sapling_spend_qap_transformations
tests.test_sapling_spend_row_correspondence` passed 15 tests, including
relation-preserving row permutation, A/B swap, nonuniform scaling, expanded
relation, malformed row maps, and invalid factor scaling. The existing
variable-map negative test continues to reject mismatched assignments.
Final validation: `python -m unittest discover -s tests -p 'test_sapling*.py'`
passed all **201 Sapling tests** with **1 skipped** in **1,314.384 seconds**.
This included the official Spend parameter parser comparison and retained the
authentic Output interoperability regressions.

### Phase 9.21.38 — Official Sapling Spend full-vector query accumulation

The official file at `%APPDATA%\ZcashParams\sapling-spend.params` was read
in full by ZyCoin's bounded parser and independently loaded by the pinned
Bellman 0.15 reference. The file size is 47,958,396 bytes, SHA-256
`8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13`, and
BLAKE2b-512
`8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c`.
All 437,707 canonical point encodings were compared byte-for-byte, in exact
IC, H, L, A, B_G1, B_G2 order; the parser verified curve/subgroup validity,
section counts, exact file digests, and the 52,836-byte trailing transcript
boundary. Section sizes were IC 8, H 131,071, L 98,638, A 85,390,
B_G1 61,300, and B_G2 61,300. This confirms stream integrity and parser
compatibility, not circuit binding or ceremony validity.

The deterministic pinned Sapling Spend test witness (Bellman assignment
SHA-256
`429887b2897ce1ee6f4bf9707c7e28158ce66dc9ba9789dff708ce02a0fc3e57`)
was independently synthesized and its complete quotient computed by Bellman
0.15. The corresponding satisfying ZyCoin witness has local matrix
fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`;
98,637 auxiliary values are mapped one-to-one, and upstream `Aux(76805)` is
explicitly represented by its anchor value, not assigned a fabricated local
column. ZyCoin then used its production full-vector BLS12-381 MSM primitive
on every parsed official point and the complete local assignment/QAP vectors.
No sample-only or scalar-exponent shortcut was used. A separate Rust
test-only Bellman 0.15 runner loaded the same official parameter file and
performed complete MSMs for the Bellman assignment and quotient.

The exact accumulated point results were:

| Section | Bellman / ZyCoin |
|---|---|
| IC | Equal |
| H | **Different** |
| L | Equal |
| A | Equal |
| B_G1 | Equal |
| B_G2 | Equal |

SHA-256 of the uncompressed accumulated H points is Bellman
`a95259f4792a7727f33efa3eb466b5a1481f06c494182ffd091e46ef39bfd7fe` and
ZyCoin `1336802122c751934174ee3689fc8b140240b85e1ab4142a019ed611461742c7`.
The Bellman and local quotient coefficient hashes are already recorded in
Phase 9.21.34 as
`27d57fc5eae604c210feda073ee1befcb73a776ef6bf4b08ba25d00314037a55` and
`a98ecf083b7660a04fd59fc887e7799cf96c1e0cf5e4cd898690340125850862`,
respectively. The H accumulation mismatch is consistent with the different
local and upstream QAP quotient vectors. IC/A/B/L equality for this
assignment follows from the equal mapped witness scalars in those query
coordinates; it does not show those query vectors encode the local circuit.

**Conclusion:** the official parameter file's query points parse correctly,
but their complete H accumulation does not agree with the local Spend QAP
for this deterministic satisfying witness under the current direct mapping.
The official file therefore does not establish support for ZyCoin's local
Spend circuit, and the observed H mismatch is a concrete direct-compatibility
failure for this witness. No row/query transformation was manufactured, no
Spend proof was generated, and no production circuit, parameter pin, or
proving gate changed. Exact parameter-to-circuit binding, ceremony validity,
and Spend proving remain **Unverified**.

The dedicated full-vector test passed in **1,152.794 seconds**; the
independent Bellman accumulation itself took **155.485 seconds**. It checks
all point encodings and section order, all six complete accumulations,
assignment correspondence, the parser's final integrity manifest, and
fixed matrix/query fingerprints. No Output equations or proof interoperability
fixtures were changed.
The complete Sapling regression command
`python -m unittest discover -s tests -p 'test_sapling*.py'` passed **206
tests** with **1 skipped** in **2,844.775 seconds**, including Output
interoperability, Spend, parser, and compatibility-manifest regressions.

### Phase 9.21.36 — Sapling Spend circuit-specific setup requirements

The local Spend setup identity is the canonical ordered
`zycoin-r1cs-matrix-v1` matrix, fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`:
98,777 constraint rows and 98,646 columns including ONE. Column 0 is ONE;
columns 1–7 are `rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`,
`nullifier_chunk_0`, and `nullifier_chunk_1`; columns 8–98,645 are 98,638
private auxiliaries in local allocation order. The ordered allocation
manifest hash is
`cc8289461de9acb811ff5ceacb239d035e00483d7c5d6227b7887e0cbc5f2be7`.
Matrix serialization preserves constraint insertion order, canonicalizes
each A/B/C linear combination by sorting columns and combining duplicate
terms modulo the scalar field, omits zero terms, and excludes labels,
variable names, and assignments from its fingerprint.

The local QAP uses the BLS12-381 scalar field. It appends eight
`Input(i)*0=0` setup rows after the 98,777 circuit rows, yielding 98,785
occupied rows, then pads with 32,287 zero rows to a 131,072-point radix-2
domain. Evaluations use natural `omega^j` order; inverse FFT returns
ascending-degree polynomial coefficients. The domain root is
`omega = 7^((SCALAR_MODULUS-1)/131072) mod SCALAR_MODULUS`, and the FFT
coset generator is 7. The quotient is divided by `X^131072-1`, and H has
131,071 query entries. A local circuit-specific parameter set must bind
these exact row/variable conventions, not merely matching dimensions or a
power-of-two domain.

For this setup, IC contains eight G1 points including ONE; dense A, B_G1,
and B_G2 vectors each have 98,646 variable positions in ONE/public/auxiliary
order; L contains 98,638 auxiliaries; H contains 131,071 points. Bellman
serialization orders verification-key points and IC before H, L, A, B_G1,
and B_G2. Serialized A/B vectors omit identity points, so their circuit-
specific omitted-position maps are necessary to recover dense query order.
The existing parser understands Bellman 0.15 encoding and point validation,
but that format has no circuit ID, matrix fingerprint, variable labels, or
sparse indices. The encoding uses canonical uncompressed BLS12-381 points
(96-byte G1 and 192-byte G2) with curve and subgroup validation. No production
setup generator or parameter writer was found.
The existing official Spend mapping describes its upstream parameter points,
not queries derived for the differing local QAP.

Reusable production components are the local R1CS/QAP/FFT construction,
validated BLS12-381 points, ordered query/MSM operations, proof equation
assembly, and verification. None performs trusted setup, authorizes a
parameter source, or proves that its points came from this local matrix.
The existing test helper
`tests/test_groth16_end_to_end.py::_synthetic_setup_for_qap` creates keys
from explicitly known toxic-waste scalars and is demonstrated only on small
QAPs. It allocates three `variable_count × domain_size` evaluation tables;
at Spend dimensions this is about 38.8 billion slots (approximately 311 GB
of 64-bit list references, excluding other allocations). It was not run for
Spend. A more memory-efficient test-only synthetic setup could exercise the
local query/proof/verifier algebra, but any successful proof would test
software plumbing only and must never be treated as production parameters or
ceremony evidence.

The official file's SHA-256 pin
`8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b756efc13`
establishes integrity relative to that pin, not compatibility with the local
matrix. The transcript format audit identifies `phase2` 0.2.2 at commit
`0c2b25fe8879deeb46530e91a5654d353a9bf94c`; verifying the existing transcript
requires the exact ceremony circuit/setup hash and `phase1radix2m17` initial
powers. Those prerequisites are absent. For a new local setup, the old
upstream circuit source is not required if the exact local matrix and its
setup hash are reproduced; instead, a pinned compatible ceremony
implementation, fresh circuit-specific contribution chain with at least one
honest contributor, and independent verification of every contribution and
the final key are required. The old Sapling Spend transcript cannot be
transferred to the local QAP. Circuit-specific parameter compatibility and
ceremony validity remain **Unverified**. No setup, Spend proof, production
circuit change, or proving-gate change was made.

Validation: `python -m unittest discover -s tests -p 'test_sapling*.py'`
passed **201 tests** with **1 skipped** in **1,269.139 seconds**.
`python -m unittest tests.test_groth16_end_to_end
tests.test_groth16_parameter_parser` passed **46 tests**. Manifest JSON and
the recorded matrix/QAP dimensions were checked successfully.

### Phase 9.21.37 — Memory-bounded full-size synthetic Spend setup

Added test-only tooling in
[`tests/sapling_spend_synthetic_setup.py`](../tests/sapling_spend_synthetic_setup.py)
and
[`tests/test_sapling_spend_synthetic_setup.py`](../tests/test_sapling_spend_synthetic_setup.py).
It targets the exact local Spend matrix fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`
(98,777 rows, 98,646 columns), with a 131,072-point domain and 131,071 H
entries. It computes the QAP setup scalars by barycentric evaluation and
sparse row accumulation; an independently traversed column-major reference
and selected inverse-FFT column calculations agree. Fixed-window G1/G2
generation with 512-point batch normalization avoids materializing the
previous three approximately 311 GB evaluation tables. It serializes and
reloads all test-only IC, H, L, A, B_G1, B_G2, and verification-key sections
in a private format. The production Bellman parameter parser rejects that
format.

The fixture uses the disclosed toxic-waste tuple
`(alpha, beta, gamma, delta, tau) = (3, 5, 7, 11, 2)` and is explicitly
insecure. Full-size query exponent vectors and their scalar accumulation pass
independent arithmetic checks. The production proof assembler and verifier
are exercised end to end; to keep the pure-Python full-vector MSM tractable,
the test substitutes a test-only scalar-exponent MSM oracle during full proof
assembly. Actual production G1/G2 MSM is separately compared with scalar
references on 64-point samples from A, B_G1, B_G2, L, and H. Therefore this
is not a full-vector production-MSM benchmark or production proving result.
The resulting synthetic proof is accepted by the local verifier; no
independent ceremony or official-parameter claim follows.

The dedicated suite passed **4 tests** in **431.399 seconds**. Measured full
run elapsed time was **428.363 seconds**, setup calculation/write/reload took
**366.642 seconds**, proof assembly took **15.868 seconds**, independent
reference checks took **14.242 seconds**, verification took **1.365 seconds**,
and peak working set was **611,672,064 bytes**. The serialized fixture was
**59,934,611 bytes** (SHA-256
`579199bf8c8bf3c703dfca6160a967e619b250b907907af104e4f9050281aba0`).
The scalar-vector SHA-256 values are A
`82e0264be14b37afb5f75fb595835684a0229a37a6124da8f4fef7b378859a80`,
B `441cb3eb5f58129305f58ae8dfb7ca01f4e06a930a387c277cca5393294ccc4f`,
and C
`b316f89b8951d0e7b29aa802a3acfa0ef5885456ec9bfdb8ff408bf38e8bf93a`.
Negative coverage rejects a wrong circuit fingerprint, malformed synthetic
file, production-parser use, unsatisfied witness, altered public input, and
corrupted proof. Synthetic setup/proof material, Spend ceremony validity,
official parameter-to-local-circuit binding, and Spend proving remain
**Unverified**. No production circuit, official parameter pin, or proving
gate changed.

The complete Sapling regression command
`python -m unittest discover -s tests -p 'test_sapling*.py'` passed **205
tests** with **1 skipped** in **1,776.259 seconds**, including the official
Spend parameter compatibility, Output interoperability, and compatibility-
manifest regressions. Its process-wide peak working set was
**1,154,809,856 bytes**; this includes all earlier tests in that process and
is not an isolated synthetic-setup measurement.

### Phase 9.21.17 — Independent Spend semantic equivalence audit

The audit compares the pinned Bellman export and local Spend rows as
polynomial relations, not by row order or witness satisfaction. The existing
98,775 row pairs are preserved: native factors, swaps, nonzero
factor-normalizations, and expanded `A*B-C` comparisons all describe the
same zero set over the BLS12-381 scalar field. The variable mapping remains
v7; no variable or row identity was inferred from assignments.

For the conditional anchor, let `R` be the final Merkle root, `T` the
upstream `conditional anchor/num`, `A` the public anchor, and
`V = Σ(i=0..63) 2^i v_i` the 64-bit note-value opening. The upstream rows
impose `(R-T)V=0` and `A-T=0`. The second equation forces `T=A`, so the
first becomes `(R-A)V=0`, exactly the local conditional-anchor row. In the
reverse direction, any local assignment extends to an upstream assignment
by choosing `T=A`. This also covers zero value: when `V=0`, the root may
differ from the public anchor, but the upstream auxiliary must still equal
the public anchor. Since `V` is a 64-bit integer embedded in the much larger
scalar field, it is nonzero in the field exactly when the integer value is
nonzero.

Both circuits represent `V` by 64 Boolean bits in little-endian order: the
pinned source uses `u64_into_boolean_vec_le` in `circuit.rs:115-116` and
accumulates those bits with powers of two at `circuit.rs:265-277`; local
Spend validates the unsigned 64-bit value and synthesizes its value bits
before the note commitment. Boundary probes cover `V=0`, `V=1`, and
`V=2^64-1`; mismatched roots are accepted only at zero value. A deliberately
misbound upstream `T` is rejected even at zero value; it is not a
counterexample because `T=A` is an upstream constraint.

For Merkle position, at path level `i`, the pinned circuit allocates a
Boolean `cur_is_right` from the authentication-path direction and appends
that bit to `position_bits` (`circuit.rs:327-345`). `ecc.rs:27-28` specifies
that fixed-base multiplication consumes little-endian bits. Therefore the
position used by `g^position` is `P = Σ(i=0..31) 2^i d_i`, with `d_i=1`
meaning the current node is the right child at level `i`. Local
`constrain_merkle_authentication_path` range-checks a packed 32-bit `P`,
uses `position_bits[i]` at that same path level, and reconstructs
`P=Σ2^i d_i`; `_prepare_witness` also checks the witness position against
the path directions. The packed local scalar occurs only in that
reconstruction relation; downstream nullifier synthesis consumes the same
32 bits. Consequently, every Boolean direction vector has exactly one local
packed scalar in `[0,2^32)`, while the upstream circuit uses the vector
directly. The extra local row adds no restriction after existentially
projecting away that scalar.

Independent relation-level witnesses cover positions `0`, `1`, `2^31`, and
`2^32-1`, confirming the least-significant-level-first interpretation.
Invalid cases include non-Boolean directions/value bits, a packed position
outside the unsigned 32-bit range, and a packed value inconsistent with its
bits. The local conditional-anchor R1CS is checked directly for valid and
invalid assignments; the pinned upstream anchor equations are separately
evaluated from their exported relation. These are focused subrelation
witness tests, not fresh full Bellman circuit runs for each boundary value.

The full pinned export comparison plus the two projection arguments supports
the same semantic relation for the compared pinned R1CS exports. It is not a
formal proof of source-code equivalence across all synthesis paths, nor does
it establish exact ordered matrix equality, authentic parameter/query
compatibility, or proof-generation readiness. Existing export artifacts and
all accepted mappings remain unchanged.

Test-only implementation:
[`sapling_spend_semantic_equivalence.py`](../tests/sapling_spend_semantic_equivalence.py)
and
[`test_sapling_spend_semantic_equivalence.py`](../tests/test_sapling_spend_semantic_equivalence.py).
The deterministic boundary-probe SHA-256 is
`94d29c70b4f5ce62e37ffa0083300fa7025699b90fbc81c7c16a6b1e278964cd`.
The row artifact regenerated byte-for-byte (SHA-256
`44a14939955a9a82a24f4013bb0b9144a1810b648d6e4d9d3643117330b58ecc`),
and the v7 variable artifact remains unchanged (SHA-256
`efa67820fdbaf0410cc1fad7380f2468173fedc5fa25ae8366ed0e067124046f`).
Focused semantic tests passed (**8 tests, 17 subtests**); the updated
correspondence/manifest focused set passed (**50 tests, 28 subtests**). The
targeted Spend, Output, Bellman, QAP, Groth16, and compatibility suite passed
(**276 tests, 570 subtests**).

### Phase 9.21.16 — Investigate remaining Spend row mismatches

The four unmatched rows trace to two separate formulation differences:

| Side / row | Source and allocation provenance | Exact relation and dependencies |
|---|---|---|
| Upstream 76893, `conditionally enforce correct root` | Pinned `sapling-crypto` source `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-crypto-reference\src\circuit.rs` allocates `rt` in namespace `conditional anchor` at line 382 and enforces the relation at lines 390–394. `rt` is `Aux(76805)`; the computed final root is `Aux(76803)`. | `(Aux(76803) - Aux(76805)) * V = 0`, where `V = Σ(i=0..63) 2^i * Aux(27812+i)`, the 64 note-value bits. A is two terms, B is 64 terms, C is zero. |
| Upstream 76894, `anchor/enforce input is correct` | `rt.inputize(cs.namespace(|| "anchor"))` at pinned `circuit.rs` line 397. This is the Bellman public-input binding for the conditional-anchor auxiliary. | `Input(5) * Input(0) = Aux(76805)`; `Input(0)` is ONE and `Input(5)` is the public anchor. The upstream `rt` allocation's event index is 76810; its typed identity is `Aux(76805)`. |
| Local 32701, `Sapling Spend Merkle path position bit reconstruction` | Local [`sapling_gadgets.py`](../src/sapling_gadgets.py) allocates `Sapling Spend Merkle path position` at line 2974 and range-checks it at line 2975 in `constrain_merkle_authentication_path`, called from [`sapling_spend_circuit.py`](../src/sapling_spend_circuit.py) line 443. Local variable index 32621 has role `merkle/path/position` and is the unresolved local allocation. | `(position - Σ(i=0..31) 2^i * position_bit[i]) * ONE = 0`; A contains 33 terms, B is ONE, C is zero. The 32 bits themselves already map to the upstream per-level `position bit` allocations and their Boolean rows. Upstream consumes those bits directly and has no packed-position scalar or equivalent reconstruction row. |
| Local 76894, `Sapling Spend Merkle path conditional anchor` | Local [`sapling_gadgets.py`](../src/sapling_gadgets.py) calls `constrain_sapling_conditional_anchor` at line 3028; its enforcement is at line 3085. The root is the mapped final Merkle root and the anchor is the mapped public input. | `(root - public_anchor) * V = 0`, with the same 64 note-value bits, and C zero. A contains two terms, B 64 terms. |

The v7 mapping independently maps local public anchor to upstream `Input(5)`,
the local final root to upstream `Aux(76803)`, and all 64 local note-value
bits to upstream `Aux(27812..27875)`. Substituting
`Aux(76805) = Input(5)` using upstream row 76894 makes every mapped A/B/C
term in upstream row 76893 identical to local row 76894. Thus the anchor
relation has a defensible **two upstream rows to one local row** algebraic
correspondence. No variable identity is added: `Aux(76805)` and `Input(5)`
are distinct upstream variables connected by a constraint, and the row
artifact only accepts one-to-one row pairs. The equal witness assignments
are a consistency check, not identity evidence.

The other unmatched row, local 32701, is a local representation helper:
the private packed position exists only to be reconstructed from the already
mapped direction bits. Pinned Bellman uses those bits directly for path
ordering and the position-generator multiplication. It does not allocate
the packed scalar. This is a genuine synthesis-shape difference, but no
incorrect anchor equation or false one-to-one row counterpart was found.
The investigation therefore identifies a missing **multi-row/substitution**
comparison rule for the anchor and an additional local-only position
reconstruction relation; it does not prove complete circuit equivalence.

The existing transformed matches do not hide another counterpart. All 32
position-bit Boolean constraints are already paired as
`valid_factor_normalization` matches. Of the 333 expanded-relation-only
pairs, the two in the final Merkle level are the `ul` and `ur` unpacking /
bit-reconstruction rows (upstream 75769 ↔ local 75770 and upstream 76025 ↔
local 76026); neither is an anchor or packed-position relation. The
28,351 factor-normalization pairs remain unchanged; none supplies a
one-to-one match for the unmatched position reconstruction or the upstream
anchor auxiliary. All 333 expanded pairs retain unit scale.

No variable or one-to-one row mapping was added or changed. The v7 variable
mapping SHA-256 remains
`efa67820fdbaf0410cc1fad7380f2468173fedc5fa25ae8366ed0e067124046f`;
the row artifact SHA-256 remains
`44a14939955a9a82a24f4013bb0b9144a1810b648d6e4d9d3643117330b58ecc`,
with row-mapping fingerprint
`f502b0f22dece3829d6e2e1e198ca8d98d82e233e9eb1a4dcded3a399f6ae17d`
and coefficient fingerprint
`883e9561c0f159bafc17f65977d1311f30f8f6e39bf66569fde51c85a24c3a32`.
Deterministic regeneration reproduced the row artifact byte-for-byte; the
accepted mapping has zero ambiguities and zero assignment mismatches.

Validation: the focused row/variable/manifest tests passed (**42 tests,
11 subtests**); the targeted Spend, Output, Bellman, QAP, Groth16, and
compatibility regression set passed (**216 tests, 280 subtests**). No
production Spend or Output synthesis code changed.

### Phase 9.21.15 — Establish Spend ordered-row correspondence

The test-only comparison uses the v7 semantic variable mapping and uniquely
matching A/B/C factor signatures, followed by unique expanded `A*B-C`
signatures for residual rows. Neither row indices nor witness satisfaction
select row pairs. Exact coefficients and variable references are recorded;
all 333 expanded-relation-only pairs have unit polynomial scale. Of the
98,775 pairs, 50,229 retain the same row index and 48,546 are reordered.
No ambiguous row pairs were accepted.

The two unmatched upstream rows are 76893 (`conditionally enforce correct
root`) and 76894 (`anchor/enforce input is correct`), which reference
unmapped upstream `Aux(76805)`. The unmatched local rows are 32701
(`Sapling Spend Merkle path position bit reconstruction`) and 76894
(`Sapling Spend Merkle path conditional anchor`). The local position variable
and upstream conditional-anchor variable have distinct source roles; they
remain unmapped, and row correspondence does not resolve that variable gap.
Consequently, exact ordered Spend matrix alignment is **not established**.

The machine-readable row artifact is
`C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-row-correspondence-v1.json`
(SHA-256 `44a14939955a9a82a24f4013bb0b9144a1810b648d6e4d9d3643117330b58ecc`;
row-mapping fingerprint
`f502b0f22dece3829d6e2e1e198ca8d98d82e233e9eb1a4dcded3a399f6ae17d`;
coefficient fingerprint
`883e9561c0f159bafc17f65977d1311f30f8f6e39bf66569fde51c85a24c3a32`;
content fingerprint
`a22e02d13ad12988836eba4dc2985060197c38c9fd9ca50d8e468191290f5609`).
Fresh production Spend synthesis matched the saved local export at 98,777
rows and 98,646 columns, including its matrix fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`,
labels, allocation names, and A/B/C terms. Both exported witnesses satisfy
their matrices, with zero assignment mismatches among mapped variables.
These results do not establish complete Spend correspondence or circuit
equivalence.

Validation: focused row/variable correspondence tests passed (**28 tests,
6 subtests**); the targeted Spend, Output, Bellman, QAP, Groth16, and
compatibility regression set passed (**216 tests, 280 subtests**).

### Phase 9.21.14 — Resolve remaining Spend variable correspondence

Test-only role translations identified 64 additional auxiliary variables:
authorization-key point interpretation (3), authorization-key small-order
checks (16), `g_d` point interpretation (5), `g_d` small-order checks (16),
randomized authorization-key addition outputs (6), value-commitment output
relation (6), note-commitment randomization (6), and faerie-gold prevention
(6). Every new identity was selected from source/gadget role and invocation
context; assignment equality was checked only after matching. No production
Spend or Output circuit was modified.

The v7 correspondence maps 8 public/ONE variables and 98,637 auxiliaries,
retains all 98,573 v6 pairs unchanged, and leaves one unmatched allocation
per side with zero ambiguity and zero accepted-pair assignment mismatches.
The local unresolved allocation is the 32-bit Merkle path position scalar;
the upstream unresolved allocation is `conditional anchor/num`. The local
path position is a range-checked input to the path-direction reconstruction,
while the upstream allocation is scoped to the conditional-anchor relation.
Neither matching position nor witness values establishes a shared identity.
Complete semantic correspondence is therefore not established and cannot be
claimed from the available metadata.

Artifacts:

- Local trace:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-local-gadget-provenance-v7.json`
  (SHA-256 `3a21ec9b20772086a0ae97c4b12f916266c732c4edff944fc83d27a4be60eb90`).
- Variable correspondence:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-variable-correspondence-gadget-v7.json`
  (SHA-256 `efa67820fdbaf0410cc1fad7380f2468173fedc5fa25ae8366ed0e067124046f`;
  mapping fingerprint `26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656`).
- Gadget crosswalk:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-gadget-allocation-crosswalk-v7.json`
  (SHA-256 `0b2b37a5ada665f4d1a640618275c02cea320555b5d58e0a8580b87f25573356`;
  mapping fingerprint `a54e423b92a0fc7649b7d4ad75e369fe957069c151c229b26f0075bb60f38a5b`).
- Provenance analysis:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-allocation-provenance-analysis-v7.json`
  (SHA-256 `4fea9950d68756db8bf4a0137df6bc9a1319234eae70c2bb87c14997c9ad14f8`).

Spend row alignment, complete Spend recorder synthesis, authentic parameter
compatibility, and production proof generation remain **Unverified**.

Validation: focused correspondence and manifest tests passed (**47 tests,
20 subtests**). The targeted Spend, Output, Bellman, QAP, Groth16, and
compatibility regression set passed (**207 tests, 280 subtests**); modified
Python helpers and tests passed `py_compile`. Deterministic regeneration
reproduced the correspondence, crosswalk, and analysis SHA-256 values exactly.
A repository-wide `git diff --check`
continues to report trailing whitespace in the unrelated, already-modified
`src/manager.py`; that file was not changed for this task.

### Phase 9.21.13 — Extended Spend scalar-multiplication correspondence

The test-only local provenance trace adds stable semantic roles for the
variable-base `pk_d` multiplication, fixed-base `nk` multiplication, and
randomized authorization-key multiplication. Identities encode operation
kind, window or operation index, and named coordinate/intermediate role;
assignments are checked only after unique semantic pairing. The resulting
correspondence retains all 90,356 prior mappings and adds 4,752 unique pairs.

The local trace artifact is
`C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-local-gadget-provenance-v5.json`
(SHA-256 `03d47ad04effdb0ce06cd7dcc8864475b126311da0821d57fb045d2dec037838`).
The correspondence artifact is
`C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-variable-correspondence-gadget-v5.json`
(SHA-256 `d16a8a3e4b31a9c8f89b539e2be739197102b7a3a2c120bcbb9d83be21d9ad67`,
mapping fingerprint `66d15a885656450f0a2fbcf24ebe41fd7f5e5e2de3e401b478d6edaa1f0d3359`).
The allocation crosswalk covers 46 gadget-invocation groups (SHA-256
`d955e449daca02de8688d91b59ee8617b692aa4ce232d28174c048dbfac3ff40`,
fingerprint `5d4ec5c712eda4722c4c8439384886100ff597df95df6673271e94ed8492ec87`).
The provenance analysis SHA-256 is
`9c6cdc6be134411f44851e8cea5fdb5d5a4da88159c7556a76c0d396021b7758`.

The 3,530 unresolved auxiliary variables on each side remain unmatched;
accepted matches have zero ambiguity and zero assignment mismatches. Remaining
unmapped families are concentrated in note-commitment Pedersen, value
commitment multiplication, local public/witness allocation-scope roles,
nullifier-rho multiplication, and a small set of point/ownership and
Merkle-combination allocations. The pinned upstream trace also exposes
repeated bare labels, so labels and assignment values are not accepted as
identity evidence. No production circuit code changed, no Spend row alignment
was started, and authentic Groth16/parameter compatibility remains
**Unverified**.

Validation: the full requested Spend, Output, Bellman, QAP, Groth16, and
compatibility regression set passed (**199 passed, 265 subtests passed**).
The focused provenance, correspondence, and manifest set passed (**39
passed, 5 subtests passed**); deterministic artifact regeneration reproduced
the correspondence, crosswalk, and analysis hashes. Modified Python files
compiled successfully, the compatibility manifest parsed as JSON, and
`git diff --check` passed for the changed files.

Phase 9.20.3 audited the prerequisites for a complete Spend circuit against
the same pinned upstream source. It did not add an incomplete circuit API:
the required commitment components, full input mapping, and independent
end-to-end Spend vector are not available in ZyCoin. Phase 9.20.8 audits those
components in synthesis order and verifies only the safe BLAKE2s-output to
nullifier-public-input packing boundary; no Spend circuit API is exposed.
Phase 9.20.9 audits the pinned Output circuit against the existing standalone
gadgets; it does not assemble or expose an Output circuit API.
Phase 9.20.11 adds and vector-tests only the Output ephemeral-key relation as
a standalone constrained gadget; it does not assemble the Output circuit.
Phase 9.20.12 composes the available Output relations into a local
witness-to-public-input R1CS assembly. Phase 9.20.14 verifies its witness
relations against one complete external vector. The assembly's constraints
differ structurally from Bellman's, so no Sapling Output circuit compatibility
claim is made. Phase 9.20.15 cross-checks the available Spend note and Merkle
fixtures, but finds no portable, independently sourced complete Spend
relation-vector; it adds no Spend circuit API or compatibility claim.
Phase 9.20.16 consolidates a source-backed readiness matrix for both
circuits, audits witness generation and hash reproducibility, and prioritizes
the remaining evidence-backed gaps without changing circuit implementations.

## Pinned upstream circuit and protocol

The circuit reference is `zcash/sapling-crypto` 0.9.0, commit
`88a7946b4a3066787776e11f0a502654167e022d` (release commit dated 2026-09-30).
This commit's `src/circuit.rs` implements two separate Bellman
`Circuit<bls12_381::Scalar>` synthesizers and has test-only assertions for
their constraint counts and public input order.

### Spend circuit

The Spend circuit proves that the public spend description is linked to a
valid note, a Sapling spending key, and a Merkle authentication path. Its
private witness includes a value-commitment opening (value and `rcv`),
proof-generation key (`ak`, `nsk`), payment address (`d`, `pk_d`), note
commitment randomness (`rcm`), spend randomizer (`ar`), and the sequence of
authentication-path sibling scalars and position bits. The anchor is
constrained conditionally: the reconstructed root must equal the exposed
anchor for nonzero notes, while the zero-value dummy-note case does not
require equality.

The public input order in the pinned upstream circuit is:

1. `rk.u`
2. `rk.v`
3. value commitment `cv.u`
4. value commitment `cv.v`
5. anchor
6. first packed nullifier input
7. second packed nullifier input

The upstream test's `num_inputs() == 8` includes Bellman's constant `ONE`,
so there are seven application public inputs. The pinned upstream test
asserts **98,777 constraints** and circuit hash
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`
for its fixture.

The nullifier is the 256-bit `nf` BLAKE2s output, represented in the gadget's
little-endian-within-byte bit order. Bellman's `multipack::pack_into_inputs`
iterates those bits in order, splitting at `Scalar::CAPACITY` (254 bits for
BLS12-381), and packs each chunk with successive powers of two. Thus the
first input is bits 0 through 253 and the second is bits 254 and 255. They
are emitted immediately after the anchor: application public-input positions
6 and 7 (R1CS variable indices 6 and 7 when index zero is the constant ONE).
Because each chunk has fewer than 255 bits and `2^254` is below the scalar
modulus, each packed value has a unique canonical field representation. No
bit reversal, digest-byte reversal, truncation, or modulus reduction is part
of this packing.

### Output circuit

The Output circuit proves a value commitment and note commitment for the
recipient note and proves that the public ephemeral key is derived from the
recipient's diversifier base and the private ephemeral secret. Private
witnesses include a value-commitment opening, payment address, note
commitment randomness, and `esk`.

The upstream implementation constrains `g_d` to the curve and rejects
small-order `g_d`, but handles `pk_d` by witnessing its encoded `v` bits and
sign bit without a separate point-on-curve check. This describes the pinned
circuit's actual semantics; an alternate implementation must not silently
change that statement.

The public input order is:

1. value commitment `cv.u`
2. value commitment `cv.v`
3. ephemeral public key `epk.u`
4. ephemeral public key `epk.v`
5. note commitment `cmu`

The upstream test's `num_inputs() == 6` includes `ONE`, so there are five
application public inputs. The pinned upstream test asserts **7,827
constraints**.

#### Output witness, inputs, and exact synthesis requirements

The host `Output` witness fields are declared in `circuit.rs` in this order;
these are struct fields, not flat R1CS variable indices:

| Host field | Witness content | Circuit use |
|---|---|---|---|
| `value_commitment_opening` | Optional `(NoteValue, jubjub::Scalar)` | 64-bit note value and `rcv` input to the value commitment |
| `payment_address` | Optional payment address `(d, pk_d)` | Its diversifier is mapped to `g_d`; its transmission key supplies the note representation |
| `commitment_randomness` | Optional `jubjub::Fr` (`rcm`) | Fixed-base note-commitment randomization |
| `esk` | Optional `jubjub::Fr` | Scalar for `epk = [esk]g_d` |

As with Bellman setup-mode circuits, the fields are optional so synthesis can
be run without assignments. For a proving witness, the value is a `NoteValue`
(unsigned 64-bit), and the randomness/scalar values are elements of the
Jubjub scalar field. The payment address must have a usable diversifier:
upstream calls `g_d().expect("checked at construction")`. The circuit then
constrains `g_d` to the curve and rejects points of small order. It does not
re-derive `pk_d` from an incoming viewing key, nor does it constrain `esk` to a
ZIP-212 PRF derivation. There is no ZIP-212 activation-height branch in this
circuit: `esk` and `rcm` are scalar witnesses. The upstream unit test builds
its expected note with `Rseed::BeforeZip212(commitment_randomness)`.

The Output application's public inputs, in allocation order, are:

| Application position | Value | Encoding / binding |
|---:|---|---|
| 1 | `cv.u` | Jubjub value-commitment coordinate `u` |
| 2 | `cv.v` | Jubjub value-commitment coordinate `v` |
| 3 | `epk.u` | `u` coordinate of `[esk]g_d` |
| 4 | `epk.v` | `v` coordinate of `[esk]g_d` |
| 5 | `cmu` | Note-commitment point's `u` coordinate |

Bellman's `num_inputs() == 6` counts its implicit `ONE` at index 0. These
public inputs are BLS12-381 scalar-field elements; `cmu` is the canonical
field representation of the revealed `cm.u` coordinate. The circuit exposes
both coordinates of `cv` and `epk`, but only `cm.u`.

The pinned `Output::synthesize` order (`circuit.rs`, `Output` implementation)
is:

1. `expose_value_commitment`: booleanize `value` to exactly 64 little-endian
   bits; multiply those bits by `VALUE_COMMITMENT_VALUE_GENERATOR`;
   decompose `rcv` into 252 Jubjub scalar-field bits; multiply by
   `VALUE_COMMITMENT_RANDOMNESS_GENERATOR`; add the points; inputize `cv.u`
   then `cv.v`. Upstream explicitly notes that its 252-bit `rcv` representation
   need not be constrained to a canonical in-field integer.
2. Reuse the same 64 value bits as the first portion of note contents.
3. Witness `g_d` from the address diversifier, constrain curve membership and
   non-small-order, and append `repr(g_d)`: 255 little-endian bits of `v`
   followed by the parity/sign bit of `u`.
4. Decompose `esk` into 252 Jubjub scalar-field bits, compute the
   variable-base product `[esk]g_d`, and inputize `epk.u` then `epk.v`.
5. Witness `pk_d` without a separate curve/subgroup constraint. Append 255
   little-endian bits of its `v` coordinate followed by the parity/sign bit
   of its `u` coordinate.
6. Require the note-content bit vector to contain exactly
   `64 + 256 + 256 = 576` bits. Apply the six-bit
   `Personalization::NoteCommitment` Pedersen hash (prefix bits
   `[true, true, true, true, true, true]`) to
   `value || repr(g_d) || repr(pk_d)`.
7. Decompose `rcm` into 252 Jubjub scalar-field bits, multiply by
   `NOTE_COMMITMENT_RANDOMNESS_GENERATOR`, add this point to the Pedersen
   result, and inputize only the randomized commitment's `u` coordinate as
   `cmu`.

The fixed bases and NoteCommitment personalization come from the pinned
Sapling constants and Pedersen implementation (`constants.rs`,
`pedersen_hash.rs`); the variable-base multiplication and representation
rules are the pinned ECC gadget (`ecc.rs`). Circuit input `g_d` is already
derived from the payment-address diversifier on the host side. `pk_d` is
included in the note hash representation, but the Output circuit intentionally
does not check it as a curve point. The Output statement proves no note
ciphertext, DH shared secret, KDF, or AEAD/encryption relation: those are not
constraints in this circuit. `esk` is only used to bind `epk` to `g_d`.

The pinned unit test `test_output_circuit_with_bls12_381` uses a fixed-seed
XorShift RNG to synthesize 100 valid samples. It asserts 7,827 constraints,
the circuit hash
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`,
and six inputs including `ONE`; it separately checks the five public values
against the expected value commitment, `[esk]g_d`, and note `cmu`. These are
upstream implementation tests, not a serialized independent Output witness
fixture available to ZyCoin.

### Required gadgets and related functionality

The pinned circuits depend on all of the following:

- Bellman R1CS and Boolean, numeric, multipacking, and BLAKE2s gadgets.
- Jubjub Edwards/Montgomery point witnesses, point addition, fixed-base
  multiplication, representation, and small-order checks.
- Sapling Pedersen hash with its exact personalization and generated
  fixed-base lookup tables.
- Bit decomposition and Boolean constraints for values, scalar witnesses,
  position bits, and point encodings.
- Spend-side IVK BLAKE2s and nullifier PRF BLAKE2s, exact personalization,
  note-value and note-commitment logic, Merkle authentication path ordering,
  conditional swaps, and the zero-value anchor rule.
- Output-side recipient diversifier point, ephemeral public key, and note
  commitment logic.

Spend authorization signatures are not a constraint in either circuit; they
are separate transaction authorization operations. The circuit exposes the
randomized validating key `rk`, value commitment, anchor, and nullifier as
public inputs but does not itself implement transaction assembly, proof
generation, or signatures.

### Complete Spend circuit audit

The pinned `Spend` host witness struct has these fields in declaration order.
The positions below are the host-struct slots, not R1CS variable indices:

| Host slot | Field | Contents and first use |
|---|---|---|
| 1 | `value_commitment_opening` | Optional `(value, randomness/rcv)`; consumed at the value commitment stage after deriving `ak`, `nk`, `ivk`, `g_d`, and `pk_d`. |
| 2 | `proof_generation_key` | Optional `(ak, nsk)`; `ak` is first witnessed, while `nsk` is later decomposed to derive `nk`. |
| 3 | `payment_address` | Optional `(d, pk_d)`; `g_d` is witnessed after IVK derivation; the circuit derives its own `pk_d` as `[ivk]g_d`. |
| 4 | `commitment_randomness` | Optional `rcm`; consumed after note-content Pedersen hashing. |
| 5 | `ar` | Optional spend-key randomizer; consumed immediately after `ak` to expose `rk`. |
| 6 | `auth_path` | Ordered vector of optional `(sibling scalar, direction bit)` entries; each direction bit and sibling is consumed in tree-level order. |
| 7 | `anchor` | Optional anchor; consumed after all authentication-path entries. |

These are option-bearing host fields; Bellman allocates their internal
coordinates, bits, carries, lookup witnesses, and intermediate values as
synthesis proceeds. There is no separate fixed flat private-witness vector
with stable indices. A private R1CS allocation index depends on every preceding
gadget allocation and must be obtained from a complete synthesis trace.

The top-level Bellman synthesis order is material to its circuit hash:

1. Witness `ak`, apply the upstream non-small-order test, compute
   `[ar]SPENDING_KEY_GENERATOR`, add it to `ak`, and inputize `rk.u`, `rk.v`.
2. Decompose `nsk`, compute `nk = [nsk]PROOF_GENERATION_KEY_GENERATOR`, and
   form `repr(ak)` and `repr(nk)` for the IVK and nullifier preimages.
3. Constrain BLAKE2s IVK over `repr(ak) || repr(nk)` with
   `CRH_IVK_PERSONALIZATION`; retain its low 251 bits.
4. Witness `g_d`, apply the non-small-order test, and derive `pk_d = [ivk]g_d`.
5. Expose the value commitment: decompose 64-bit `value`, compute its fixed
   base product; decompose `rcv`, compute its fixed base product, add them,
   then inputize `cv.u`, `cv.v`. Reuse the same value bits in note contents.
6. Form the 576-bit note preimage `value || repr(g_d) || repr(pk_d)`, compute
   the NoteCommitment Pedersen hash, decompose `rcm`, multiply the note
   randomness generator and add it to form `cm`.
7. Initialize the Merkle accumulator from `cm.u`. For each authentication
   path entry in order: allocate the Boolean direction, append it to the
   little-endian `position_bits`, allocate the sibling, conditionally reverse
   `(cur, sibling)`, decompose both with non-strict `to_bits_le`, and apply
   that level's MerkleTree-personalized Pedersen hash to get the next `cur`.
8. Allocate the anchor, enforce `(cur - anchor) * value = 0`, then inputize
   the anchor. A zero value therefore does not require the root to match.
9. Compute `[position]NULLIFIER_POSITION_GENERATOR` from the accumulated
   direction bits; add it to `cm` to form `rho`.
10. Append `repr(rho)` to the previously prepared `repr(nk)`, constrain the
    `Zcash_nf` BLAKE2s nullifier digest, then multipack its 256 Boolean bits
    into the final two public inputs.

The application public-input order is fixed at steps 1, 5, 8, and 10:
`rk.u`, `rk.v`, `cv.u`, `cv.v`, anchor, nullifier chunk 0, nullifier chunk 1.
Bellman numbers these application inputs after its implicit `ONE`. The
top-level namespaces above define the required subcircuit order; their inner
constraint sequences are determined by the pinned Bellman Boolean, ECC,
Pedersen, BLAKE2s, numeric, and multipack gadgets. The 98,777 total and
upstream circuit hash are the pinned test assertions. ZyCoin does not produce
a corresponding full trace, count, or hash.

The circuit itself does **not** witness the original spending scalar `ask` or
constrain `ak = [ask]SPENDING_KEY_GENERATOR`: it accepts the proof-generation
key's `ak` point witness and proves knowledge of that circuit witness. The
authorization signature is also outside the circuit. A compatible
implementation must follow those pinned semantics rather than adding assumed
relations.

The complete Spend system remains **unsupported / not implemented**. The
requirement-by-requirement audit is:

| Upstream stage / requirement | ZyCoin evidence | Classification |
|---|---|---|
| BLS12-381 scalar field and generic R1CS | Builder uses the matching scalar modulus and evaluates R1CS constraints; its allocation rules, serializer, and namespace/constraint ordering are ZyCoin-specific rather than Bellman's. | Implemented but structurally different |
| Seven public inputs and their order | Nullifier multipacking binds indices 6 and 7; standalone value gadget binds a caller-provided `cv.u/v` pair. No whole-circuit allocator connects `rk`, `cv`, and anchor in upstream order. | Partially implemented |
| Witness `ak`, curve membership, and non-small-order check | Jubjub membership and three-doubling nonzero-`u` checks exist and have local tests. No Spend witness allocation or `rk` composition. | Implemented but structurally different |
| `[ar]SPENDING_KEY_GENERATOR`, addition, public `rk` | Fixed-base multiplication and affine addition exist independently, but are not assembled to bind public `rk`. Fixed-base lookup constraints differ from Bellman's lookup shape and enforce a stricter canonical scalar range than upstream's unconstrained field-bit representation. | Partially implemented |
| `nsk` bits and `[nsk]PROOF_GENERATION_KEY_GENERATOR` | The generator and fixed-base gadget exist; no Spend witness path binds private `nsk` bits to output `nk`. Its canonical scalar bound is stricter than upstream's comment that the bit representation need not be canonical. | Partially implemented |
| `repr(ak)`, `repr(nk)` and IVK personalized BLAKE2s | Point representation, constrained BLAKE2s IVK, and pinned IVK vector exist. BLAKE2s differs by 524 constraints in the recorded Bellman comparison; no Spend integration binds these results. | Implemented but structurally different |
| `g_d` membership and non-small-order; `pk_d=[ivk]g_d` | Point checks and variable-base multiplication exist separately. Address-derived `g_d`, IVK, and `pk_d` are not composed into a Spend witness, and the local scalar-multiplication shape is not Bellman-trace compatible. | Partially implemented |
| `cv` fixed-base products, addition, and public coordinates | Standalone value-commitment gadget is pinned-vector tested and binds both public coordinates. Its one-hot fixed-base lookups and scalar range checks are structurally stricter/different than Bellman. | Implemented but structurally different |
| Note contents, Pedersen hash, `rcm` randomization, and `cm.u` leaf | One independent note vector passes. The standalone note gadget does not receive the Spend-derived `pk_d`/value flow; its `rcm` uses a variable-base gadget, and Pedersen/fixed-base structure is not Bellman-compatible. | Partially implemented |
| Authentication path direction, siblings, conditional reversal, level hashes, position bits | A 32-level path gadget and reference vector exist. It requires strict node range decomposition where upstream explicitly uses non-strict decompositions; it is not integrated with `cm.u` and the nullifier position, so it does not match the complete upstream path constraints. | Implemented but structurally different |
| Conditional anchor relation `(root-anchor)*value=0` | Existing Merkle helper enforces unconditional root equality; zero-value dummy-note semantics are absent. | Missing |
| `[position]NULLIFIER_POSITION_GENERATOR` and `rho=cm+[position]G` | Position generator fixed-base and point addition exist separately, but path bits and note commitment are not connected to the result. | Partially implemented |
| `repr(nk)||repr(rho)` and `Zcash_nf` digest | Hash interface and the pinned nullifier output vector pass. The local BLAKE2s constraints are structurally different from Bellman's and inputs are not connected to Spend-derived points. | Implemented but structurally different |
| Digest multipacking to public nullifier inputs | Little-endian 254+2 packing has pinned-vector, boundary, tampering, and exact public-slot tests. A combined constrained hash-to-public-packing vector now verifies the interface boundary. ZyCoin adds explicit Boolean constraints and does not use Bellman's exact constraint serialization. | Implemented but structurally different |
| Entire Spend synthesis order, witness wiring, Bellman trace/hash | No circuit builder or complete independently sourced Spend witness/trace. | Missing |

No larger circuit integration is safe: several required gadgets have
structurally different (and in places stricter) constraints, public/witness
allocation is not composed in the upstream synthesis order, and the Merkle
anchor rule is missing. Integrating their host outputs would not demonstrate
constraint compatibility and could silently exclude upstream-valid witnesses.
The verified integration boundary is limited to the `Zcash_nf` constrained
hash output feeding the constrained nullifier multipacker. Its pinned
independent vector satisfies the final two public chunks; the local combined
system has 22,306 constraints. This still does not establish a complete Spend
proof relation or Bellman constraint compatibility.

### Complete Output circuit audit

The Output circuit is **not implemented** in ZyCoin. This comparison checks
whether existing components cover its statement; standalone output matches
are not treated as proof of full-circuit compatibility.

| Upstream Output requirement | ZyCoin evidence | Classification |
|---|---|---|
| BLS12-381 scalar-field R1CS substrate | The builder supports scalar-field equations, variables, and constraints, but its allocation rules, serializer, and namespaces are ZyCoin-specific rather than Bellman's. | Implemented but structurally different |
| 64-bit little-endian `value` decomposition reused by `cv` and note contents | Value range checking and the value commitment are constrained independently; the note gadget also consumes a 64-bit value. There is no Output composition reusing a single decomposition across both stages. | Partially implemented |
| `rcv` decomposition, value/randomness fixed-base products, point addition, public `cv.u/v` | `constrain_sapling_value_commitment` implements this relation and passes a pinned value-commitment vector plus boundary/tampering tests. It enforces canonical `rcv` range constraints and uses one-hot lookup constraints, unlike upstream's explicitly non-canonical `rcv` bit-decomposition semantics and Bellman lookup shape. | Implemented but structurally different |
| `g_d` witness, curve and non-small-order constraints | Point membership and three-doubling non-small-order checks exist and are used by the standalone note gadget. They are not placed into a full Output synthesis trace. | Partially implemented |
| 256-bit `repr(g_d)` and Output `pk_d` representation | The Jubjub representation helper and unchecked `pk_d` v-bits/sign-bit allocation path exist. The note fixture exercises this representation, but not the complete Output circuit's representation/allocation ordering. | Partially implemented |
| `esk` Jubjub field-bit decomposition, variable-base `[esk]g_d`, public `epk.u/v` | A generic variable-base scalar-multiplication gadget exists, but no Output test binds an `esk` witness, `g_d` and its result to both public `epk` coordinates in the upstream synthesis order. | Partially implemented |
| 576-bit note-content ordering and six-bit NoteCommitment Pedersen hash | The note gadget constrains value, `g_d` representation, and `pk_d` representation through Pedersen hashing; the pinned `cmu` vector passes. It uses ZyCoin's lookup/constraint layout, and this result is not integrated with the Output value and ephemeral-key stages. | Implemented but structurally different |
| `rcm` field-bit decomposition and fixed-base note-randomness multiplication | The note gadget constrains the `rcm` multiplication and commitment randomization with a variable-base gadget, not the upstream fixed-base circuit gadget. Its lookup/constraint shape is not equivalent. | Implemented but structurally different |
| `cm = note_hash + [rcm]R`, public `cmu = cm.u` | The standalone note gadget binds `cm.u` to a caller-supplied public field element and passes a pinned note commitment vector. It does not share the full Output circuit's witness and public allocation sequence. | Partially implemented |
| Output public inputs `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu` in exact order | One local note test allocates five slots in that order but uses zero placeholders for `cv` and `epk`; it validates only the final `cmu` relation. No integrated Output public-input vector is independently verified. | Partially implemented |
| Complete synthesis order, Bellman trace/hash and 7,827-constraint result | The upstream test asserts the count/hash and field mapping for deterministic generated samples. ZyCoin has no Output synthesizer, complete independent witness fixture, local whole-circuit count, or circuit hash. | Missing |

Available independent ZyCoin tests verify pieces, not an Output witness:

- The pinned `zcash-test-vectors` note-key-components fixture supplies
  `default_d`, `default_pk_d`, `note_v`, `note_r`, and `note_cmu`; the note
  commitment gadget binds the resulting `cm.u` to a public variable and tests
  value/randomness/public-output tampering.
- The pinned note-encryption vector supplies `value`, value-commitment
  randomness, and compressed `cv`; the value commitment gadget checks both
  coordinates, range boundaries, and witness tampering.
- The pinned `sapling-crypto` test checks all five Output public values and
  the 7,827 count/hash for its deterministic generated samples, but ZyCoin has
  no corresponding checked-in full witness and has not independently replayed
  that complete reference sample.
- The BitcoinZ compact-output capture has no corresponding controlled IVK/FVK
  or independently established plaintext, value, and diversifier. It cannot
  serve as a full Output witness vector.

No Output circuit integration is safe: fixed-base constraints and scalar
canonicality differ, the note and value commitment gadgets are not wired into
one witness, and the ephemeral-key multiplication is not bound to the public
inputs in a complete synthesis. The upstream 7,827 count and circuit hash
remain reference assertions only; ZyCoin has no Output constraint count or
hash.

### Phase 9.20.10 — Output note-encryption constraint audit

The pinned Output circuit has no note-ciphertext, key-agreement, KDF, or AEAD
constraints to add. Its only encryption-adjacent relation is the existing
Output statement's ephemeral-key computation:

`epk = [esk]g_d`

The circuit decomposes the private Jubjub scalar `esk`, multiplies the
diversifier base `g_d`, and exposes `epk.u` and `epk.v`. The pinned synthesis
does not compute a DH shared secret, derive an encryption key, serialize a
note plaintext, or accept/bind ciphertext. The 7,827 upstream constraint
count already describes the complete Output circuit as specified; it is not
missing an encryption subcircuit.

The separately pinned `zcash_test_vectors/sapling/note_encryption.py` gives
the ordinary protocol-layer encryption flow and makes the boundary explicit.
Outside the circuit it:

- Samples `esk`, derives the same `epk = [esk]g_d`, and derives the DH shared
  secret as the cofactor multiple of `[esk]pk_d`.
- Derives `k_enc` with BLAKE2b-256 personalized as `Zcash_SaplingKDF`, over
  the encoded shared secret followed by the encoded ephemeral key.
- Serializes the note plaintext as a version byte, 11-byte diversifier,
  unsigned 64-bit little-endian value, 32-byte `rcm`, and 512-byte memo
  (564 bytes total), then uses ChaCha20-Poly1305 with a 32-byte key and
  12-byte all-zero nonce to produce a 580-byte ciphertext (564 plaintext
  bytes plus the 16-byte authentication tag).
- Optionally derives an outgoing ciphertext key from `ovk`, `cv`, `cmu`, and
  `epk`, or uses fresh randomness when no `ovk` is supplied. The 64-byte
  outgoing plaintext encrypts to 80 bytes; this recovery ciphertext is
  likewise outside the Output circuit.

These are ordinary witness construction and transaction-encryption
operations, not R1CS constraints. In particular, adding native code for DH,
BLAKE2b, plaintext encoding, or ChaCha20-Poly1305 would not add circuit
semantics and would not make the Output relation more complete. ZyCoin's
constrained BLAKE2s gadget is not a substitute for this external BLAKE2b KDF,
and this audit adds no encryption code or circuit API.

| Encryption-related relation | Evidence/status |
|---|---|
| `[esk]g_d` and public `epk.u/v` | Required inside the pinned Output circuit; Phase 9.20.11 now constrains this standalone relation against a pinned note-encryption vector. It is not integrated with the complete Output value/note commitment synthesis. |
| DH shared secret `[esk]pk_d` with Sapling cofactor | Not part of `Output::synthesize`; performed by note-encryption code outside the circuit. No R1CS gadget is required for this phase. |
| `Zcash_SaplingKDF` BLAKE2b-256 and exact input byte ordering | Not part of `Output::synthesize`; external encryption operation. The existing constrained BLAKE2s interface is a different hash and personalization. |
| Note plaintext serialization and ChaCha20-Poly1305 ciphertext | Not part of `Output::synthesize`; external encryption operation, not a missing Output constraint. |
| Optional outgoing ciphertext / `ock` | Not part of `Output::synthesize`; external output-recovery encryption operation. |

No new gadget was justified or implemented, so there is no new constraint
count or gadget witness-tampering test to report for Phase 9.20.10. Existing
note-encryption vectors cover the external protocol algorithm, not a full
Output circuit witness. The repository's checked-in value-commitment fixture extracts
`value`, `rcm`, and `cv` from that vector family; the BitcoinZ compact-output
capture contains only public compact data and is marked incomplete for note
decryption. Neither supplies a complete independent witness for the 7,827
constraint Output relation. Full Output synthesis, its Bellman trace/hash,
Groth16 parameters, and proof-generation remain the blockers described above.

### Phase 9.20.11 — constrained Output ephemeral key

The pinned Output synthesis (`circuit.rs`, `Output::synthesize`) witnesses
`g_d` from the already host-validated payment address, interprets it as a
Jubjub point, rejects small-order points, decomposes `esk` into
`jubjub::Fr::NUM_BITS` (252) little-endian Boolean bits, computes the
variable-base multiplication `[esk]g_d`, and inputizes the resulting affine
coordinates in `epk.u`, `epk.v` order. `ecc.rs` implements that multiplication
by doubling the current base for each subsequent bit, conditionally selecting
the current base or identity, and adding selected points to the accumulator.
There is no fixed-base lookup in this relation.

The circuit does **not** take the 11-byte diversifier as a circuit input and
does not constrain its validity or the `Zcash_gd` hash-to-point derivation.
Those are payment-address construction checks before circuit synthesis. The
R1CS relation starts from witness coordinates for `g_d`; it constrains curve
membership and applies the upstream three-doubling/nonzero-`u` small-order
check, but does not prove that these coordinates came from any diversifier.
Likewise, `esk` is a private 252-bit little-endian bit vector. The upstream
gadget boolean-constrains those bits but has no additional canonical
`esk < jubjub::Fr::MODULUS` inequality constraint. ZyCoin's witness helper
accepts only canonical Jubjub field-element integers; its R1CS bit relation
does not add that range inequality.

`constrain_sapling_ephemeral_key` and its separate witness constructor use
ZyCoin's existing variable-base Jubjub multiplication (never the fixed-base
gadget). They add the required curve and non-small-order constraints on the
input `g_d`, booleanize the 252 scalar variables through the multiplication
gadget, and equate the computed output coordinates to caller-allocated public
epk coordinates. The caller must allocate the public inputs before private
witnesses, as required by the builder. The wrapper does not add diversifier
bytes, a host group-hash result, a circuit API, or any DH/KDF/encryption
operations.

Independent verification uses case 0 from the pinned
`zcash-test-vectors` `sapling_note_encryption.json`, whose `default_d`, little-
endian `esk`, and compressed `epk` are recorded in
`tests/fixtures/sapling_ephemeral_key_reference.json`. The host
`Zcash_gd` diversification result multiplied by the fixture scalar matches
the published compressed `epk`. Its R1CS system assigns the public slots in
Output order (test placeholders for `cv.u/v`, then fixture `epk.u/v`, then a
`cmu` placeholder), and the ephemeral gadget satisfies while binding the
middle two public values.

For ZyCoin's local gadget, the measured count is **3,547 constraints**:
4 for `g_d` curve membership, 16 for three doublings plus the nonzero-`u`
test, 3,525 for the 252-bit generic variable-base scalar multiplication, and
2 for public `epk` coordinate binding. The scalar-multiplication portion
consists of 252 Boolean constraints, 504 selection constraints, 1,255
doubling constraints, 1,512 accumulator-addition constraints, and two
identity constraints. The pinned Bellman source-level flow omits that initial
identity and first accumulator addition (its first selected point becomes the
accumulator), giving 1,506 addition constraints and a source-level total of
**3,539** for this isolated relation (including point validation and two
inputizations). This eight-constraint structural difference is retained and
reported; no constraints were removed or padded to make the counts match.
The count is a local component count, not the complete Output circuit count.

Tests additionally cover `esk` values 0, 1, and `r-1`, malformed 251-bit
inputs, an out-of-range witness scalar, invalid/off-curve and small-order
diversifier-base witnesses, an invalid host diversifier rejected by the
existing `group_hash` routine, and tampering with scalar bits/byte order,
`g_d`, an intermediate multiplication point, and either public epk
coordinate. All tampered R1CS assignments are unsatisfied. The fixture
verifies only the ephemeral relation; no full Output witness, count, circuit
hash, or compatibility claim is established.

### Phase 9.20.12 — Output witness and public-input assembly

The pinned authority remains `zcash/sapling-crypto` 0.9.0 at commit
`88a7946b4a3066787776e11f0a502654167e022d`, especially `circuit.rs`'s
`Output` witness declaration and `Circuit::synthesize` implementation. Its
host witness fields, in declaration order, are:

| Host slot | Field | Contents and validation |
|---:|---|---|
| 1 | `value_commitment_opening` | `(value, rcv)`; `value` is unsigned 64-bit and `rcv` is a Jubjub scalar witness. |
| 2 | `payment_address` | `(d, pk_d)`; `d` is 11 bytes and must map to `g_d`; `pk_d` is a Jubjub subgroup point in the host address type. Only its encoding is constrained in this circuit. |
| 3 | `commitment_randomness` | Jubjub scalar `rcm` used to randomize the note commitment. |
| 4 | `esk` | Jubjub scalar used only for `epk = [esk]g_d`. |

These are host-struct slots, not flat R1CS witness indices. Bellman allocates
intermediate variables inside gadgets; the local R1CS builder does not model
Bellman's exact variable or constraint trace.

The five application public inputs and the local assembly order are:

| Position | Public input | Constrained relationship |
|---:|---|---|
| 1 | `cv.u` | `u` coordinate of `[value]G_v + [rcv]G_r`. |
| 2 | `cv.v` | `v` coordinate of the same value commitment. |
| 3 | `epk.u` | `u` coordinate of `[esk]g_d`. |
| 4 | `epk.v` | `v` coordinate of `[esk]g_d`. |
| 5 | `cmu` | `u` coordinate of `Pedersen(NoteCommitment, value || repr(g_d) || repr(pk_d)) + [rcm]G_rnote`. |

Bellman's `num_inputs() == 6` includes its implicit `ONE`; ZyCoin exposes the
five application values above. In the local builder, all five public variables
must be allocated before any private witness, so the public-value order is
preserved but allocation interleaving and circuit hash cannot match Bellman.

The host synthesis sequence in the pinned source is: constrain the 64
little-endian value bits and `rcv` fixed-base multiplication, add the points,
and inputize `cv.u/v`; reuse those value bits in the note preimage; witness and
check `g_d`, append `repr(g_d)`; decompose 252 little-endian `esk` bits, compute
`[esk]g_d`, and inputize `epk.u/v`; append `repr(pk_d)` without a circuit
curve check; Pedersen-hash the 576-bit preimage with the six one-bits for
`Personalization::NoteCommitment`; decompose `rcm`, add its fixed-base
randomization, and inputize only `cm.u`.

`make_sapling_output_witness` validates the diversifier length and mapping,
requires `pk_d` to be on-curve and in the Jubjub subgroup as required for a
host payment-address point, and constructs the existing value-commitment,
ephemeral-key, and note-commitment witnesses. `constrain_sapling_output`
allocates the five public inputs in the order above and connects their
computations. It reuses the value-bit variables between value commitment and
note commitment, uses the single constrained `g_d` for the ephemeral key and
note preimage, and leaves `pk_d` unconstrained as a curve point in R1CS,
matching the pinned Output statement. The function requires a fresh R1CS so
these public values occupy the canonical five slots; it does not accept a
public-input offset. Diversifier hashing, `pk_d` derivation from an IVK,
ZIP-212 derivation of `esk`/`rcm`, and note encryption remain outside this
circuit.

| Output requirement | ZyCoin result | Classification |
|---|---|---|
| Five public values, order, and `ONE` convention | Exposed as `(cv.u, cv.v, epk.u, epk.v, cmu)`; local builder's five public indices are 1–5 after its constant-one slot. | Implemented; allocation order structurally different |
| 64-bit `value`, value-generator multiplication, `rcv` multiplication, point addition, and `cv.u/v` | Composed from the independently fixture-tested value-commitment gadget. The local fixed-base lookup/range constraints are not Bellman-shaped. | Implemented but structurally different |
| Payment-address diversifier to `g_d` | Host constructor computes the pinned `Zcash_gd` group hash and rejects invalid diversifiers; circuit constrains `g_d` on-curve and non-small-order. Diversifier bytes/hash derivation are not R1CS constraints, matching upstream. | Implemented; host-side derivation |
| 252-bit little-endian `esk`, variable-base multiplication, and `epk.u/v` | Composed from the pinned-vector-tested ephemeral-key gadget. Its local multiplication has eight more constraints than the pinned source-level relation. | Implemented but structurally different |
| `pk_d` representation | Witnessed as 255 little-endian `v` bits followed by the parity bit of `u`; no R1CS curve check is added. The host constructor checks the address point is in the subgroup. | Implemented; representation gadget shape differs |
| Shared value bits, 576-bit note preimage, NoteCommitment personalization, and Pedersen hash | Value bits are reused; the six personalization bits and point representations are bound into the note hash. Existing independent note-commitment fixture passes. Pedersen lookup/accumulation structure is not Bellman-equivalent. | Implemented but structurally different |
| 252-bit `rcm`, note-randomness multiplication, addition, and `cmu` binding | Composed from the independently fixture-tested note-commitment gadget and bound to public input 5. | Implemented but structurally different |
| DH, KDF, plaintext serialization, and AEAD | Not in the pinned Output circuit and intentionally not included. | Unsupported by design / not an Output constraint |
| Complete independent Output witness and upstream hash comparison | At the time of this Phase 9.20.12 audit, only component fixtures were recorded; Phase 9.20.14 adds an independent complete relation-vector. The vector is not an upstream circuit assignment transcript or circuit-hash result. | See Phase 9.20.14 |

Before Phase 9.20.13, the assembled system satisfied 16,715 local constraints:
3,057 value-commitment, 3,547 ephemeral-key, 10,110 note-commitment and
`pk_d`-representation, plus one duplicate shared-value equality. This was not
evidence of upstream circuit compatibility.

The Phase 9.20.12 composition test used separate nullifier and component
fixtures. Phase 9.20.14 adds a complete independently sourced relation-vector;
that establishes witness/public-value correspondence for its one case but
does not validate the full upstream circuit's constraint system.

### Phase 9.20.13 — Output constraint-count and structural audit

The upstream comparison is pinned to `zcash/sapling-crypto`
`88a7946b4a3066787776e11f0a502654167e022d` and Bellman 0.15.0. The Sapling
Output test's 7,827 is a `TestConstraintSystem` synthesis count for the
deterministically generated test witnesses (including Bellman's constant-one
input convention), not an independently measured ZyCoin target. The test also
asserts its circuit hash; ZyCoin does not claim that hash. Relevant upstream
operations are in
[Output synthesis](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs),
[Jubjub fixed/variable-base operations](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs),
[Pedersen synthesis and its constraint-count test](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/pedersen_hash.rs),
and Bellman's
[3-bit lookup implementation](https://github.com/zkcrypto/bellman/blob/0.15.0/src/gadgets/lookup.rs).

The source comparison found correctness-preserving opportunities, not a basis
for claiming circuit equivalence. The local 3-bit fixed-base lookup now uses
the Bellman `lookup3_xy` relation: one Boolean AND precomputation and two
coordinate constraints, three constraints per full window. It retains the
upstream little-endian bit order, constant-zero final-window padding, protocol
tables, and ordered additions. The local signed Pedersen lookup now uses four
constraints rather than 14 one-hot constraints. Its remaining difference from
upstream's two-constraint lookup is explained by representation: Bellman
returns the Montgomery x-coordinate as a linear expression and conditionally
negates an allocated y-coordinate; ZyCoin allocates both Edwards coordinates
and constrains the sign and lookup explicitly. Local Pedersen group operations
also remain six-constraint affine Edwards additions, while upstream uses
three-constraint Montgomery additions inside segments and converts each
segment to Edwards form before combining segments.

Other verified corrections:

- The note-randomness generator uses the upstream fixed-base multiplication,
  not the previous generic variable-base gadget.
- Variable-base multiplication starts with the first selected point instead
  of allocating the identity and adding the first point. This removes exactly
  eight constraints per 252-bit multiplication while preserving zero-bit,
  one-bit, and tampering behavior.
- `pk_d` is allocated directly as 255 little-endian `v` bits plus the `u`
  parity bit. The local Output path no longer reconstructs a numeric `v` or
  adds a curve check that the pinned Output circuit does not make.
- Note-message Boolean constraints are not repeated when the value, `g_d`
  representation, and `pk_d` representation bits are already constrained by
  their respective gadgets. The duplicate outer equality for the shared
  value bits was removed; the note gadget still binds those bits to its value
  variable.
- Output `rcv` bit constraints remain Boolean, but ZyCoin's stricter
  standalone canonical-scalar range check is disabled for Output synthesis:
  upstream exposes the value commitment without requiring that extra
  canonicality relation. The standalone value-commitment API keeps its
  existing strict default. The `rcm` canonical range checks remain enabled.

Measured results for the same composed Output fixture:

| Local synthesis component | Before Phase 9.20.13 | After Phase 9.20.13 |
|---|---:|---:|
| Value commitment | 3,057 | 1,265 |
| Ephemeral key | 3,547 | 3,539 |
| Note commitment and its reused representations | 10,110 | 5,366 |
| Duplicate shared-value equality | 1 | 0 |
| **Composed local Output** | **16,715** | **10,170** |

The 10,170 total is 2,343 above the upstream 7,827. The local system is
satisfied and all five public inputs retain their tested positions; this
remaining gap reflects the local Pedersen coordinate/allocation and affine
addition structure, scalar range/decomposition details, and variable-base
gadget shape. The count was measured from actual constraints, not forced.
The test rechecks public-input tampering and major witness-bit/point
intermediates; these assignments remain unsatisfied. Phase 9.20.14 validates
an independent complete Output relation-vector, but no upstream circuit
assignment trace or comparable hash is available. The local Output circuit
remains **unsupported as Bellman-compatible**.

Earlier phases already established the principal component gaps:

- Phase 9.20.4 adds constrained BLAKE2s and the exact IVK/nullifier hash
  interfaces. These are standalone gadgets, not a synthesized Spend circuit
  or a whole-circuit equivalence result.
- Phase 9.20.5 adds the standalone fixed-base gadget for all six pinned
  generators and the 32-, 64-, and 252-bit input widths used by the upstream
  circuit. Phase 9.20.13 changes its lookup equations to the pinned
  Bellman-shaped 3-bit relation. This does not make the complete Spend or
  Output systems structurally equivalent.
- Phase 9.20.6 adds a standalone constrained value-commitment gadget tying a
  64-bit `value` and canonical Jubjub scalar `rcv` to public `cv.u` and `cv.v`.
  It is not integrated into a complete Spend system.
- Phase 9.20.7 adds standalone constrained multipacking of the 256 nullifier
  bits to the exact two public inputs. Phase 9.20.8 composes only the existing
  `Zcash_nf` hash output with this packer against the published nullifier
  vector; position, anchor, value commitment, and key gadgets remain outside
  a Spend circuit.
- The existing Merkle path gadget does not implement Spend's conditional
  anchor rule, its exact upstream allocation and decomposition ordering, or
  bind the note/position result to the nullifier construction.
- The local fixtures provide individual note/nullifier and Merkle reference
  data, but no independently sourced complete Spend witness with all public
  inputs, circuit outputs, and a pinned synthesized constraint trace.

Consequently, no full Spend R1CS, constraint count, circuit hash, or end-to-end
Spend vector result is reported for ZyCoin. The upstream **98,777** constraint
count remains a comparison target only. The existing gadget counts and fixture
results are not an approximation or substitute for it. No constraints were
added or removed to force a count match, and no Sapling spending functionality
was enabled.

### Phase 9.20.14 — independent Output relation-vector

The previous missing-fixture status was resolved for witness/value relations
using vector 0 from `zcash/zcash-test-vectors` JSON
`test-vectors/json/sapling_note_encryption.json`, pinned to commit
`78321beacb0e0477e33cd002b56585a107c2708c`. Its generator is the Python
`zcash_test_vectors/sapling/note_encryption.py` at the same commit. The
independent generator constructs `g_d` from the 11-byte diversifier, computes
`epk = [esk]g_d`, uses the supplied `rcm` in the note commitment, constructs
`cv` from the value and that same `rcm`, and exports compressed `cv`/`epk` plus
`cmu`. The local regression fixture
[`tests/fixtures/sapling_output_reference.json`](../tests/fixtures/sapling_output_reference.json)
records those values and the provenance. It does not derive reference outputs
using ZyCoin.

The vector contains all host witness values needed for a coherent Output
sample: `value`, `rcv`, payment address `(d, pk_d)`, `rcm`, and `esk`. In this
particular independent vector, its generator uses `np.rcm` as both the value
commitment blinding and note commitment randomness; the fixture therefore
records `rcv == rcm`, rather than inventing a second randomness value. Its
expected public values are obtained from the independently serialized
compressed `cv` and `epk` points, and the canonical little-endian `cmu` field
encoding.

| Output relation / evidence | Status | Result / boundary |
|---|---|---|
| Public input order `cv.u, cv.v, epk.u, epk.v, cmu` | **Verified** | The five local public values match the independent vector after canonical decoding of its compressed `cv`/`epk`; local public variable indices are 1–5 after the constant-one slot. |
| `d` length and diversified base `g_d` | **Verified** | The 11-byte vector diversifier maps to the local `group_hash("Zcash_gd", d)`; dividing the independent `epk` by the independent nonzero `esk` yields the same base point. |
| `epk = [esk]g_d` | **Verified** | Independent compressed `epk` matches the local witness point and constrained public coordinates. `esk` is interpreted as a canonical little-endian Jubjub scalar. |
| Value commitment `cv = [value]G_v + [rcv]G_r` | **Verified** | The decoded independent compressed `cv` equals the local constrained commitment for the vector's 64-bit value and canonical `rcv`. |
| Note commitment and public `cmu` | **Verified** | Independent `cmu` equals the local constrained note commitment's `u` coordinate using the vector `value`, `d`, `pk_d`, and `rcm`. The vector does not provide the commitment's hidden `v` coordinate. |
| Canonical encodings | **Verified** | Fixture tests round-trip compressed points; check 11-byte `d`, 32-byte little-endian scalar encodings, scalar bounds, and canonical base-field `cmu`; `pk_d`, `cv`, and `epk` decode as subgroup points. |
| Witness byte serialization / Bellman variable assignment | **Unverified** | The test-vector JSON serializes semantic input/output values; it does not contain a flat private-witness assignment, Bellman variable order, or serialized `TestConstraintSystem`. |
| Merkle path or anchor inputs | **Unsupported / not applicable** | The pinned Output circuit has no Merkle path or anchor public/private input; those belong to Spend. |
| Full circuit constraints and circuit hash | **Unverified** | The pinned upstream test's generated witness is not this vector, and ZyCoin's synthesis shape/order differs. Matching values do not establish circuit compatibility; no hash comparison is made. |

Regression coverage now loads the independent vector directly, validates
canonical point/scalar/field encodings, checks diversified-base and all three
commitment/key relationships, asserts the exact five public inputs and
positions, and confirms local satisfaction. It also tampers with each public
input, value and scalar bits, the diversifier base, `pk_d` representation, and
an ephemeral multiplication intermediate; every altered assignment fails.
The reference set supplies one complete Output relation-vector, not the
upstream circuit's private assignment transcript or full circuit result.
Accordingly, end-to-end witness relations for this one sample are verified;
Bellman-compatible synthesis and Groth16 readiness remain unsupported.

The upstream Output test at Sapling commit
`88a7946b4a3066787776e11f0a502654167e022d` still establishes the separate
7,827-constraint count and hash
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee` for
its own deterministic test witnesses. ZyCoin does not reproduce that test
generator or its exact Bellman constraint ordering and hash serialization.
Therefore the local measured count (10,170) and upstream count/hash are
reported separately, without treating either as a compatibility proxy.
ZyCoin's
[`R1CS.serialize`](../src/r1cs.py) emits its own `zycoin-r1cs-v1` JSON shape,
including local variable names and constraint labels while omitting private
witness assignments. That is not Bellman's TestConstraintSystem encoding or
hash input. Hashing the local bytes would produce no meaningful upstream
comparison, so no local circuit digest is reported.

### Phase 9.20.15 — independent Spend relation verification

The pinned references were inspected for a complete Spend relation-vector:

- `zcash/sapling-crypto` 0.9.0, commit
  `88a7946b4a3066787776e11f0a502654167e022d`, defines the Spend witness,
  synthesis, and public-input order in `src/circuit.rs`. Its tests include a
  deterministic-seeded Spend synthesis that generates keys, address,
  commitment randomness, `ar`, authentication path, and anchor at runtime,
  then checks the Bellman constraint system. They do not publish those values
  as a portable complete witness fixture.
- `zcash/zcash-test-vectors`, commit
  `78321beacb0e0477e33cd002b56585a107c2708c`, provides separate Sapling
  key-component, note-encryption, ZIP-32, and Merkle data. The key-component
  vector includes note/key/nullifier fields; the Merkle fixture supplies an
  independently generated path and anchor for its leaf. Those records do not
  contain the full Spend witness and all seven public inputs in one coherent
  case. The pinned JSON set contains Sapling generator, key-component,
  note-encryption, signature, ZIP-32, and ZIP-32-hard vectors, but no
  `sapling_spend.json` relation-vector.
- No complete Spend witness assignment, expected `rk`, corresponding Spend
  value commitment, anchor/path plus note/key tuple, or serialized Bellman
  private-variable assignment was found. Values from different vector cases
  are not combined to manufacture one.

For the pinned circuit, the complete application public-input order and
host-witness shape are:

| Order | Public input / host witness field | Width, encoding, and relation |
|---:|---|---|
| Public 1–2 | `rk.u`, `rk.v` | Two BLS12-381 scalar-field coordinates of `ak + [ar]SPENDING_KEY_GENERATOR`; Bellman's implicit `ONE` is input index 0. |
| Public 3–4 | `cv.u`, `cv.v` | Two scalar-field coordinates of `[value]VALUE_COMMITMENT_VALUE_GENERATOR + [rcv]VALUE_COMMITMENT_RANDOMNESS_GENERATOR`. |
| Public 5 | `anchor` | One BLS12-381 scalar-field tree root. The circuit enforces `(root - anchor) * value = 0`, then exposes the anchor. |
| Public 6–7 | Nullifier chunks 0 and 1 | Little-endian digest bits 0–253 and 254–255, respectively; 254-bit and 2-bit chunks packed as field elements. |
| Host 1 | `value_commitment_opening` | Unsigned 64-bit value represented by little-endian bits and Jubjub scalar `rcv`; `rcv` is decomposed into its 252 little-endian field bits without a separate canonical-bit-string check. |
| Host 2 | `proof_generation_key` | Jubjub point `ak` and Jubjub scalar `nsk` (252 little-endian bits; no `ask` witness). `nk = [nsk]PROOF_GENERATION_KEY_GENERATOR`. |
| Host 3 | `payment_address` | 11-byte diversifier `d`; circuit witnesses `g_d` from `d` and derives `pk_d = [ivk]g_d`. The Spend circuit does not witness the supplied address `pk_d` as an independent input. |
| Host 4 | `commitment_randomness` | Jubjub scalar `rcm`, decomposed into 252 little-endian bits to randomize `cm`. |
| Host 5 | `ar` | Jubjub scalar, decomposed into 252 little-endian bits for `rk`. |
| Host 6 | `auth_path` | Ordered tree-level entries `(sibling BLS12-381 scalar, direction Boolean)`; Sapling uses 32 levels and 32 position bits. Each pair selects the Pedersen preimage order. |
| Host 7 | `anchor` | Optional witness value for the public anchor; in the zero-value case it need not equal the computed root. |

All seven application public inputs are BLS12-381 scalar-field elements and
use canonical 32-byte little-endian field encodings when serialized; the two
nullifier chunks are each below the field modulus. Bellman's implicit `ONE`
is not an application input.

The circuit forms `repr(ak) || repr(nk)` for the IVK hash, derives `pk_d`,
commits to `value || repr(g_d) || repr(pk_d)` with `rcm`, authenticates
`cm.u` using the ordered path, forms
`rho = cm + [position]NULLIFIER_POSITION_GENERATOR`, hashes
`repr(nk) || repr(rho)` with `Zcash_nf`, and multipacks the digest. The
point representations in these preimages are 255 little-endian bits of the
`v` coordinate followed by the parity bit of `u`. Each Merkle level
decomposes its current-root and sibling field elements into 255 little-endian
bits for the Pedersen preimage. The original spending scalar `ask`,
authorization signature, and transaction authorization are not Spend-circuit
witnesses.

The available data supports independently checking some relations, but not
validating a complete Spend witness assembly:

| Spend relation | Status | Independent evidence and boundary |
|---|---|---|
| Public input order `rk.u, rk.v, cv.u, cv.v, anchor, nf[0], nf[1]` | **Partially Verified** | The pinned circuit source establishes this order. Local tests bind the anchor at position 5 and the multipacked nullifier at positions 6–7, but there is no complete Spend case supplying and checking all seven values together. |
| `ak`, `ar`, and `rk = ak + [ar]SPENDING_KEY_GENERATOR` | **Unavailable** | The public Sapling key-component vectors provide spending-key material but do not publish a coherent Spend case with `ak`, `ar`, and expected `rk`; no local Spend assembly binds them. |
| 64-bit value and `rcv` to public `cv.u/v` | **Partially Verified** | A pinned note-encryption vector independently verifies the standalone value-commitment relation. It is not the same complete Spend case as the key-component and Merkle data, and its `cv` cannot stand in for a missing Spend `cv`. |
| `nsk` to `nk`, and `ak/nk` to `ivk` | **Partially Verified** | Pinned key-component and ZIP-32 fixtures exercise related outputs separately. They do not supply one complete Spend witness or bind those values through the Spend circuit's synthesis sequence. |
| Diversifier, `g_d`, `ivk`, and `pk_d` | **Partially Verified** | Published note vectors provide diversifier and transmission-key data, and existing tests verify selected derivations. There is no complete Spend vector tying these to the same `ak`, `nsk`, `ar`, and public inputs. |
| Note contents, `rcm`, and `cmu` | **Verified** | The pinned key-component note vector supplies note data and expected `cmu`; existing tests verify the note commitment and nullifier relation for that vector. This is semantic component verification, not full-circuit verification. |
| Authentication path and anchor | **Partially Verified** | The pinned Merkle fixture supplies a 32-level path and root. Its first leaf and position match the first key-component note's `cmu` and `note_pos`; a regression test checks that cross-fixture identity. The available matching case has value zero, so it does not verify Spend's conditional nonzero-value anchor rule. |
| `rho = cm + [position]NULLIFIER_POSITION_GENERATOR`, `Zcash_nf`, and public nullifier | **Partially Verified** | The key-component `nk`, note, position, and expected nullifier are checked by the constrained `Zcash_nf`-to-multipacking integration. This does not connect the result to all other Spend witnesses or public inputs. |
| Canonical encodings and full witness/public-input mapping | **Unverified** | Individual fixture encodings are validated by their component tests. No complete assignment exists against which to validate all encodings, field widths, and public-input values in synthesis order. |
| Complete Spend relation-vector and full-circuit satisfaction | **Unavailable** | The pinned upstream test generates a complete witness internally, but does not publish a portable relation-vector; ZyCoin does not run or translate that test into a reference. No ZyCoin complete Spend circuit is assembled. |

Regression coverage cross-checks the shared note commitment and tree position
between the independent key-component and Merkle fixtures, checks Merkle
witness construction at positions zero and `2^32 - 1`, and retains rejection
of out-of-range positions. The checked-in
[`sapling_spend_partial_reference.json`](../tests/fixtures/sapling_spend_partial_reference.json)
records those source revisions and join fields, marks itself incomplete, and
lists missing Spend values rather than supplying synthetic ones. Existing
component tests verify the supplied Merkle anchor/path, note/nullifier,
nullifier packing and public-slot tampering, and value-commitment relation.
Their independent-vector scope is limited to each relation as described
above; no fake `rk`, `cv`, anchor, or other missing witness value is added to
make a combined Spend sample.

Accordingly, Phase 9.20.15 establishes **partial independent semantic
verification only**. It does not validate ZyCoin's complete Spend witness
assembly, conditional anchor semantics, public-input vector as a whole,
Bellman constraint structure, or circuit hash. The upstream 98,777-constraint
count remains reference information only. Sapling spending remains disabled.

### Phase 9.20.16 — circuit readiness and gap audit

This audit compares ZyCoin's current code and fixture results against
`zcash/sapling-crypto` 0.9.0, commit
`88a7946b4a3066787776e11f0a502654167e022d`, and the separately pinned
`zcash-test-vectors` commit
`78321beacb0e0477e33cd002b56585a107c2708c`. Statuses below describe evidence
for the stated relation; a host output matching a vector does not verify its
R1CS shape or the complete circuit.

#### Spend readiness matrix (Phase 9.20.16 snapshot)

This matrix records the state at Phase 9.20.16. It is retained as historical
context; its statuses are superseded by the Phase 9.20.27 assembly
reassessment below. In particular, conditional-anchor, Merkle-position, rho,
and randomized-key work was added in later phases.

The public inputs are seven BLS12-381 scalar elements in order:
`rk.u`, `rk.v`, `cv.u`, `cv.v`, anchor, nullifier chunk 0, nullifier chunk 1.
Bellman's implicit `ONE` is index 0 and is not an application input. The
private host witness slots are `(value: u64, rcv: Jubjub scalar)`,
`(ak: Jubjub point, nsk: Jubjub scalar)`, payment address `(d: 11 bytes,
pk_d)`, `rcm`, `ar`, an ordered authentication path of 32
`(BLS12-381 scalar sibling, Boolean direction)` entries, and the anchor. The
circuit derives `nk`, `ivk`, `g_d`, and `pk_d`; `ask` and signatures are not
circuit witnesses. Jubjub scalar decompositions use 252 little-endian bits;
point representations use 255 little-endian `v` bits followed by the parity
bit of `u`. Public scalar values serialize canonically as 32-byte
little-endian field elements. The exact upstream synthesis order and
zero-value conditional-anchor semantics are detailed above.

| Spend requirement | Status at Phase 9.20.16 | Evidence and then-known gap |
|---|---|---|
| BLS12-381 scalar R1CS substrate | **Implemented but independently unverified** | Generic equations, allocation, and satisfaction are unit tested. The builder is ZyCoin-specific; no full Spend synthesis exists. |
| Seven public inputs, order, and canonical encodings | **Partially implemented** | The anchor slot and two packed nullifier slots are tested, and standalone value commitment binds its two supplied public variables. `rk`, `cv`, and anchor are not assembled together in upstream order or validated as one vector. |
| `ak` witness, curve membership, and non-small-order semantics | **Partially implemented** | Jubjub membership and small-order checks exist; they are not composed with the Spend witness or public `rk`. |
| `ar` decomposition, `[ar]SPENDING_KEY_GENERATOR`, addition, and `rk` binding | **Partially implemented** | Fixed-base multiplication and addition exist separately. No Spend assembly binds them; scalar range behavior and synthesis structure differ from upstream. |
| `nsk` decomposition, `[nsk]PROOF_GENERATION_KEY_GENERATOR`, `nk` | **Partially implemented** | The generator and fixed-base primitive exist; no Spend witness path binds private `nsk` to the derived point. Local canonical-range checks are stricter than upstream's field-bit witness semantics. |
| `repr(ak)`, `repr(nk)`, and IVK personalized BLAKE2s | **Verified by an independent reference** | The standalone IVK interface matches a pinned ZIP-32 vector. Its Spend-stage allocation and composition with derived `ak`/`nk` are not implemented. |
| Diversifier, `g_d` validation, `ivk`, and `pk_d=[ivk]g_d` | **Partially implemented** | Group hash, point checks, and variable-base multiplication exist separately. There is no constrained Spend chain joining them to the key witness and note preimage. |
| 64-bit value and `rcv` to public `cv.u/v` | **Verified by an independent reference** | A pinned note-encryption vector verifies the standalone value-commitment relation and public coordinates. It does not supply the missing `cv` for the joined Spend note/path case. |
| Note contents, `rcm`, and `cm.u` | **Verified by an independent reference** | The pinned key-components note vector verifies note commitment and nullifier outputs. The note gadget is not wired to Spend-derived value, `g_d`, and `pk_d`. |
| Authentication path directions, siblings, Merkle Pedersen levels, and position bits | **Partially implemented** | A pinned path/root fixture and tampering are tested, and its leaf/position cross-match the first key-components vector. Local strict decompositions differ from upstream's non-strict `to_bits_le`; the path is not connected to the Spend note commitment or nullifier position. |
| Conditional anchor `(root-anchor)*value=0` | **Missing** | The local helper enforces unconditional root equality. The joined independent note is zero-value, so it cannot verify the nonzero-value condition. |
| `[position]NULLIFIER_POSITION_GENERATOR`, `rho=cm+[position]G`, and nullifier PRF | **Partially implemented** | The published note nullifier is checked through constrained `Zcash_nf`; fixed-base and addition gadgets exist. Path-derived position, note commitment, and `rho` are not connected in R1CS. |
| 254+2-bit digest multipacking into public inputs 6–7 | **Verified by an independent reference** | Published nullifier digest, little-endian packed values, boundaries, bit-order reversal, public-slot placement, and tampering are covered. ZyCoin adds explicit Boolean constraints and does not reproduce Bellman's shape. |
| Complete Spend witness/public-input synthesis and satisfaction | **Missing** | No Spend circuit API or single complete relation-vector exists. No ZyCoin full-circuit constraint count or hash. |
| Spend signing, proof generation, and authorization | **Not applicable to the circuit** | The pinned Spend relation does not include signatures or Groth16 proving. Those are outside this readiness audit and remain disabled. |

#### Output readiness matrix

The five application public inputs are `cv.u`, `cv.v`, `epk.u`, `epk.v`,
`cmu`, after Bellman's implicit `ONE`. Its host witness slots are
`(value: u64, rcv)`, payment address `(d: 11 bytes, pk_d)`, `rcm`, and `esk`.
The circuit reuses the 64 little-endian value bits, derives/constrains `g_d`
from the host address, constrains `epk=[esk]g_d`, commits to
`value || repr(g_d) || repr(pk_d)` with NoteCommitment Pedersen hashing,
randomizes with `rcm`, and exposes `cm.u`. The upstream circuit does not
rederive `pk_d` from an IVK and does not add a separate `pk_d` curve check.
Scalar witnesses are represented by 252 little-endian bits; the pinned
circuit's field decomposition is not interchangeable with an extra canonical
range restriction.

| Output requirement | Status | Current evidence and remaining gap |
|---|---|---|
| Five public inputs, order, and canonical values | **Verified by an independent reference** | The complete pinned note-encryption relation-vector matches all five local public values and their positions. This is semantic verification, not Bellman constraint equivalence. |
| Value and `rcv` fixed-base products, addition, and public `cv.u/v` | **Verified by an independent reference** | The external compressed value commitment decodes to the constrained result. Local fixed-base/range construction is not identical to Bellman's full allocation/constraint trace. |
| 11-byte diversifier and host derivation of `g_d` | **Verified by an independent reference** | The fixture's diversifier maps to the recorded diversified base. Hash-to-point occurs host-side, as in the pinned circuit's witness creation. |
| `g_d` curve and non-small-order constraints | **Implemented but independently unverified** | The local assembly applies point and small-order checks; the complete external relation vector verifies its resulting point, but supplies no independent constraint-system transcript. |
| 252-bit `esk`, `[esk]g_d`, public `epk.u/v` | **Verified by an independent reference** | Independent `epk` matches the host relation and the local constrained public coordinates, including scalar-boundary and tampering tests. Local variable-base construction is structurally different. |
| `repr(g_d)` and `repr(pk_d)` ordering; `pk_d` point policy | **Partially implemented** | The note preimage vector is verified and the local Output assembly preserves `v`-bits then `u`-parity encoding. The upstream circuit only witnesses `pk_d` representation bits; the local host constructor applies its own subgroup validation and local synthesis allocation differs. |
| Shared 64-bit value, 576-bit note preimage, NoteCommitment Pedersen, `rcm`, and `cmu` | **Verified by an independent reference** | The fixture verifies the note commitment's public `cmu` from the exact semantic inputs. Local Pedersen and fixed-base equations/order are not Bellman-equivalent. |
| Randomness relationship `rcv` versus `rcm` | **Verified by an independent reference** | For the one pinned note-encryption vector only, the published generator uses the same `np.rcm` for both, so `rcv == rcm`. This is sample provenance, not a protocol-wide equality requirement. |
| Full Output constraint system, ordering, and Bellman hash | **Partially implemented** | ZyCoin's local assembly satisfies the complete semantic vector at 10,170 constraints. Upstream asserts 7,827 and a different hash; local allocation and gadget structure differ, so circuit equivalence is not established. |
| Merkle path, anchor, nullifier, spend key, and randomized spend key | **Not applicable to the circuit** | These are Spend relations; Output has no Merkle/anchor/nullifier or `rk` public inputs. |
| DH, KDF, plaintext serialization, and AEAD | **Not applicable to the circuit** | They are performed outside the pinned Output circuit. |
| Groth16 proof generation and Sapling spending | **Not applicable to the circuit** | They are not circuit witness relations and remain disabled in ZyCoin. |

#### Constraint structure, counts, and serialization

Counts are measurements/assertions for the named systems only; they are not
compatibility evidence and component counts must not be added as if they were
a complete Spend circuit.

| System | Pinned upstream | ZyCoin current | Interpretation |
|---|---:|---:|---|
| Spend circuit | 98,777 constraints; hash `d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89` | No complete Spend system/count/hash | Upstream source test assertion only. |
| Output circuit | 7,827 constraints; hash `c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee` | 10,170 constraints | Local complete semantic assembly passes one independent vector; local count and constraint stream differ. |
| BLAKE2s with 512 variable message bits | 21,518 constraints in Bellman's gadget test | 22,042 constraints | 524-constraint difference: ZyCoin uses output-bit Boolean constraints/direct carry reconstruction; Bellman uses `UInt32`/`MultiEq`. |
| Spend nullifier hash plus multipacking | Not a complete standalone Spend count | 22,306 constraints | ZyCoin hash-to-two-public-chunks integration only. |
| Merkle path-only gadget | No comparable complete isolated count used here | 87,650 constraints | Local path gadget only; strict decomposition and unconditional anchor semantics make it non-equivalent. |

Additional concrete structural differences:

- The R1CS builder emits ZyCoin's `zycoin-r1cs-v1` JSON with local names and
  labels and omits witness values. Bellman 0.15.0's `TestConstraintSystem`
  hash instead feeds counts and ordered A/B/C linear combinations into
  BLAKE2s, using input/aux indices and canonical coefficient encodings. The
  hash is constraint-shape data, not a serialized witness or standardized
  circuit file.
- For Output, ZyCoin allocates all public variables before private variables;
  Bellman inputizes values at their upstream synthesis stages. Pedersen
  signed lookups use four local constraints versus Bellman's two-coordinate
  lookup; local point additions use six affine Edwards constraints where
  Bellman uses Montgomery segment operations/conversions. Local scalar
  decomposition/range constraints and variable-base multiplication also do
  not establish the identical trace.
- For Spend, the local authentication path uses strict node range checks
  rather than upstream's non-strict bit decomposition and has unconditional
  anchor equality. `ak/ar/rk`, `nsk/nk/ivk`, address-derived `pk_d`, value,
  note commitment, path-derived position, `rho`, nullifier, and all public
  inputs are not composed in the complete upstream order.
- The fixed-base lookup was aligned with the upstream three-constraint
  `lookup3_xy` window relation, but this isolated improvement does not erase
  differences in scalar decomposition, allocation, other gadgets, or
  inter-gadget ordering.

The upstream Spend test (`test_input_circuit_with_bls12_381`) seeds
`XorShiftRng` with
`58 62 be 3d 76 3d 31 8d 17 db 37 32 54 06 bc e5`, then runs ten cases. Each
case samples the 64-bit value, `rcv`, a fake-random validating key and `nsk`,
retries random 11-byte diversifiers until payment-address construction
succeeds, samples `rcm`, 32 random path sibling/direction pairs, and `ar`.
It computes expected `rk`, value commitment, note commitment, tree root and
position, nullifier and packed chunks, then checks satisfaction, public inputs,
98,777 constraints, and the fixed hash. The Output test uses the same seed
with 100 cases, sampling value, value randomness, key material, valid address,
`rcm`, and `esk`; it checks all five public inputs, satisfaction, 7,827
constraints, and the fixed hash. Both generators and checks are visible in
the pinned `src/circuit.rs`; their generated full witness records are not
checked in as test-vector files.

A complete Spend semantic reference is **reproducible in principle in pure
Python**, but not directly present in the pinned vector corpus: port the exact
seeded test procedure plus the pinned `rand_xorshift`/`rand_core` sampling,
Sapling fake-random key/address construction, note/Merkle/nullifier functions,
and compare every resulting relation against the pinned source assertions and
available independent component fixtures. This is a separate, nontrivial
reference-generation task; no such port or complete fixture exists today.
The partial manifest remains intentionally incomplete. The authoritative
upstream count/hash values can be read from the pinned tests. A pure-Python
recomputation of Bellman's `TestConstraintSystem::hash` is also possible from
the published hash algorithm, but requires the exact ordered constraint
stream. ZyCoin's existing local streams are structurally different, so
hashing them cannot verify equivalence or reproduce the upstream hashes.
Neither circuit currently has an independently obtained complete matching
serialization/hash from ZyCoin.

#### Phase 9.20.17: deterministic Spend witness reproduction status

The pinned source fully specifies the deterministic test procedure, but this
phase did **not** produce an independent pure-Python reproduction or a complete
fixture. The Spend test at
[`src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
uses seed `58 62 be 3d 76 3d 31 8d 17 db 37 32 54 06 bc e5` and, for each of
ten cases, samples `value`, `rcv`, a fake-random `ak`, `nsk`, a valid
11-byte diversifier (retrying until address derivation succeeds), `rcm`,
32 `(sibling, direction)` pairs, and `ar`. It then derives the viewing and
payment-address values, `rk`, `cv`, `cmu`, the Merkle anchor and position,
the nullifier, and its two packed public inputs.

The pinned `Cargo.lock` resolves `rand_xorshift` 0.5.0, `rand_core` 0.10.1,
`jubjub` 0.11.1, `bls12_381` 0.9.0, and `ff` 0.14.0. The source defines
little-endian seed words and RNG byte filling; field sampling consumes 64
bytes and reduces the little-endian wide value; subgroup-point sampling
retries invalid curve candidates and clears the cofactor. The test's
`SpendValidatingKey::fake_random` and diversifier loop add their own rejection
steps. These rules and the witness call order are traceable in the pinned
crate sources, but the upstream test does not publish the resulting sampled
values as a fixture.

In particular, its checks assert satisfaction, the fixed 98,777 constraint
count and shape hash, and equality between circuit outputs and values computed
by the same upstream APIs. Those assertions do not provide literal expected
values for the seeded `value`, `rcv`, key material, address, path, anchor,
`rk`, `cv`, `cmu`, nullifier, or seven application public inputs. The pinned
external test-vector corpus also does not contain this seeded assignment. The
existing partial manifest joins independent note/nullifier and Merkle-path
records only by note commitment and position; it explicitly lacks a coherent
value commitment, `ak/ar/rk`, and complete public-input record. That manifest
remains unchanged and incomplete.

Accordingly, **complete deterministic Spend reproduction is unverified**:
there is no independently implemented Python generator whose outputs were
checked against literal upstream witness values, and using ZyCoin's own
implementation to generate such a fixture would not meet the independence
requirement. This is a verification gap, not evidence that the upstream
procedure is intrinsically unreproducible; the pinned source is sufficient to
guide a future independent port. No complete fixture, Spend circuit API, or
compatibility claim is added by this phase.

#### Phase 9.20.18: independent Spend reference acquisition

**Outcome: blocked.** The source and test-infrastructure search did not find a
complete, independently generated Spend assignment with all seven application
public inputs and traceable provenance for the exact pinned circuit revision.
No fixture or test was added.

| Candidate | Source and revision | What is available | Completeness and disposition |
|---|---|---|---|
| Pinned upstream Spend test | [`src/circuit.rs` at `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs), `test_input_circuit_with_bls12_381` | Deterministic test construction, satisfaction assertion, seven application-input checks, constraint count and shape-hash assertions. | **Not a fixture.** It checks calculated values against the same in-process APIs and does not serialize or print the sampled witness or expected values. |
| Pinned upstream CI | [CI run 36778734609](https://github.com/zcash/sapling-crypto/actions/runs/36778734609), commit `88a7946b4a3066787776e11f0a502654167e022d` | The successful test job log says `test circuit::test_input_circuit_with_bls12_381 ... ok`; the workflow runs `cargo test --all-features --verbose --release`. | **No witness export.** The run has zero artifacts; the workflow has no artifact-upload step and the test log contains no witness values. |
| Pinned test-vector corpus | [`zcash/zcash-test-vectors` at `78321beacb0e0477e33cd002b56585a107c2708c`](https://github.com/zcash/zcash-test-vectors/tree/78321beacb0e0477e33cd002b56585a107c2708c), including `sapling_key_components`, `sapling_note_encryption`, and `zcash_test_vectors/sapling/merkle_tree.py` | Independent key-component, note, and nullifier vectors; the Merkle source has a single Pedersen-CRH check, not an authentication-path fixture. | **Partial only.** There is no Sapling Spend-circuit witness vector. The existing note/nullifier and separately generated Merkle-path fixtures are joined only by commitment and position in the unchanged partial manifest; they do not supply one coherent `ak/ar/rk`, `cv`, anchor, path, and complete public-input record. |
| Third-party Z23 C23 port | [`z23c/z23` at `f271ce00f02df783944f8a9bcb464a5b8436a2e9`](https://github.com/z23c/z23/tree/f271ce00f02df783944f8a9bcb464a5b8436a2e9); see [`test_native_spend_proof.c`](https://github.com/z23c/z23/blob/f271ce00f02df783944f8a9bcb464a5b8436a2e9/tests/harness/src/test_native_spend_proof.c), [`groth16_spend_oracle_kat.h`](https://github.com/z23c/z23/blob/f271ce00f02df783944f8a9bcb464a5b8436a2e9/tests/harness/include/test/groth16_spend_oracle_kat.h), and [`GROTH16-SPEND-PARITY.md`](https://github.com/z23c/z23/blob/f271ce00f02df783944f8a9bcb464a5b8436a2e9/docs/quality/GROTH16-SPEND-PARITY.md) | The C test constructs a full witness and derives its public inputs through that port. A separate checked-in KAT contains `ask`, `nsk`, `rcm`, diversifier, value, position, and expected `ak`, `nk`, `ivk`, `pk_d`, note commitment, and nullifier. The project says its circuit port is based on librustzcash commit `06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5`. | **Promising but insufficient.** The KAT omits `ar`, `rcv`, the 32 authentication-path elements and directions, anchor, `rk`, `cv`, and the complete seven public inputs. The full-witness test does not check in its derived public outputs; those are computed by the same C implementation under test. Its proof test also self-skips without the local Sapling parameter file. The source pin differs from the target `sapling-crypto` 0.9.0 revision, and no evidence found here establishes equivalence between those circuit revisions. This is not accepted as a complete independent reference. |
| Published upstream release assets | [`sapling-crypto` GitHub releases](https://api.github.com/repos/zcash/sapling-crypto/releases?per_page=10) | The GitHub releases endpoint returned an empty list. | **Unavailable.** No release asset or archived witness was found. |

The upstream `TestConstraintSystem` assertions are not an export mechanism:
the test reads selected variables and public inputs for assertions, while
`hash()` commits to ordered constraint shape, not the witness assignment.
The pinned CI run establishes that the test passed, not the literal sampled
values. The official vectors provide useful independent component evidence,
but their records do not compose into the missing Spend fixture.

The acquisition route remains blocked until a source provides, for one
coherent case, every private witness field (including canonical encodings,
all 32 path siblings and direction bits) and all seven public inputs in
upstream order, plus provenance tying the values to the pinned circuit or a
demonstrably equivalent revision. Unblocking evidence should include the
generator/toolchain and source revision, the actual serialized values or a
durable test artifact, and independent validation of their relationships
against the upstream circuit (for example, upstream-generated values or an
externally verified proof tied to the exact official parameters). A test that
only regenerates values with its own implementation, a matching constraint
count/hash, or unrelated partial vectors is insufficient. No complete
reference, Spend circuit API, or compatibility claim is added.

#### Phase 9.20.19: Spend relation coverage and rho closure

**Outcome: one isolated Spend relation is now constrained and independently
checked end to end; complete Spend verification remains unavailable.** The
highest-priority relation supported by the existing references was the
nullifier preimage point:

```text
rho = cm + [position]J
```

The pinned Spend synthesis derives `position_bits` from authentication-path
direction bits, computes `[position]J` with the fixed nullifier-position
generator, adds it to the constrained note commitment point, and hashes the
canonical representation of `rho` with `nk`. ZyCoin previously constrained
the BLAKE2s nullifier hash and multipacking but accepted the `rho` representation
as an independent witness input. The new
`make_sapling_nullifier_rho_witness` and
`constrain_sapling_nullifier_rho` helpers reuse the existing fixed-base
multiplication and Jubjub addition gadgets. Callers must bind `cm` to the note
commitment gadget and supply the 32 authentication-path position bits; this is
not a Spend circuit API.

The regression composes the constrained note commitment, the new rho
relation, canonical point representation, nullifier BLAKE2s, and two
public-nullifier chunks using case 1 from the pinned Sapling key-components
vectors. It checks the vector's independently published `cmu`, position, `nk`,
and `nf`. The point `rho` itself is not a separately published fixture value;
the independently expected nullifier is the end-to-end oracle. Boundary tests
cover positions zero and `2^32 - 1`, canonical rho encoding, position and
commitment-randomness tampering, rho/representation tampering, and public
nullifier-chunk tampering. No new expected-value fixture was generated and
the partial Spend manifest remains unchanged and incomplete.

| Required upstream relation | ZyCoin implementation | Independent reference | Test coverage | Status at Phase 9.20.19 |
|---|---|---|---|---|
| `ak`, `nk`, `ivk`, and payment-address/`pk_d` derivation | Shared host-side ZIP32/key derivation; IVK BLAKE2s gadget exists. | Pinned key-components vectors at `zcash-test-vectors` commit `78321beacb0e0477e33cd002b56585a107c2708c`. | Key-component and IVK vector tests. | **Partially implemented.** The Spend witness does not constrain the complete key/address derivation chain. |
| Note contents and `cm = NoteCommitment(value, g_d, pk_d, rcm)` | `constrain_note_commitment` and shared Pedersen/fixed-base gadgets. | Published key-components/note-encryption vectors; `note_cmu` and note fields are cross-checked. | Independent note-commitment tests; Phases 9.20.19 and 9.20.22 bind the note output to the path leaf and rho input. | **Verified as a component relation.** No full Spend circuit or key-derivation assembly. |
| `cv = [value]V + [rcv]R` | `constrain_sapling_value_commitment`. | Pinned note-encryption/value-commitment vector and pinned `sapling-crypto` value formula at commit `88a7946b4a3066787776e11f0a502654167e022d`. | Independent commitment, boundary, and tampering tests; Phase 9.20.22 composes a locally derived `cv` using the same value bits as the note. | **Verified as a component relation.** The composed test's `rcv`/`cv` are local and are not an independent Spend vector. |
| `rk = ak + [ar]G` | `constrain_sapling_randomized_authorization_key` constrains the 252 little-endian Jubjub scalar bits, fixed-generator multiplication, point addition, and ordered public coordinates. The host witness constructor enforces `0 <= ar < r`; no less-than-`r` comparison is added to the circuit bit constraints. | Phase 9.20.24 adds case 0 from the pinned `zcash-test-vectors` Sapling RedJubJub signatures corpus: encoded subgroup `ak=vk`, nonzero Jubjub scalar `ar=alpha`, and expected `rk=rvk`, generated as `vk + alpha * SPENDING_KEY_BASE`. | Tests independently source nonzero `ak/ar/rk`, check bit width/order and multiplication input, public coordinate order, and tampering of both coordinates, `ak`, and `ar`. | **Verified as the component relation.** The point equation is independently checked for the fixture tuple and scalar semantics match pinned types/gadget behavior; it remains component-level, not a complete Spend assembly. |
| Merkle authentication path and path-derived `position_bits` | `constrain_merkle_authentication_path` range-checks and packs the 32-bit position, uses bit `i` for the left/right selection at level `i`, hashes all 32 parents, and binds the final root either strictly or conditionally when given the note value. | Pinned upstream-generated Merkle path fixture, with canonical node encodings and anchor. No coherent independent Spend witness. | Phase 9.20.20 verifies path semantics; Phase 9.20.22 passes the returned position-bit variables directly to rho and binds the note's `cm.u` to the Merkle leaf. | **Verified as component composition on the zero-value case.** Full Spend synthesis/order and an independent complete witness remain unavailable. |
| Conditional anchor `(root - anchor) * value = 0` | `constrain_sapling_conditional_anchor` uses the caller-supplied value variable. | Pinned upstream source specifies the equation; the joined independent path/note is zero-value. | Phases 9.20.21 and 9.20.22 verify the zero-value composition; Phase 9.20.21 separately tests both branches with local assignments. | **Implemented; source-backed semantics verified.** No independently sourced nonzero Spend assignment; caller must pass the value tied to the same 64-bit opening. |
| `rho = cm + [position]J` | Fixed-base/addition, point representation, BLAKE2s, and multipacking helpers. | Pinned note/nullifier vector; no independent literal `rho`. The case-0 note/path join also establishes matching `cmu` and position. | Phase 9.20.19 verifies the constrained note→rho→nullifier result; Phase 9.20.22 supplies the Merkle path's actual position-bit variables to rho and the note point to both path and rho. | **Verified as component composition for the joined zero-value case.** `nk` remains an externally supplied witness input; no complete Spend assembly. |
| `nf = BLAKE2s(nk concatenated with repr(rho))` and public chunks | Constrained BLAKE2s and 254+2-bit public multipacking gadgets. | Pinned key-components nullifier vectors and pinned Bellman 0.15.0 multipacking specification. | Phase 9.20.19 checks the case-1 note→rho→nullifier result; Phase 9.20.22 carries the joined case-0 note through path-derived position, rho, hash, and public chunks. | **Verified as component relations and joined composition.** `nk` is supplied from the authoritative vector, not derived inside a complete Spend assembly. |
| All seven Spend public inputs bound in upstream synthesis order | Randomized-key helper binds `rk.u/v` at slots 0–1, value commitment binds `cv` at 2–3, path binds anchor at 4, and multipacking binds nullifier chunks at 6–7. There is still no Spend assembler. | Upstream source specifies ordering; no complete independent seven-input Spend record exists. The independent RedJubjub vector establishes only the `rk` component and is not joined to the unrelated note/path fixtures as a purported full witness. | The Spend component-composition regression proves slots 0–1 are constrained using the nonzero published tuple and tests coordinate tampering. | **Partially implemented.** `rk` public binding is independently vector-verified for the fixture's scalar range; complete key derivation and full-witness public-input validation remain missing. |
| Complete Spend witness satisfaction and proof relation | No complete Spend circuit/API; proving remains disabled. | No qualifying independent complete witness was found in Phase 9.20.18. | Component and relation tests only. | **Unavailable.** Keep complete reference acquisition explicitly blocked; no compatibility or full-circuit claim. |

The pinned circuit provenance is
[`src/circuit.rs` at `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs);
the independent relation-vector provenance is
[`sapling_key_components.json` at `78321beacb0e0477e33cd002b56585a107c2708c`](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/sapling_key_components.json).
The complete Spend reference acquisition remains **blocked** as documented
above; Phase 9.20.19 closes only the rho relation and does not change that
finding.

Validation on CPython 3.10.11: focused BLAKE2s/rho tests **9 passed**; full
suite **91 passed**; `compileall`, targeted Ruff, and targeted Pylance
diagnostics passed. Wheel and sdist builds passed. A clean-target wheel
installation imported `zycoin.sapling_gadgets` and read the bundled `btcz.json`
resource; the sdist contains this report, its index, the relation tests, the
existing authoritative nullifier fixture, and gadget source. The first
resource-list assertion used the wrong filename (`bitcoinz.json`); inspection
showed the configured file is `btcz.json`, and the corrected packaging check
passed.

#### Phase 9.20.20: Spend Merkle path-to-position binding

**Audit result: the required path/position constraints already existed; no
constraint implementation was missing.** The coverage gap was that the
existing test only changed direction bit 0, did not tamper with the leaf, and
did not exercise a valid constrained path at the maximum 32-bit position.
Rather than duplicating correct constraints, this phase strengthens the
regression suite.

The pinned Spend synthesis at
[`src/circuit.rs` revision `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
iterates over the authentication path in tree-level order. At each level it
allocates a Boolean direction bit, appends that bit to `position_bits`
least-significant first, conditionally reverses `(current, sibling)`, hashes
the two field elements with that level's Merkle personalization, and makes
the final root conditional on the note value before exposing the anchor.
The authentication path therefore defines the Spend position bit-by-bit; it
is not an independently supplied scalar position.

ZyCoin's `constrain_merkle_authentication_path` already applies a 32-bit
little-endian range check to its private position, which Boolean-constrains
all bits and constrains the packed position to their weighted sum. The loop
uses `position_bits[level]` to constrain both left/right selections before
hashing the level-specific Pedersen parent. Its leaf is the input variable to
the first parent hash, and the final parent is constrained equal to the
public anchor. This proves the requested bit-to-position, direction-to-hash,
leaf-to-root, and root-to-anchor relationships locally.

The expanded test uses witness 3 from
[`sapling_merkle_tree_reference.json`](../tests/fixtures/sapling_merkle_tree_reference.json),
whose independently pinned upstream-generated authentication path, leaf,
position, and anchor provide a Merkle-only reference. It checks all 32
little-endian position-bit assignments, the first two path-ordering cases,
and tampering of each position bit both alone and together with its packed
position. It also checks the leaf, siblings at levels 0, 1, and 31,
intermediate roots at levels 0, 15, and 31, the public anchor, and the
authentication-path width. A separately synthesized maximum-position path
checks the canonical `2^32 - 1` boundary and rejects a position assignment
of `2^32`; its path hashes are generated by the local witness helper and are
not treated as independent expected values.

The fixture establishes Merkle path and anchor semantics only. It is not a
Spend-specific witness: no coherent independent record binds its leaf/path,
nonzero note value, `rk`, `cv`, nullifier, and all seven public inputs. The
when the path gadget is used without its optional note-value argument, it
retains the standalone unconditional anchor behavior. Pinned upstream uses
`(computed_root - anchor) * value = 0`, allowing an arbitrary anchor for a
zero-value note. The local strict selected-node decomposition also remains
structurally different from upstream's non-strict `to_bits_le` hashing. The
conditional anchor is implemented in Phase 9.20.21.

Phase 9.20.20 focused Merkle/Sapling tests on CPython 3.10.11: **20 passed**.
The updated relation matrix above records the isolated Verified status and
these explicit Spend-integration limitations. The blocked complete Spend
reference acquisition remains unchanged. The full Python 3.10.11 suite passes
**91 tests**; compileall, targeted Ruff, targeted Pylance diagnostics, report
and index consistency, and `git diff --check` pass. Wheel and sdist builds
pass; the sdist contains the updated report/index, Merkle fixture, regression
test, and gadget source. A clean-target wheel installation imports
`constrain_merkle_authentication_path` and reads the bundled `btcz.json`
resource.

#### Phase 9.20.21: Spend conditional anchor semantics

The pinned Spend synthesis at
[`src/circuit.rs` revision `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
constructs `value_num` from the 64 little-endian Boolean bits returned by
`expose_value_commitment`. After computing the Merkle root `cur`, it allocates
the public anchor `rt` and enforces:

```text
(cur - rt) * value_num = 0
```

Thus the condition depends on the note value from the value-commitment
opening, not on path validity or a Boolean “witness valid” flag. For a
nonzero value, field arithmetic forces `cur == rt`. For a zero value the
constraint is satisfied for any public anchor. The Merkle path itself is
still fully constrained in either branch: each path bit is Boolean, selects
the two level-ordered hash inputs, and contributes to the computed root.
The path's leaf remains bound to the first hash independently of the anchor
condition.

Added `constrain_sapling_conditional_anchor`, which emits that single
R1CS relation over the already-constrained root, public anchor, and private
note-value variable. It deliberately does not range-check or duplicate
value-opening constraints: callers must bind this value to the same 64
Boolean bits used by note/value-commitment synthesis. The existing
`constrain_merkle_authentication_path` accepts an optional keyword-only
`note_value`; when supplied it uses the upstream conditional relation.
Without that argument, its existing strict root-to-anchor equality remains
unchanged for standalone Merkle use. This helper is not a Spend circuit API
and does not establish complete witness assembly.

The independent pinned key-components vector supplies a zero-value note
whose commitment matches the pinned upstream-generated Merkle path fixture.
The combined regression verifies the path remains constrained while a
different public anchor is allowed at value zero. It then changes both the
value variable and its 64-bit decomposition to one: the same wrong anchor
fails, while the computed root used as anchor satisfies the relation. It
also rejects a tampered leaf and sibling under the zero branch, and verifies
the helper rejects a public value variable, public computed root, and
foreign-system value. The nonzero branch and negative tampering cases are
locally synthesized constraints; the independent fixture itself remains a
zero-value component/path join and is not a complete Spend witness.

The relation matrix now marks conditional anchor semantics as implemented
and source-backed. Complete Spend reference acquisition remains **blocked**;
there is no claim of full Spend witness verification or upstream circuit
compatibility. On CPython 3.10.11, focused Sapling tests **21 passed** and
the full suite **92 passed**. `compileall`, targeted Ruff, and targeted
Pylance diagnostics pass. Wheel and sdist builds pass; archive inspection
confirms the updated reports, existing independent Merkle/nullifier fixtures,
tests, and gadget source are included. A clean-target wheel installation
imports the conditional-anchor helper and reads the bundled `btcz.json`
resource. Pip reported resolver warnings for pre-installed protobuf consumers,
but the wheel installation and import succeeded.

#### Phase 9.20.22: Spend relation integration audit

The composition audit compared the pinned
[`src/circuit.rs` at `sapling-crypto` commit `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
with the local relation helpers. Upstream's relevant data flow is: expose the
64-bit value and constrain `cv`; derive the note commitment from that same
value, `g_d`, `pk_d`, and `rcm`; use its `cm.u` as the Merkle leaf; use the
authentication path's 32 little-endian direction bits as position bits; use
the same value in `(root - anchor) * value = 0`; derive
`rho = cm + [position]J`; hash `repr(nk) || repr(rho)`; and pack the digest
into public inputs 6 and 7. The public input order is
`rk.u, rk.v, cv.u, cv.v, anchor, nf[0], nf[1]` after the implicit constant.

Added `test_spend_component_relations_share_note_value_path_and_position`.
It composes the pinned case-0 nullifier note with its matching independently
generated Merkle path fixture, and verifies these exact local variable
connections:

| Shared relation data | Composition and check |
|---|---|
| Note value and opening | One private `value` and its 64 range-checked bits feed both the value commitment and note commitment; the same `value` variable selects conditional-anchor behavior. Changing the value or a shared bit fails. |
| Note commitment | The constrained `cm.u` is explicitly equated to the Merkle leaf; the same constrained point feeds rho. Changing either the note output or the leaf alias fails. |
| Position | The path's constrained 32-bit little-endian position bits are passed directly to the fixed-base rho relation. The test confirms each same variable appears in both path and rho constraints; changing a direction bit fails. |
| Nullifier | The constrained rho point is canonically represented, combined with vector-provided `nk`, hashed, and the same 256 digest bits are multipacked into public inputs 6 and 7. Tampering with rho, its representation, digest, or a public chunk fails. |
| Public fields | `cv.u/v`, anchor, and nullifier chunks occupy slots 2–3, 4, and 6–7 respectively. The test confirms the allocated seven-slot order. |

This is a constrained component-composition regression, not a purported
complete Spend reference: case 0 independently supplies the note commitment,
position, `nk`, and nullifier; the matching Merkle fixture independently
supplies the path and anchor; the test's `rcv=1` and resulting `cv` are local
test assignments, not authoritative expected Spend values. Its zero note
value only exercises the zero branch in the joined fixture; the nonzero
conditional branch remains covered by the local tests from Phase 9.20.21.

The audit also confirms the integration boundary and remaining gaps:

- The helpers do not constitute a Spend assembler. Callers must reuse the
  returned note point, path position bits, value variable, and nullifier bits
  as this regression does. An unrelated private variable of the right kind
  is not automatically bound by the conditional-anchor helper.
- The test allocates seven public inputs in upstream order. `cv`, anchor, and
  nullifier outputs are constrained at their expected slots, but `rk.u` and
  `rk.v` are placeholders. An inspection of all constraint expressions
  confirms neither slot is referenced. The `rk = ak + [ar]G` relation and
  constrained `ak`/`ar` derivation are still missing.
- `nk` and the note address inputs are supplied from the vector; their full
  Spend key derivation chain is not synthesized. The fixture has no
  independent `cv` for this joined note.
- The safe standalone note and value-commitment helpers each Boolean-check
  shared value bits, so composing them through these public entry points
  repeats those Boolean constraints. The Output assembler has an internal
  preconstrained-bits path, but there is no Spend assembler/API that can
  safely select it. No constraints were removed in this audit.
- Upstream source relation order is known, but local constraint allocation
  order/shape is not Bellman-equivalent. No full witness, proof, or compatible
  Spend circuit is claimed.

The independent evidence remains limited to the exact fixture components
listed in
[`sapling_spend_partial_reference.json`](../tests/fixtures/sapling_spend_partial_reference.json).
It is not combined into a complete Spend witness. Complete independent Spend
reference acquisition remains explicitly **blocked**.

On CPython 3.10.11, the new composition regression passes, the full suite
passes (**93 tests**), and focused Sapling tests pass. `compileall`, targeted
Ruff, targeted Pylance diagnostics, and `git diff --check` pass. Wheel and
sdist builds pass; the sdist contains this report, the reports index, the
composition test, the partial manifest, and both joined independent fixtures.
A clean-target wheel install imports the conditional-anchor helper and reads
the bundled `btcz.json` resource. Pip emitted resolver warnings for unrelated
pre-installed protobuf consumers; installation and import succeeded.

#### Phase 9.20.23: Spend randomized authorization key

The pinned Spend synthesis at
[`src/circuit.rs` revision `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
states that `ak` is witnessed from `proof_generation_key.ak()`, checks it is
on the Jubjub curve, and applies `assert_not_small_order`. It then obtains
little-endian Boolean bits from `ar`,
computes `[ar]SPENDING_KEY_GENERATOR`, adds that point to `ak`, and calls
`inputize` on the resulting point as `rk`. The generator is the Sapling
subgroup generator defined by pinned
[`constants.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/constants.rs)
with personalization `Zcash_G_` and empty message, matching the existing
`spending_key_base()`/`sapling_fixed_base_generator("spending_key")`.

The `Spend` struct declares `ar: Option<jubjub::Fr>`, so its host witness is a
Jubjub scalar, not an arbitrary canonical BLS12-381 scalar. The R1CS arithmetic
is over the BLS12-381 scalar field, while point coordinates are in the Jubjub
base field and `ar`, `nsk`, `rcv`, and `rcm` use the Jubjub scalar type. The
pinned source converts these scalar witnesses with Bellman's
`field_into_boolean_vec_le`; this conversion and its exact range semantics
must not be conflated with a canonical BLS12-381 scalar range check. `ak`, the
generator multiple, and `rk` are Jubjub points. Upstream
does not add an in-circuit subgroup test for `ak`; its witness comes from the
subgroup-valued Sapling key derivation, while the circuit itself constrains
curve membership and non-small-order. ZyCoin's witness constructor also
checks `ak` is in the subgroup, a synthesis-time validation guard; the R1CS
relation intentionally follows upstream's on-curve/non-small-order checks
and does not claim to prove subgroup membership from arbitrary unconstrained
inputs. `rk` public inputs are the two canonical BLS12-381 scalar-field
coordinates in `u, v` order, not a compressed 32-byte point encoding.

Added `make_sapling_randomized_authorization_key_witness` and
`constrain_sapling_randomized_authorization_key`. The latter currently
range-checks `ar` against the BLS12-381 scalar modulus and constrains its
255-bit little-endian variable-base Jubjub multiplication by the fixed generator,
constrains `ak + [ar]G`, and separately binds result `u` and `v` to public
input indices 0 and 1. Both coordinates are required, owned by the same R1CS,
public, and ordered. The helper is a relation gadget, not a public Spend
circuit API. Compared with the pinned `Option<jubjub::Fr>` host type,
accepting the wider BLS12-381 scalar range is an upstream-compatibility gap;
the current independent vector exercises a valid Jubjub scalar but does not
detect this over-acceptance.

The regression suite covers:

- The existing pinned ZIP-32 `ak` from
  [`sapling_ivk_blake2s_reference.json`](../tests/fixtures/sapling_ivk_blake2s_reference.json).
  For `ar = 0`, the expected randomized key is the independently sourced
  point itself; this checks its encoding/subgroup and public coordinate
  binding but is only the identity-randomizer case.
- `ar` values `0`, `1`, `Jubjub scalar modulus - 1`, the Jubjub scalar
  modulus, and `BLS12-381 scalar modulus - 1`; invalid negative, Boolean, and
  field-modulus values are rejected. Nonzero expected randomized keys in
  these boundary tests are computed by ZyCoin and are local tests, not
  independent vectors.
- Identity/small-order, invalid-curve, and valid-on-curve but
  non-subgroup authorization keys; a noncanonical encoded point is rejected.
- Both public coordinates, both authorization-key coordinates, `ar`, and
  swapped `u/v` public assignments; each tampering case makes constraints
  unsatisfied (or fails validation for malformed inputs).
- The Phase 9.20.22 relation-composition regression now uses a nonzero local
  `ar`, constrains the `rk` coordinates in public slots 0–1, and verifies
  tampering of both public coordinates and the `ak`/`ar` witness values.

At Phase 9.20.23's cutoff, no authoritative test vector containing a coherent
nonzero `ak`, `ar`, and
expected `rk` was found in the pinned local vector corpus. Consequently the
nonzero relation is **source-backed and locally constrained-tested**, not
independently vector-verified. The zero-randomizer relation is anchored to
the published `ak`, but it does not independently exercise multiplication by
a nonzero scalar. The Phase 9.20.22 note/path/nullifier vectors remain
separate component evidence and are not represented as a complete Spend
witness. Complete independent Spend reference acquisition remains
**blocked**; no complete Spend verification or circuit compatibility is
claimed. On CPython 3.10.11, the full suite passes (**94 tests**), including
the randomized-key and Spend composition regressions. Focused Sapling tests
pass (**22 gadget tests; 10 BLAKE2s/Spend tests**). `compileall`, targeted
Ruff, targeted Pylance diagnostics, and `git diff --check` pass. Wheel/sdist
builds and clean-target wheel import/resource checks pass; the sdist includes
the current reports, implementation, tests, and existing independent
fixtures. At that phase cutoff, no randomized-key fixture had been added.

#### Phase 9.20.24: Independent nonzero randomized authorization-key vector

The acquisition route is closed for the isolated randomized-key relation:
case 0 of the published
[`sapling_signatures.json`](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/sapling_signatures.json)
at `zcash-test-vectors` revision
`78321beacb0e0477e33cd002b56585a107c2708c` provides `vk`, nonzero `alpha`,
and `rvk`. The pinned vector generator
[`redjubjub.py`](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/redjubjub.py)
defines `randomize_public(vk, alpha)` as `vk + self.P_g * alpha`, and
constructs the case with `self.P_g = SPENDING_KEY_BASE`. The pinned
[`generators.py`](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/generators.py)
derives that base using `find_group_hash(b'Zcash_G_', b'')`, which matches
the SpendAuth generator in the pinned Sapling circuit constants and ZyCoin's
existing generator helper.

The separate fixture
[`sapling_randomized_authorization_key_reference.json`](../tests/fixtures/sapling_randomized_authorization_key_reference.json)
records exactly that source tuple (`ak=vk`, `ar=alpha`, `rk=rvk`), its source
revision, relation, encoding notes, and case index. The pinned vector
[`jubjub.py`](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/jubjub.py)
defines `Fr` modulo the Jubjub scalar order and serializes its value as
32-byte little-endian. The value is canonical and nonzero, and the regression
verifies that it is less than the BLS12-381 scalar modulus used by the Spend
circuit.
The Jubjub compressed points decode as subgroup points. Thus no reinterpretation
of bytes or generated expected output is used: the fixture's published `rvk`
is the expected value supplied to the R1CS relation. The test checks both
public coordinates, verifies the source generator matches the circuit helper,
and rejects changes to either public coordinate, either `ak` coordinate, or
`ar`.

The vector's `alpha` is a canonical Jubjub scalar, matching the pinned Spend
host field type. The current ZyCoin helper accepts a wider BLS12-381 scalar
range than the pinned `jubjub::Fr` input and uses a 255-bit decomposition;
that mismatch is not exercised by this fixture and must be corrected before
claiming upstream-compatible scalar semantics. The vector independently
verifies the nonzero point relation for its value; it does not verify complete
Spend synthesis, provide a complete Spend witness, or establish circuit
equivalence. The composition regression
uses the published tuple alongside separate note/path/nullifier component
evidence only to test shared R1CS/public-input bindings. Those independent
fixtures do not describe one coherent Spend witness. Complete independent
Spend reference acquisition remains **blocked**.
Verification on CPython 3.10.11: the full suite passes (**95 tests**), and
the focused Sapling gadget/Spend relation suites pass (**33 tests**).
`compileall`, focused Ruff, and Pylance diagnostics for both changed test
modules pass; Pylance reports no diagnostics. Wheel and sdist builds pass.
The sdist contains this report, the reports index, and the new reference
fixture. A `--no-deps` clean-target wheel installation successfully imports
`zycoin` and `zycoin.coin_loader` and reads the bundled `coins/btcz.json`
resource. `git diff --check` passes.

#### Phase 9.20.25: Complete Spend witness coverage audit

This audit compares ZyCoin's current components to the exact `Spend` struct
and `Circuit::synthesize` order at pinned
[`sapling-crypto` revision `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs).
The host witness inventory and synthesis sequence recorded in the
[complete Spend circuit audit](#complete-spend-circuit-audit) above are the
source-backed reference: seven host fields—six option-bearing values
(`value_commitment_opening`, `proof_generation_key`, `payment_address`,
`commitment_randomness`, `ar`, and `anchor`) plus the ordered vector of
optional authentication-path entries—followed by the
ten-stage allocation/constraint sequence. The seven application public
inputs, after Bellman's implicit `ONE`, are exactly
`rk.u, rk.v, cv.u, cv.v, anchor, nf_chunk_0, nf_chunk_1`. The private key
fields are `ak` and `nsk`; the circuit derives `nk`, `ivk`, `g_d`, and `pk_d`.
It does not witness `ask`, verify an authorization signature, or prove
Groth16 inside the Spend relation.

| Spend field or relation | Status | Evidence, wiring, and exact remaining gap |
|---|---|---|
| Pinned witness fields, synthesis order, and seven public-input order | **Verified** | The pinned source explicitly declares the host fields and synthesizes `rk`, `nk`/IVK, address, `cv`, note commitment, path/anchor, `rho`, nullifier, and multipacking in that order. ZyCoin has no single allocator implementing this order; source agreement does not imply matching Bellman variable/constraint order. |
| BLS12-381 scalar-field R1CS and variable ownership | **Implemented, Unverified** | ZyCoin's R1CS evaluates equations over the intended scalar field and guards variable ownership. No Spend-wide constraint transcript, ordered Bellman comparison, or full-system independent witness establishes compatibility. |
| `ak` curve membership and non-small-order | **Partially Verified** | Jubjub point and small-order relations are implemented and exercised in the `rk` gadget. There is no single Spend synthesis binding this point to a complete `ProofGenerationKey`; upstream itself does not constrain `ak = [ask]G` or require a signature. |
| `ar` host type and field-to-bit decomposition | **Verified** | Pinned `Spend` types `ar` as `Option<jubjub::Fr>`. The pinned Jubjub `Fr` modulus is `0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7`, with `NUM_BITS = 252`; Bellman's `field_into_allocated_bits_le` allocates exactly those bits in little-endian order and only Boolean-constrains them. The canonical host field value is below the modulus, but the constraint gadget does not add a less-than-modulus check over its 252 Boolean witness bits. ZyCoin now validates public witness construction against the Jubjub modulus and uses 252 bits; its custom `ar` variable is range-decomposed and tied to those bits without an additional modulus comparator. |
| `rk = ak + [ar]SPENDING_KEY_GENERATOR`; public `rk.u/v` | **Verified** | The nonzero pinned RedJubJub tuple independently checks the point equation, both coordinates, and source generator; R1CS tests reject key, scalar, and coordinate tampering. Scalar multiplication consumes the 252 little-endian bits, matching Bellman's fixed-base table lookup order. This establishes the equation for the fixture tuple only; integration remains component-level and the custom R1CS construction is not Bellman-equivalent. |
| `nsk` decomposition, `nk = [nsk]PROOF_GENERATION_KEY_GENERATOR`, and `repr(nk)` | **Partially Verified** | Jubjub fixed-base multiplication, point representation, and the generator primitive exist. The pinned key-components case 0 includes paired `nsk`/`nk` values, but the Spend relation does not allocate `nsk`, constrain this derivation, or feed its result to both later hash preimages. |
| `repr(ak)` concatenated with `repr(nk)`, then IVK BLAKE2s (`Zcashivk`, low 251 bits) | **Partially Verified** | The constrained IVK hash and representation encoding are checked against pinned key-component/ZIP-32 evidence. In Spend, the inputs are not the `ak` and derived `nk` variables from a common witness; those bindings and stage ordering are absent. |
| Diversifier, `g_d`, `pk_d = [ivk]g_d`, and their note-preimage representations | **Partially Verified** | Group hash, point/scalar arithmetic, representation, and note-commitment primitives are present and individually exercised. There is no constrained chain from the payment-address diversifier through the derived IVK to the same `pk_d` used by the Spend note commitment, nor a coherent independent Spend vector for the chain. |
| 64-bit `value`, `rcv`, value commitment, public `cv.u/v`, and reuse of value bits | **Partially Verified** | The value-commitment formula is checked against an independent note-encryption vector, and the component composition reuses one 64-bit value decomposition for `cv` and note contents. This is not a single independent Spend assignment. The local helper canonical-range-checks the Jubjub scalar randomness; upstream's `field_into_boolean_vec_le` path does not add that canonical Jubjub-range constraint for `rcv`, as its source comment states. Accepted witness semantics and constraint trace therefore still differ. |
| Note contents (`value`, `repr(g_d)`, and `repr(pk_d)`), Pedersen commitment, `rcm`, and `cm` | **Partially Verified** | Note commitment is independently vector-tested, and the Spend component regression binds the same note point to the path leaf. `g_d` and `pk_d` currently enter as external component inputs rather than being produced by the Spend key/address chain. Local scalar widths/range constraints and Pedersen construction are not shown to have Bellman's identical trace. |
| 32-level path, Boolean directions, sibling ordering, and path-derived position | **Partially Verified** | An authoritative Merkle path fixture verifies root and direction semantics; composition passes the returned position bits directly to `rho`. The fixture is Merkle-only, and the local custom R1CS/Pedersen constraint construction has not been shown identical to Bellman's per-level construction. There is no full Spend-path witness. |
| Conditional anchor `(cur - anchor) * value = 0` | **Verified** | The local gadget implements the exact equation from pinned source and tests both branches. The joined independent note/path case is zero-valued; a nonzero independent Spend assignment is not available. The caller binding to the same value-opening bits is tested locally, not through a complete independent witness. |
| `rho = cm + [position]NULLIFIER_POSITION_GENERATOR` | **Partially Verified** | The constrained relation reuses path-derived direction bits and the joined note/path fixture establishes its commitment and position. The independent nullifier vector verifies the resulting nullifier end-to-end but does not publish an independent literal `rho`; `nk` is supplied as a fixture input, not derived from `nsk` in the same system. |
| Nullifier PRF BLAKE2s (`repr(nk)` concatenated with `repr(rho)`, `Zcash_nf`) | **Verified** | Pinned key-component/nullifier vectors independently verify digest behavior and the component regression connects the path-derived `rho` to the constrained hash. Complete Spend composition still lacks the upstream-derived `nk`. |
| 256-bit nullifier multipacking and public chunks 6–7 | **Verified** | Pinned digest/multipacking evidence verifies little-endian bit order, 254+2-bit split, public slot placement, boundaries, and tampering. The helper is exercised in the partial Spend composition, but not after a full Spend synthesis. |
| Shared-variable composition and all seven public inputs in one Spend system | **Missing** | The regression shares `value`/bits across `cv` and note, binds `cm.u` to the path leaf, reuses path bits in `rho`, and feeds `rho` to the nullifier hash. It manually allocates the public tuple; its `rk` comes from a different published vector, `cv` is locally derived, the nullifier fixture supplies `nk`, and key derivation is not joined. These are isolated composition tests, not one coherent witness. |
| Exact Bellman allocation, constraint order, complete Spend satisfaction, and circuit hash | **Missing** | ZyCoin has no Spend assembler or complete independently sourced witness. Its custom R1CS/Pedersen/fixed-base/BLAKE2s structures have not been compared relation-by-relation as ordered constraints with Bellman 0.15.0. Matching component values or counts cannot establish equivalence. |

The independent fixtures **cannot form one coherent Spend witness**. The
case-0 note/nullifier and Merkle-path materials align on note commitment and
position, and the local regression joins their supported relations; however,
the fixture is zero-valued, uses an externally supplied `nk`, and has no
matching proof-generation key, independently verified `cv`, or matching
`rk`. The RedJubjub `ak/ar/rk` vector and the value-commitment vector are
separate cases. The regression's `rcv=1` is locally chosen. No values are
combined or represented here as an authoritative complete witness. The
complete independent Spend-witness acquisition finding remains **blocked**.

The remaining blockers, in dependency order, are: (1) obtain a coherent,
independently generated full witness; (2) implement one Spend assembly that
threads the same `ak/nsk/nk/ivk/g_d/pk_d/value/cv/cm/path/position/rho/nf`
variables and public inputs through pinned synthesis order; (3) reconcile
upstream field-to-bit semantics and host domains for `nsk`, `rcv`, and `rcm`,
including the explicit upstream comments that omit extra canonical range
constraints; and (4) compare the complete ordered constraint stream and
serialization with Bellman before asserting circuit equivalence. The current
component gadgets do not show evidence for another Spend-specific relation
beyond those inventoried above; `ask` derivation, authorization signatures,
transaction authorization, and Groth16 proving are not part of this pinned
Spend circuit relation.

The original Phase 9.20.25 recommendation to investigate `ar`/scalar
decomposition is superseded by the source-backed closure below.

#### Phase 9.20.26: Spend randomizer scalar semantics

The exact pinned sources settle the `ar` semantics:

- The pinned `Spend` struct at
  [`circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
  declares `ar: Option<jubjub::Fr>`. The circuit immediately passes it to
  `boolean::field_into_boolean_vec_le`, then to the
  [`fixed_base_multiplication`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs)
  for `SPENDING_KEY_GENERATOR`.
- The pinned Sapling manifest depends on Jubjub 0.11. The
  [`jubjub::Fr` source](https://docs.rs/crate/jubjub/0.11.0/source/src/fr.rs)
  defines modulus
  `r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7`,
  `NUM_BITS = 252`, and canonical 32-byte little-endian field encoding.
  Therefore valid host `ar` values are integers `0 <= ar < r`.
- Pinned
  [Bellman 0.15.0 `field_into_allocated_bits_le`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/boolean.rs#L262-L315)
  emits exactly `F::NUM_BITS` Boolean variables, least-significant bit first.
  Its gadget adds Boolean constraints but no separate comparison proving
  that the bit-string is less than `r`. The typed host value is canonical;
  the circuit's bit witness by itself can represent any 252-bit integer.
- Bellman's pinned
  [fixed-base multiplication](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs)
  consumes those bits in little-endian order, in consecutive 3-bit windows.
  On the order-`r` subgroup generator, the resulting point represents scalar
  multiplication by the integer encoded by the bits (and thus is reduced
  modulo `r` by the group law).

Updated `make_sapling_randomized_authorization_key_witness` to accept only
canonical Jubjub scalars `0 <= ar < r`, and to construct exactly 252
little-endian bits. Updated the R1CS helper to decompose the scalar variable
into 252 bits, with Boolean and reconstruction constraints but no separate
less-than-`r` comparator. This is the closest semantic representation in
ZyCoin's custom R1CS: the public witness constructor rejects `r` and larger
values, while the Boolean circuit relation itself does not impose a
less-than-modulus condition on an arbitrary 252-bit witness. That distinction
matches Bellman's typed host input versus circuit constraints; it does not
make ZyCoin's full allocation or constraint stream Bellman-compatible.

Regression coverage now checks `ar=0`, `1`, and `r-1`; rejects `r`, negative,
Boolean, and BLS12-381-only out-of-domain values; verifies 252-bit
little-endian ordering and reconstruction; checks that the multiplication
witness consumes those exact bits and equals the generator multiplication;
and rejects scalar and `rk.u/rk.v` tampering. The existing independent
nonzero `(ak, ar, rk)` fixture is unchanged and remains the expected point
oracle for its canonical scalar.

`ar` semantics are now **Verified against pinned source behavior** and the
independent fixture verifies the nonzero point equation for its scalar.
This closes only the randomizer semantic gap. The other scalar fields `nsk`,
`rcv`, and `rcm`, full shared-variable Spend composition, a coherent
independent Spend witness, Bellman constraint ordering/hash, and complete
Spend compatibility remain unverified or blocked. No Spend API or proving
support was added. On CPython 3.10.11 the full suite passes (**95 tests**);
focused Sapling gadget/Spend tests pass (**33 tests**). `compileall`, targeted
Ruff, and Pylance diagnostics for the changed gadget and tests pass. Wheel and
sdist builds pass, the sdist contains the updated report and retained
randomized-key fixture, and a clean-target wheel install imports both
`zycoin` and `zycoin.sapling_gadgets` and reads the bundled `btcz.json`
resource. Markdown link/anchor, matrix, report-index, whitespace, and
`git diff --check` validations pass.

#### Phase 9.20.27: Spend assembly reassessment

This is the current coverage matrix, superseding the Phase 9.20.25 snapshot
above. It audits the pinned `Spend` allocation order and the actual shared
variables in
[`test_spend_component_relations_share_note_value_path_and_position`](../tests/test_blake2s_gadget.py).
The matrix distinguishes independently tested components from an assembled
Spend relation; component vectors are not treated as one witness.

| Spend field or relation | Status | Current evidence and exact remaining gap |
|---|---|---|
| Pinned host-witness fields, synthesis order, and seven public inputs | **Verified** | Pinned `sapling-crypto` 0.9.0 source specifies host inputs and the order `rk`, key derivation, address, `cv`, note, path/anchor, `rho`, nullifier, and multipacking. The public order is `rk.u, rk.v, cv.u, cv.v, anchor, nf[0], nf[1]`, after implicit `ONE`. The regression allocates these seven inputs in that order; there is no single Spend allocator enforcing the complete upstream sequence. |
| Component gadgets and custom R1CS substrate | **Implemented, Unverified** | The individual point, scalar, BLAKE2s, Pedersen, path, anchor, and multipacking gadgets are implemented and covered at component level. Their combined constraint stream has not been compared relation-by-relation with Bellman. |
| Complete Spend circuit assembler | **Missing** | No one function synthesizes the pinned Spend relations in upstream order while threading the same derived key/address/note/path/nullifier variables through all public inputs. |
| `ak` validation and `rk = ak + [ar]G`; public `rk.u/v` | **Verified** | The nonzero pinned RedJubJub tuple independently checks the point equation and both coordinates; R1CS tests reject key, scalar, and coordinate tampering. This verifies the component relation only. |
| `nsk -> nk = [nsk]G`, then `repr(nk)` | **Partially Verified** | The pinned key-components case 0 includes paired `nsk` and `nk` values, correcting the Phase 9.20.25 matrix's overly broad statement that no such pair was available. The relation is not synthesized from an `nsk` variable in the Spend composition, and its result is not shared with the later IVK and nullifier preimages. |
| IVK from `repr(ak) \|\| repr(nk)` | **Partially Verified** | The IVK hash is independently checked against key-component/ZIP-32 evidence. In the Spend regression, there is no shared `ak/nk` derivation feeding this stage; the `nk` used by the nullifier hash is allocated directly from fixture bytes. |
| Diversifier, `g_d`, `pk_d = [ivk]g_d`, and address-to-note inputs | **Partially Verified** | Group-hash, point, scalar-multiplication, and note-commitment components are tested. The joined regression supplies fixture-derived `g_d` and `pk_d` directly; neither is derived from the same constrained IVK/address chain. |
| `ar` and `rk` scalar/point relation | **Verified** | Phase 9.20.26 matches the host `jubjub::Fr` domain and 252-bit little-endian decomposition, and the independent nonzero tuple checks the resulting point. The constructor enforces canonical host `ar`; Bellman's bit constraints themselves do not add a scalar-modulus comparator. This does not establish a full Spend circuit match. |
| 64-bit value, `rcv`, value commitment, public `cv.u/v` | **Partially Verified** | The value-commitment formula has an independent component vector, and the regression shares one value decomposition between `cv` and the note. Its `rcv=1` is locally selected, not from a coherent Spend reference; ZyCoin's canonical `rcv` range check is stricter than the pinned field-to-bits constraints. |
| Note contents, `rcm`, `cm`, and `cm.u` leaf binding | **Partially Verified** | An independent key-component fixture and the joined zero-value case exercise the commitment; `cm.u` is explicitly equated to the Merkle leaf. `g_d`/`pk_d` are supplied rather than derived by the same Spend, and local scalar/constraint semantics have not been compared against Bellman. |
| 32-level path, position directions, and conditional anchor | **Partially Verified** | An independent Merkle-only fixture verifies path direction, root and position; the zero-value joined case tests the conditional anchor. The same path position bits are passed to `rho`. No independent complete Spend fixture establishes all these relations together. |
| `rho = cm + [position]J` and nullifier PRF | **Partially Verified** | The joined regression uses the note point and path-derived position in the `rho` relation and hashes the result. It supplies `nk` externally rather than deriving it from the `nsk` witness in the same system. |
| Nullifier multipacking and public chunks | **Verified** | Independent digest/multipacking evidence verifies little-endian bit order, 254+2 packing and public positions 6–7; the helper is also exercised in the partial composition. |
| Complete deterministic upstream test-witness reproduction | **Partially Verified** | The standalone Python generator now reproduces the pinned seed and sampling order and emits a coherent witness. The other ten-case external-vector test independently verifies `cv.u/v`; upstream publishes no literal expected values for the remaining fields, so their outputs lack field-by-field external validation and no complete witness fixture is claimed. |
| Pure-Python deterministic witness generator | **Implemented, Unverified** | `sapling_spend_reference.py` reproduces the pinned RNG, sampling order, key/address, note, `rk`, `cv`, path, anchor, nullifier, and seven public inputs without R1CS gadgets. All ten `cv.u/v` values from the separate pinned external-vector test match; the other generated fields have no published literal upstream witness oracle. |
| One shared witness across all relations and all public inputs | **Missing** | The test shares `value`/bits across `cv` and note commitment, binds `cm.u` to the path leaf, reuses path bits in `rho`, and feeds that `rho` to the nullifier hash. But `nk` is fixture-allocated; `rk` comes from a separate RedJubJub vector; `cv` is locally generated with `rcv=1`; and the zero-valued note/path case is separate. The manually allocated public tuple is not a full Spend synthesis. |
| Complete witness satisfaction, Bellman constraint ordering/hash, and circuit compatibility | **Missing** | No coherent authoritative witness, complete Spend assembler, ordered Bellman constraint comparison, or Spend-wide verification is present. Individual fixture results and constraint counts do not establish completeness or compatibility. |

**Shared-variable and encoding audit.** In the partial regression, the note
value variable and its 64 range bits are passed to both value commitment and
note commitment; the note commitment's `u` coordinate is equated to the path
leaf; the path's 32 little-endian position bits are passed directly to the
`rho` multiplication; and the resulting `rho` representation feeds the
nullifier hash. The nullifier digest bits then feed the two public chunks.
The `ak/ar` variables feed `rk`, whose public coordinates occupy inputs 0–1.
The public tuple's positions and values are checked in that regression.
However, `nsk` is not allocated or used there, `nk` is allocated from encoded
fixture bytes, and there is no one key/address chain deriving and reusing
`nk`, `ivk`, `g_d`, and `pk_d`. The isolated vector values for `rk` and `cv`
do not belong to the zero-valued note/path case.

Several local Boolean constraints are duplicated in this test system:
`ar` bits are Boolean-constrained by range decomposition and again by scalar
multiplication; the shared value bits are constrained by `range_check` and
again by note commitment (the call does not mark them preconstrained); path
position bits are Boolean-constrained by `range_check` and again when used in
the `rho` scalar multiplication; and nullifier digest bits are checked by
the hash gadget and again by multipacking. These are redundant local
constraints, not evidence that the underlying variables are disconnected or
that invalid assignments are accepted. They are retained; this phase does
not remove constraints or assert Bellman trace equivalence.

**Independent-evidence determination.** A complete coherent independent
Spend witness is not present in the checked-in fixtures or the pinned
published vector cases reviewed here. The case-0 nullifier/key-components
data and Merkle path align on note commitment and position, but that join is
zero-valued and uses externally supplied `nk`. The nonzero `(ak, ar, rk)`
vector is separate; the value-commitment reference is separate; and the
regression's `rcv=1` is locally chosen. These components must not be presented
as a complete witness. The pinned upstream test's deterministic witness
generation is a possible source for a future independent pure-Python
reproduction, but it does not publish the resulting full witness as a
literal vector. Therefore full Spend assembly can be explored as code, but
cannot yet be independently validated or claimed compatible.

The Phase 9.20.27 recommendation to acquire a complete reference is addressed
by the report-only Phase 9.20.28 result below. No complete witness has yet
been produced; the exact remaining work is an independent pure-Python port
with a source-backed comparison for every generated field. Do not use ZyCoin
to generate expected values or implement a full-system Spend assembler before
that coherent reference exists.

#### Phase 9.20.28: Independent pure-Python Spend witness reproduction

**Phase 9.20.28 outcome: no complete fixture; reproducibility was not yet
implemented.** The pinned implementation was inspected directly at
[`sapling-crypto/src/circuit.rs` revision
`88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs).
The deterministic test `test_input_circuit_with_bls12_381` uses
`rand_xorshift` 0.5.0 / `rand_core` 0.10.1 and this 16-byte
`XorShiftRng` seed:
`58 62 be 3d 76 3d 31 8d 17 db 37 32 54 06 bc e5`. It runs ten iterations.
Each iteration samples, in order, a `u64` value, Jubjub `rcv`, fake-random
`ak`, `nsk`, an address-valid 11-byte diversifier (retrying on invalid
diversifiers), Jubjub `rcm`, 32 BLS12-381 sibling scalars each paired with a
sampled direction bit, and Jubjub `ar`. It then derives the viewing
key/payment address, `rk`, `cv`, note/`cmu`, anchor and position, nullifier
and nullifier multipacking.
The source checks circuit satisfaction, 98,777 constraints, a fixed shape
hash, `cmu`, and all eight Bellman inputs (implicit `ONE` followed by seven
application inputs).

That test does not log or serialize the generated witness. Its expected
values for the relation checks are computed by the same upstream APIs during
the test, so the pinned source establishes the procedure and assertions, but
not literal witness bytes suitable as an independent expected fixture. A
second pinned test,
`test_input_circuit_with_bls12_381_external_test_vectors`, uses seed
`59 62 be 3d 76 3d 31 8d 17 db 37 32 54 06 bc e5` and publishes ten
expected value-commitment coordinate pairs.
It still samples the proof-generation key, address, note randomness,
authentication path, and `ar` at runtime and does not publish complete
Spend witnesses or all seven public inputs. This is useful partial evidence
for `cv` only, not a complete witness oracle. Its fixed expected `cv.u/v`
values cover values `0..9` with `rcv = 1000 * (i + 1)`; the published
coordinates do not determine the other witness fields.

The request's reference to “all five Spend public inputs” does not match the
pinned circuit: Spend has seven application public inputs in this order:
`rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`, nullifier chunk 0, and nullifier
chunk 1. Bellman's implicit `ONE` is the eighth `TestConstraintSystem`
input, not an application public input. This ordering is asserted in the
pinned test and recorded in the coverage matrix.

The pinned test additionally asserts 98,777 constraints and shape hash
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`.
Those assertions constrain circuit shape/satisfaction, not the sampled
private witness values. The exact blocker is **not missing RNG state**: the
seed, crate versions, random-call order, and rejection loops are available in
the pinned source and lockfile. The remaining gap is that no independent
pure-Python implementation has reproduced the full cryptographic generation
pipeline, and no full literal witness exists against which such an
implementation can be checked. ZyCoin's gadgets were not used to create
expected values, no fields were invented, and unrelated fixtures were not
combined. The repository's
[partial Spend manifest](../tests/fixtures/sapling_spend_partial_reference.json)
remains explicitly incomplete. Therefore no deterministic complete witness
fixture can be accepted in this phase; this finding does not prove that a
careful independent port is impossible.

#### Phase 9.20.29: Pure-Python deterministic witness generator

Added
[`sapling_spend_reference.py`](../src/sapling_spend_reference.py), a
non-circuit reference generator for the pinned Spend test. It implements
`rand_xorshift` 0.5.0 / `rand_core` 0.10.1 word ordering, byte filling,
wide field sampling, and the test's field, subgroup-point, diversifier,
authentication-path, and randomizer sampling sequence. It computes the
proof-generation key and viewing key, address, note commitment, randomized
key, value commitment, 32-level anchor and position, nullifier, and seven
application public inputs. Its “spending key” fields are the pinned circuit's
proof-generation-key components `ak` and `nsk`; the upstream Spend witness
does not contain `ask`. It treats Bellman's `ONE` separately. It imports
the repository's pure-Python Jubjub point/hash primitives, but does not
import or call `r1cs`, `sapling_gadgets`, or the R1CS BLAKE2s gadgets; it is
not the R1CS assembler or a claim of circuit equivalence.

The RNG transition and byte/word rules are pinned to
[`rand_xorshift` 0.5.0](https://docs.rs/crate/rand_xorshift/0.5.0/source/src/lib.rs)
and
[`rand_core` 0.10.1 utilities](https://docs.rs/crate/rand_core/0.10.1/source/src/utils.rs);
wide Jubjub and BLS scalar conversion follows
[`jubjub` 0.11.1 `Fr`](https://docs.rs/crate/jubjub/0.11.1/source/src/fr.rs)
and
[`bls12_381` 0.9.0 scalar](https://docs.rs/crate/bls12_381/0.9.0/source/src/scalar.rs).
The pinned dependency versions are those resolved by the upstream
[`Cargo.lock`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/Cargo.lock).

The explicitly sourced expected `cv.u/v` pairs for all ten cases of the
pinned `test_input_circuit_with_bls12_381_external_test_vectors` are stored
in
[`sapling_spend_external_cv_reference.json`](../tests/fixtures/sapling_spend_external_cv_reference.json).
All ten pairs match the Python value-commitment calculation. This test uses
the upstream vector test's separate seed and fixed openings (`value=i`,
`rcv=1000*(i+1)`). It does **not** make its random key, note, path, or public
inputs a complete published vector.

The deterministic first case from
`test_input_circuit_with_bls12_381` is also generated as a coherent
in-memory witness, and the regression checks repeatability, 32 direction
bits, Merkle root reconstruction, nullifier packing, and exact seven-input
ordering. It is not saved as a provenance fixture: the pinned primary test
does not publish literal expected values for its `value`, `rcv`, `ak`, `nsk`,
`nk`, `ivk`, diversifier/address, `rcm`, `cm`, `ar`, `rk`, authentication
path, anchor, nullifier, or packed public inputs. The local deterministic
regression is not an independent oracle for those fields. Although the
generator computes them, their expected values remain **unverified against
independent literal results**. The report therefore does not present the
generated output as an independently checked complete witness.

**Completion status:** RNG/sampling and reference formulas are implemented;
all ten upstream `cv.u/v` assertions plus the independent note/nullifier and
Merkle component vectors pass. A complete independently verified witness
and provenance-bearing full witness fixture remain **Missing**. No R1CS
assembler, Sapling spending support, or compatibility claim was added. On
Python 3.10.11 the full suite passes (**100 tests**), the five focused
generator tests pass, `compileall`, targeted Ruff, and Pylance
diagnostics pass, and wheel/sdist plus clean-target import checks pass. The
sdist contains the generator, its CV-only provenance fixture, tests, and
reports.

#### Phase 9.20.30: independent Spend witness relation verification

Added
[`sapling_spend_verification.py`](../src/sapling_spend_verification.py).
It does not import the Phase 9.20.29 generator. It recomputes the IVK, `nk`,
payment-address key, note commitment, value commitment, randomized key,
Merkle root/position, nullifier, and seven ordered public inputs through
separate existing Sapling code paths: ZIP-32 key derivation, note-decryption
commitment logic, value/rk gadget witness calculations, the commitment-tree
Merkle hash, and the validated-note nullifier API. It also checks sampled
field domains, path encoding, and the pinned public-input sequence. These are
independent implementation paths for relation consistency, not independent
literal expected values for the seeded witness; some low-level Jubjub and
group-hash primitives are shared.

The following matrix classifies every generated witness field. “Direct”
published matches refer only to the fixture/case identified in the evidence
column; they must not be read as a published value for the Phase 9.20.29
seeded witness.

The pinned synthesis and sampling semantics are in
[`sapling-crypto` `circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs).
Separate published component evidence is retained in the
[ten-case value-commitment fixture](../tests/fixtures/sapling_spend_external_cv_reference.json),
[Sapling key-components fixture](../tests/fixtures/sapling_nullifier_reference.json),
[randomized-authorization-key fixture](../tests/fixtures/sapling_randomized_authorization_key_reference.json),
and [Merkle-path fixture](../tests/fixtures/sapling_merkle_tree_reference.json).
These fixtures describe different test inputs and are not merged into a
single purported Spend vector.

| Witness field | Evidence classification | Evidence and limitation |
|---|---|---|
| `value` | Checked only through upstream source semantics | The pinned test samples a `u64`; the checker enforces the width and checks downstream relations. No seeded literal value is published. |
| `rcv` | Checked only through upstream source semantics | The pinned test samples a Jubjub scalar; range checked and its value-commitment relation recomputed. The ten published `cv` cases use a different test seed and fixed openings. |
| `ak` | Checked only through upstream source semantics | The primary test samples a non-identity subgroup point; the checker validates curve/subgroup properties and its downstream use. No seeded `ak` literal is published. |
| `nsk` | Checked only through upstream source semantics | The scalar range is checked and the relation to `nk` is recomputed. No seeded `nsk` literal is published. The Spend circuit witness contains `ak`/`nsk`, not `ask`. |
| `nk` | Independently recomputed from authoritative specifications | Recomputed as `[nsk]PROOF_GENERATION_KEY_GENERATOR`; there is no primary-seed literal for comparison. |
| `ivk` | Independently recomputed from authoritative specifications | Recomputed from the canonical `ak`/`nk` encodings and Sapling IVK BLAKE2s rule; no primary-seed literal is published. |
| `diversifier` | Checked only through upstream source semantics | The 11-byte sampled diversifier is validated through its dependent address relations; no seeded literal is published. |
| `diversifier_base` (`g_d`) | Independently recomputed from authoritative specifications | Recomputed from `Zcash_gd` and the sampled diversifier. No seeded literal is published. |
| `transmission_key` (`pk_d`) | Independently recomputed from authoritative specifications | Recomputed as `[ivk]g_d`; no seeded literal is published. |
| `rcm` | Checked only through upstream source semantics | Scalar range and its note-commitment relation are checked; no seeded literal is published. |
| Note commitment point / `cmu` | Independently recomputed from authoritative specifications | Recomputed through the separate note-decryption commitment implementation. Its `cmu` relation also matches published key-component cases, but those cases use different witness inputs; no primary-seed expected `cmu` exists. |
| `ar` | Checked only through upstream source semantics | Scalar range and its use in `rk` are checked; no primary-seed literal is published. |
| Randomized key (`rk`) | Independently recomputed from authoritative specifications | Recomputed by the separate fixed-base gadget witness path. The independent RedJubjub tuple fixture directly matches a different `(ak, ar, rk)` case, not this seeded witness. |
| `value_commitment` (`cv.u/v`) | Directly matched against published expected values | All ten pinned external-test-vector pairs are retained and pass. They correspond to the separate external-vector test. The primary seeded `cv` has no published literal; its relation is recomputed by the verifier. |
| Authentication path | Checked only through upstream source semantics | The checker enforces 32 canonical siblings and Boolean directions. The seeded path entries are generated, not published as literals. |
| Merkle position | Independently recomputed from authoritative specifications | Reconstructed from the path direction bits. The separately published Merkle fixture validates the algorithm on another leaf/path, not this seeded path. |
| Anchor | Independently recomputed from authoritative specifications | Recomputed through the separate Sapling commitment-tree Merkle implementation. The seeded anchor has no published literal; an independent path fixture covers another witness. |
| Nullifier | Independently recomputed from authoritative specifications | Recomputed through `SaplingNote` and the public nullifier API. The key-components fixture directly matches its own note/key/position case; no primary-seed nullifier literal is published. |
| Seven application public inputs | Checked only through upstream source semantics | The verifier recomputes their values from checked relations and checks the pinned order (`rk.u/v`, `cv.u/v`, anchor, then two nullifier chunks). No complete seeded public-input vector is published. |
| Bellman implicit `ONE` | Checked only through upstream source semantics | The pinned test's `num_inputs()` count includes `ONE`; it is not one of the seven application inputs and is not a generated witness field. |
| `ask` / complete spending key | Not independently verified | The pinned circuit witness carries `ak` and `nsk`; it does not carry `ask`. This generator does not claim to derive or verify a complete spending key. |

Regression coverage calls the verifier on the generated witness and mutates
each exposed witness field in turn, including each of the seven public-input
slots; each mutated case is rejected. This proves that the verification
relations are connected to those fields, not that the un-published seeded
values are independently correct. The existing ten `cv` vector comparisons,
key-components note/nullifier checks, Merkle fixture check, and randomized
authorization-key vector checks remain unchanged and separate.

**Completion status:** every generated field now has an explicit evidence
classification, and independently computable relations have verifier and
mutation coverage. The deterministic seeded inputs and their derived outputs
still lack a coherent authoritative literal oracle. The checker therefore
does not close the independent full-witness evidence gap; do not begin full
Spend R1CS assembly on the basis of its consistency result. Obtain an
independently generated complete fixture or independently published primary
test outputs first. No Spend assembler, proving support, or spending
capability was added.

#### Phase 9.20.31: independent full Spend reference acquisition

**Outcome: no ready-to-use complete independent witness source or fixture
was found.** Sources examined:

| Source | What it provides | Why it does not close the exact-witness gap |
|---|---|---|
| Pinned [`sapling-crypto` `circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs), revision `88a7946b4a3066787776e11f0a502654167e022d` | The exact circuit, witness-generation order, RNG seed/call order, relation assertions, seven application public-input order, constraint count and shape hash. | It is the implementation being audited. Its test constructs its sampled values and expected relations in-process; it does not publish a serialized assignment or literal values for the seeded witness. A shape hash/count does not reveal the private values. |
| [`zcash/zcash-test-vectors`](https://github.com/zcash/zcash-test-vectors/tree/78321beacb0e0477e33cd002b56585a107c2708c), revision `78321beacb0e0477e33cd002b56585a107c2708c` | Maintained pure-Python protocol reference modules for [Jubjub](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/jubjub.py), [generators](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/generators.py), [Pedersen](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/pedersen.py), [note/nullifier](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/notes.py), [key components](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/key_components.py), [Merkle tree](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/merkle_tree.py), [RedJubjub](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/redjubjub.py), ZIP-32, and per-relation JSON vectors. | The pinned JSON inventory contains Sapling generators, key components, note encryption, signatures and ZIP-32 datasets, but no circuit Spend assignment or record joining the exact `test_input_circuit_with_bls12_381` seed to its sampled fields and all seven public inputs. These modules are a plausible source for a separately implemented verification harness, not an already available full-witness reference. |
| [`QED-it/zcash-test-vectors-internal`](https://github.com/QED-it/zcash-test-vectors-internal/tree/cbdb16ed55f15a255e76cb2a40ee4b90b47a7a62), revision `cbdb16ed55f15a255e76cb2a40ee4b90b47a7a62` | Small Python calculators for Jubjub, generators, key components, Merkle, notes/Pedersen and signatures. | The inspected tree contains only these component scripts and a short README; it has no circuit witness export or complete seven-input Spend case. It was last pushed in 2018, predates the pinned Sapling 0.9.0 test, and is not a suitable version-matched full-witness oracle. |
| [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf) and the [Sapling ZIPs](https://zips.z.cash/) | Normative Spend, note, key, group, commitment and encoding semantics. | Specifications define computations and encodings; they do not supply the seeded test's RNG outputs or a complete test-witness fixture. |
| [`summa-tx/riemann`](https://github.com/summa-tx/riemann/blob/9e6dbaaf1b339594c0c0d55b2db6e96d7e3f12c4/riemann/tx/sapling.py) | Python Sapling transaction/proof byte structures. | The examined module serializes transaction fields and proof bytes; it does not implement seeded circuit witness generation or derive the private witness relations. |
| [`betterclever/zebend`](https://github.com/betterclever/zebend/tree/38d3753f8c85c56eac1a7b82c42d2dfc7325436f), revision `38d3753f8c85c56eac1a7b82c42d2dfc7325436f` | An independently developed Zcash implementation with Sapling cryptography in Bend and Python orchestration. | It is not a pure-Python implementation, and the examined README/source search did not expose a serialized fixture for this pinned Rust circuit test. It is not eligible as a validation dependency under this phase's restrictions. |

Compatibility assessment: the pinned upstream [`Cargo.toml`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/Cargo.toml) specifies `sapling-crypto` 0.9.0, `jubjub` 0.11, `bls12_381` 0.9, Bellman 0.15 and `rand_xorshift` 0.5 for this circuit test. The Zcash pure-Python Jubjub reference uses the same base/scalar moduli (`q_j`/`r_j`), `a = -1`, `d = -10240/10241`, cofactor 8, little-endian compressed `v` plus the `u` sign bit, and group-hash rigidity string as the pinned Sapling implementation. Its generator and Pedersen code uses the Sapling personalizations and bases (`Zcash_G_`, `Zcash_H_`, `Zcash_J_`, `Zcash_PH`, `Zcash_cv`); its note/nullifier code uses `Zcashivk` and `Zcash_nf`, and the note commitment includes the six one-bit personalization prefix. The circuit's application input order remains `rk.u/v`, `cv.u/v`, anchor, then the 254+2-bit little-endian nullifier chunks.

These are compatible protocol primitives and an independent algorithmic basis for a future Python harness, not a byte-for-byte match already established for this test case. In particular, the vector library does not implement the pinned Rust XorShift/field-sampling sequence. Its Merkle test helper calls a `layer` argument using `MERKLE_DEPTH - 1 - layer`; the upstream circuit applies `MerkleTree(i)` while walking its path. Any independent port must explicitly reconcile the test helper's layer naming with the circuit's leaf-to-root depth before using its Merkle calculation. It also must reproduce the circuit test's random sibling values and exact field-to-bit handling. The blocking issue is therefore not a known curve or personalization mismatch; it is the missing independent seeded-input and complete-output calculation. The separate value-commitment, key-component, RedJubjub and Merkle fixtures cover different inputs and cannot be merged to fill that gap.

The sample fields still lacking independent expected values for the exact
seeded case are `value`, `rcv`, sampled `ak`, `nsk`, sampled diversifier,
`rcm`, all 32 sampled sibling field elements and direction bits, and `ar`.
Consequently, no exact-case expected values exist for derived `nk`, `ivk`,
`g_d`, `pk_d`, note commitment, `rk`, `cv`, position, anchor, nullifier, or
the seven application public inputs either. Relations for these derived
fields can be independently recalculated only after the sampled inputs are
independently established. Existing component vectors provide direct
expected values for their own separate cases only.

**Evidence needed to unblock:** either (a) an upstream-maintained serialized
witness from the pinned test containing the sampled fields and seven ordered
application inputs, or (b) a separately implemented pure-Python reproduction
using an independently sourced RNG interpretation plus the official
pure-Python Sapling reference algorithms, with reproducible checks for every
sample and derived field and provenance pinned to source revisions. The
second option is additional reference implementation work; it is not an
already available fixture and must not treat ZyCoin's generator or verifier
as its oracle.

**Completion status:** reference acquisition remains blocked. No fixture or
code was added in this documentation-only phase. The Phase 9.20.30
consistency verifier remains useful for relation mutation checks but is not
an independent expected-value source. Do not start full Spend R1CS assembly,
claim full-witness verification, or enable Sapling spending until the
evidence gate above is satisfied.

#### Prioritized implementation plan

1. **Build the missing independent pure-Python reference harness or acquire
   an upstream witness export.** The Zcash test-vector repository supplies
   suitable protocol primitive implementations, not the pinned test's
   complete witness or sampling harness. Independently validate the XorShift
   word/byte and field sampling interpretation, then use the upstream
   pure-Python vector algorithms to calculate and compare each complete
   witness field and public input. Do not use the Phase 9.20.29 generator or
   Phase 9.20.30 verifier as an oracle, infer outputs from circuit
   shape/hash, or join unrelated fixture cases. Keep full Spend assembly
   blocked until this evidence gate is met.
2. **Close the remaining isolated Spend path semantic gaps.** The constrained
   `rho = cm + [position]J` relation is covered in Phase 9.20.19 and the
   conditional `(root-anchor)*value=0` relation in Phase 9.20.21. Match
   upstream non-strict path-bit semantics where source evidence establishes
   them; test malformed widths and changed direction/sibling witnesses
   before wiring the path into a Spend circuit.
3. **Align shared circuit primitive semantics.** Reconcile Jubjub scalar-bit
   bounds with upstream field decomposition; compare Pedersen lookup,
   Montgomery segment addition/conversion, variable-base multiplication, and
   BLAKE2s `UInt32`/`MultiEq` construction against pinned source operations.
   Keep independent host-vector correctness and unsatisfied-tampering tests
   for each change; do not remove constraints solely to target upstream
   counts.
4. **Preserve and then align Output synthesis ordering.** Keep its verified
   external semantic fixture and randomness relationship; after primitive
   traces are comparable, adapt public/private allocation interleaving and
   witness bindings to the pinned order, then compare individual constraints
   and hash inputs. No API or compatibility claim before the complete
   requirement matrix is satisfied.
5. **Assemble Spend only after all preceding gates pass.** Bind all witness
   fields in pinned synthesis order, including shared value bits, `ak/ar/rk`,
   `nsk/nk/ivk`, address/`pk_d`, note/`cm`, path/position/anchor, `rho`,
   nullifier, and public multipacking. Add independent public-input and
   witness tampering checks; stop if any required primitive remains
   structurally or semantically different.
6. **Reproduce the upstream shape hash only against an identical stream.**
   Implement a small pure-Python port of Bellman 0.15.0's TestConstraintSystem
   hash procedure, first test it against a known upstream source test, and
   only compare Spend/Output digests after variable allocation, ordered
   constraints, and canonical coefficients are independently shown identical.
   Do not treat matching counts or a hash of ZyCoin's custom JSON as proof.

This order separates the feasible semantic witness work from the larger
constraint-equivalence effort. No circuit API, proving support, or spending
capability is implied by the plan.

### Constrained BLAKE2s implementation

The implementation follows Bellman's `blake2s` gadget used by the pinned
Sapling circuit (`bellman = 0.15.0` in the Sapling manifest), checked against
the released Bellman 0.15.0 source. The hash function follows RFC 7693:
BLAKE2s-256, 32-byte digest, no key, 64-byte blocks, 32-bit little-endian
words, ten rounds, and the standard SIGMA schedule. Bellman's Sapling-facing
API requires exactly eight personalization bytes and input bits in complete
bytes.

`src/blake2s_gadget.py` implements the following constrained execution:

- The parameterized initial state encodes digest length 32, fanout 1, depth 1,
  no key, and the two little-endian personalization words. The remaining six
  IV words and all BLAKE2s constants are fixed circuit constants.
- Message bits are ordered least-significant-bit first within each byte.
  Consecutive bytes form little-endian 32-bit words. Each 64-byte block is
  zero-padded to the compression input shape. The byte counter and final-block
  flag are applied exactly as in the Bellman gadget, including empty inputs
  and messages whose length is an exact block multiple.
- The ten rounds apply the RFC BLAKE2s G schedule and rotations (16, 12, 8,
  and 7). Rotations are bit wiring; XOR is constrained by a quadratic
  relation. Modular additions allocate 32 constrained output bits and
  constrained carry bits, then enforce the full integer reconstruction
  equation. Variable message bits and all generated arithmetic output bits
  are Boolean-constrained.
- The output is all 256 digest bits in little-endian byte order. No native hash
  result is used as an unconstrained output: the host `hashlib.blake2s` call in
  witness preparation supplies an expected digest only, and the synthesized
  constrained output is checked against it.

The Sapling interfaces expose exactly:

- `constrain_sapling_ivk`: `repr(ak) || repr(nk)`, each 256 bits, personalized
  with `Zcashivk`; returns the low 251 little-endian bits required by the
  Sapling circuit's `drop_5` truncation.
- `constrain_sapling_nullifier_hash`: `repr(nk) || repr(rho)`, each 256 bits,
  personalized with `Zcash_nf`; returns all 256 little-endian digest bits.

Both helpers constrain the underlying complete 64-byte BLAKE2s computation.
They do not construct the Jubjub points, compute `rho`, multipack the
nullifier, or synthesize the Spend circuit.

#### BLAKE2s verification and counts

The independent fixtures and tests provide:

- Bellman 0.15.0's blank-input test vector with personalization
  `12345678`, including its expected digest.
- The BLAKE2 reference KAT for message `00` with zero personalization (equal
  to the unpersonalized variant).
- A pinned `zcash-test-vectors` ZIP-32 IVK vector from commit
  `78321beacb0e0477e33cd002b56585a107c2708c`.
- A pinned Sapling note/nullifier fixture with its published expected
  nullifier, also checked through the `Zcash_nf` constrained interface.
- Boundary messages of 0, 1, 3, 63, 64, and 65 bytes against the independent
  Python `hashlib` implementation; the 65-byte case exercises two compression
  blocks. Tests mutate an input bit, digest bit, and intermediate addition
  witness and confirm unsatisfied constraints; malformed bit lengths,
  personalization, and witness mismatches are rejected.

For one 64-byte all-variable input, ZyCoin synthesizes **22,042 constraints**
and **21,723 variables** (including the ONE variable). A local Python 3.10.11
measurement took 0.746 seconds for synthesis and 0.065 seconds for
satisfaction evaluation. This is a single environment measurement, not a
performance guarantee; peak memory was not measured.

Bellman's pinned test reports **21,518 constraints** for 512 allocated
variable input bits. ZyCoin's 64-byte case is 524 constraints higher. The
systems are not wire-format or constraint-order compatible: ZyCoin uses
per-output-bit Boolean constraints and direct carry reconstruction, while
Bellman uses its `UInt32` and `MultiEq` gadgets. The 524-constraint difference
has not been reconciled constraint-by-constraint. This does not invalidate
the separately checked digest and tampering behavior, but it prevents any
claim of matching Bellman's constraint shape or hash.

## ZyCoin implementation

`src/r1cs.py` implements a generic rank-1 constraint builder with:

- Scalar-field variables, linear combinations, public/private allocation,
  constraints `A(w) * B(w) = C(w)`, multiplication, equality, Boolean, and
  bit-range constraints.
- Witness satisfaction evaluation and explicit errors for missing assignments,
  invalid indices, and cross-system expressions.
- Deterministic canonical JSON serialization of the field modulus, public
  input order, variable shape, and constraint shape. Witness values are
  deliberately omitted.

This generic format is ZyCoin-specific. It is not Bellman's wire format,
does not recreate Bellman's namespace/gadget naming, and has not been shown
to produce the upstream circuit hash or constraint counts.

`src/sapling_gadgets.py` adds the following constrained operations:

- Boolean bit packing (up to 254 bits to avoid scalar-field aliases) and strict
  field-element range decomposition. A strict bound comparator prevents
  non-canonical field aliases in bit representations.
- Jubjub twisted-Edwards curve membership, and the pinned circuit's point
  representation order (`v` bits followed by the low bit of `u`).
- Affine Jubjub addition using the pinned `U`, `A`, `B`, and `C` products and
  the two coordinate division relations. In the pinned source, `U`, `A`, `B`,
  and `C` are four multiplication constraints; the coordinate relations add
  two more R1CS constraints. Addition, doubling, and scalar multiplication
  require their input points to have been constrained on-curve by the caller.
  This is the source-level accounting used here.
- Pinned affine doubling, with its `T`, `A`, and `C` products and two division
  relations.
- Little-endian variable-base scalar multiplication using Boolean bits,
  conditional selection against the identity, repeated doubling, and affine
  addition.
- Sapling fixed-base multiplication for the six pinned protocol generators:
  proof-generation key (`Zcash_H_`, empty message), note-commitment randomness
  (`Zcash_PH`, `r`), nullifier position (`Zcash_J_`, empty message), value
  commitment value (`Zcash_cv`, `v`), value commitment randomness
  (`Zcash_cv`, `r`), and spending key (`Zcash_G_`, empty message). It accepts
  the upstream scalar widths (32-bit positions, 64-bit values, and 252-bit
  Jubjub scalar decompositions), with a maximum of 252 bits. Bits are read
  least-significant first in up to 84 three-bit windows; a partial last window
  is zero-padded. Each window selects identity or one of the first seven
  multiples from a base advanced by a factor of eight; selected points are
  accumulated in upstream order. The full-width Jubjub scalar receives a
  strict subgroup-order bound; shorter widths are inherently below that
  order. Lookup selection, scalar bit packing, and each point addition are
  actual R1CS constraints. Witness preparation is separate from satisfaction
  evaluation.
- Sapling value commitment using the pinned
  `[value]VALUE_COMMITMENT_VALUE_GENERATOR +
  [rcv]VALUE_COMMITMENT_RANDOMNESS_GENERATOR` formula. The value is represented
  by exactly 64 little-endian constrained bits, and `rcv` by 252 little-endian
  bits with the canonical Jubjub scalar bound. The two fixed-base products are
  constrained, their points are added in R1CS, and the result's `u`, then `v`,
  coordinates are bound to caller-allocated public inputs. Witness construction
  is separate from constraint evaluation. This gadget does not implement any
  additional transaction-level restriction on zero-value commitments.
- Sapling nullifier multipacking: 256 private Boolean variables in the
  existing BLAKE2s output order, packed as 254 and 2 little-endian bits into
  public inputs at R1CS variable indices 6 and 7, following the five preceding
  Spend inputs. Each packed chunk is tied to its public field element by an
  R1CS equality; each digest bit is Boolean-constrained. The chunk widths prove
  injectivity below the scalar modulus without a lossy reduction. Witness
  preparation from the 32-byte digest is separate from R1CS satisfaction.
- Six-bit Pedersen personalization and 3-bit lookup windows. The lookup
  selects the points for `(1 + a + 2b) * (-1)^c`, with successive windows
  weighted by powers of 16. The implementation uses all six pinned
  `Zcash_PH` generators, 63 windows per generator, and constrained point
  additions to combine windows and segments. The six-generator correction
  allows the 194 windows needed for a complete note-commitment preimage.
- Note commitment content hashing: 64 value bits, the 256-bit `g_d`
  representation, and the 256-bit `pk_d` representation, prefixed with the
  six-bit NoteCommitment personalization. The `g_d` point is constrained to
  the curve and non-small-order; `pk_d` follows the pinned Output-circuit
  representation semantics and is not independently constrained on-curve.
  The resulting Pedersen point is randomized by the constrained scalar
  multiplication `[rcm]R`, and its `u` coordinate can be bound to the Output
  public commitment.
- A 32-level Merkle authentication path: a constrained 32-bit position,
  position-bit-directed left/right selection, canonical 255-bit node
  decompositions, per-level MerkleTree personalization, Pedersen parent
  hashes, and equality of the final node to the public anchor. Witness
  generation and constraint synthesis are separate operations.
- `src/blake2s_gadget.py` provides constrained BLAKE2s-256 with Sapling's
  `Zcashivk` and `Zcash_nf` interfaces, complete-byte inputs, little-endian bit
  order, constrained carries and XORs, ten rounds, and a 256-bit result.

Witness-generation helpers are separate from R1CS satisfaction evaluation.
Witness helper output is not itself a constraint: all bit selections, point
operations, and output relations are represented in the generated system.
These gadgets are reusable components, not complete Sapling circuits.

### Gadget constraint accounting

Counts below are ZyCoin constraint counts, not full-circuit counts:

| Gadget / fixture | ZyCoin constraints |
|---|---:|
| Jubjub curve membership | 3 multiplications + 1 equation = 4 |
| Pinned affine point addition | 4 multiplications + 2 division relations = 6 |
| Pinned affine doubling | 3 multiplications + 2 division relations = 5 |
| Variable-base scalar multiplication, five bits | 63 after removing the identity allocation and first point addition; the pinned-base case also checks base membership |
| Fixed-base Jubjub multiplication, any of six bases, 32-bit position | 124 |
| Fixed-base Jubjub multiplication, any of six bases, 64-bit note value | 255 |
| Fixed-base Jubjub multiplication, 252-bit canonical scalar | 1,626: 252 lookup, 498 addition, 253 scalar-pack, and 623 strict-range constraints |
| Fixed-base Jubjub multiplication, 252-bit noncanonical-range mode | 1,002: 252 Boolean, 252 lookup, and 498 addition constraints |
| Sapling value commitment fixture | 1,889: 255 value-multiplication, 1,626 randomness-multiplication, 6 point-addition, and 2 public-coordinate binding constraints |
| Output value-commitment relation | 1,265; the upstream Output semantics do not add ZyCoin's standalone canonical-`rcv` check |
| Sapling nullifier multipacking | 258: 256 digest-bit Boolean constraints and 2 public-chunk packing equalities |
| Bellman-shaped fixed-base lookup window | 1 Boolean AND precomputation + 2 coordinate equations = 3 |
| Local signed Pedersen lookup window | 4 constraints; versus upstream's two-constraint lookup because ZyCoin allocates both Edwards coordinates and constrains conditional sign |
| Merkle Pedersen reference fixture | 3,522 including two strict 255-bit field decompositions |
| Note commitment reference fixture | 5,450, including the note-content Pedersen hash, fixed-base `rcm` multiplication, `g_d` checks, and public `cmu.u` binding |
| Output note-commitment component | 5,366 with the already constrained `g_d` and shared value bits |
| Output ephemeral-key component | 3,539 after removing identity initialization and the first addition |
| Composed local Output witness | 10,170; satisfied locally, not Bellman-compatible or independently verified end-to-end |
| 32-level Merkle path reference fixture | 87,650, including position and node decomposition, branch selection, 32 personalized Pedersen hashes, and public-anchor binding |
| BLAKE2s-256, one 64-byte variable block | 22,042, including 512 input-bit Boolean constraints; 21,723 total variables including ONE |

The fixture system has 172 lookup windows, 171 point additions, and two
strict-field decompositions. These counts describe the tests and individual
gadgets only. No local Spend or Output circuit count is available.

## Verification results

- Generic R1CS tests cover finite-field arithmetic, public/private ordering,
  satisfied and unsatisfied multiplication/equality constraints, Boolean and
  bit-range checks, missing assignments, deterministic shape serialization,
  omission of witness values, and rejection of foreign variables.
- Gadget tests cover strict field alias rejection, Jubjub membership and
  representation, valid/invalid curve points, affine addition and doubling,
  variable- and fixed-base scalar-multiplication tampering, and Pedersen
  lookup/input tampering.
- The six fixed-base generators reproduce their independent canonical
  coordinates from the pinned upstream `sapling-crypto` constants. The
  scalar-one tests synthesize the constrained gadget for every base and match
  those upstream coordinates. The 32-bit Merkle position and 64-bit note
  value call widths are separately synthesized and checked. Scalar zero,
  five, and the maximum canonical scalar (`r - 1`) are also checked;
  malformed widths, the non-canonical scalar `r`, invalid points, altered
  lookup points, altered accumulators, and changed scalar bits are rejected
  or make the R1CS unsatisfied.
- Each full-width ZyCoin fixed-base instance has 2,550 constraints. Bellman's pinned
  `lookup3_xy` uses one AND and two coordinate constraints per window; ZyCoin's
  one-hot implementation uses twelve selector multiplications and two
  coordinate constraints. Point addition uses six constraints in both
  source-level accounting. ZyCoin also enforces scalar packing and a strict
  canonical scalar bound. Thus its fixed-base system is not Bellman constraint
  shape/order compatible; no constraints were padded or removed to imitate
  Bellman counts.
- On CPython 3.10.11 on the current Windows host, a cold scalar-five
  measurement took 0.333 s for witness preparation, 0.046 s for synthesis,
  and 0.004 s for satisfaction evaluation. `tracemalloc` reported a 4,123 KiB
  peak for witness plus system creation. These are one-run local measurements,
  not performance guarantees; the memory figure excludes native/process RSS.
  Point arithmetic, generator validation, and Python constraint evaluation
  are variable-time and are not side-channel resistant.
- The Pedersen output matches the existing pinned MerkleCRH fixture in
  `tests/fixtures/sapling_merkle_tree_reference.json`. That vector's provenance
  is the pinned `zcash-test-vectors` `sapling/merkle_tree.py` reference. This
  verifies one host output against independent reference data; it is not an
  independent comparison of the full R1CS shape or every gadget equation.
- The note commitment's public `cmu.u` matches the first pinned
  `zcash-test-vectors` Sapling key-components vector in
  `tests/fixtures/sapling_nullifier_reference.json`. The R1CS satisfied test
  also checks the Output public-input order and rejects changes to the public
  commitment, `rcm` bits, or note value. This verifies the committed output
  against an independent vector; it is not an independent comparison of the
  full circuit's R1CS shape.
- The 32-level Merkle path satisfies its independently sourced fixture in
  `tests/fixtures/sapling_merkle_tree_reference.json`. The R1CS test checks the
  Spend anchor's public-input slot and rejects a changed anchor, sibling, or
  position bit; malformed path lengths and out-of-range positions are rejected.
  This does not establish equivalence to Bellman's complete Spend circuit.
- The value commitment matches the first published Sapling note-encryption
  vector in `tests/fixtures/sapling_value_commitment_reference.json`, pinned
  to `zcash-test-vectors` commit
  `78321beacb0e0477e33cd002b56585a107c2708c`; the upstream vector supplies
  value, `rcm`, and compressed `cv`. ZyCoin decodes the scalar little-endian
  and independently decodes the compressed Jubjub point. The R1CS test binds
  public coordinates in `u`, `v` order, satisfies at 3,057 constraints, and
  fails on altered public coordinates, value or randomness bits, a corrupted
  lookup selection, or a corrupted multiplication accumulator. Separate
  satisfied R1CS cases cover `(value, rcv) = (0, 0)` and the maximum 64-bit
  value with `rcv = r - 1`; `value = 2^64` and `rcv = r` are rejected. This
  independently verifies the host commitment output and local constraint
  behavior, not Bellman shape compatibility or a complete Spend circuit.
- Nullifier multipacking uses the pinned first Sapling key-components
  `note_nf` vector (`44fad6...ab4063`) from
  `zcash-test-vectors` commit
  `78321beacb0e0477e33cd002b56585a107c2708c`. Its expected packed values are
  calculated from that independently published digest using Bellman's pinned
  `compute_multipacking` rule: little-endian bit order, 254-bit chunks, and
  powers-of-two coefficients. The resulting decimal inputs are fixed in
  `tests/fixtures/sapling_nullifier_multipacking_reference.json`; they equal
  `15945210029497314482160337095886142342816578537174547304857438980922152516164`
  and `1`. The R1CS test confirms their exact public-input placement and
  satisfies with 258 constraints. Changing either public chunk or a digest bit
  fails satisfaction; a bit-reversed digest does not satisfy the published
  packed inputs. Zero and all-ones digests produce `(0, 0)` and
  `(2^254 - 1, 3)`. Wrong digest lengths, malformed bit widths, wrong public
  slots, non-Boolean assigned bits, and noncanonical witness chunk values are
  rejected. The upstream multipack
  gadget relies on its input Boolean types; ZyCoin explicitly adds all 256
  Boolean constraints, so its standalone constraint count is not Bellman's
  count or a Spend-circuit compatibility result.
- Phase 9.20.8 composes the existing constrained `Zcash_nf` hash output
  directly with nullifier multipacking using the same pinned note-nullifier
  vector. The resulting 256 hash bits satisfy the two independently derived
  public chunk values in positions 6 and 7; changing a public chunk makes the
  combined system unsatisfied. The combined fixture synthesizes **22,306
  constraints** (including 258 multipacking constraints). This verifies only
  the hash-to-packing boundary, not the upstream Spend path that constructs
  `nk`, `rho`, and all preceding public inputs.
- The affine addition/doubling equations and bit ordering were transcribed
  from the pinned upstream circuit gadget source. They have not been compared
  against Bellman's serialized constraints or a complete upstream
  constraint-system trace.
- BLAKE2s boundary and constrained-output tests pass for 0, 1, 3, 63, 64, and
  65-byte inputs. The blank-input personalized result matches Bellman 0.15.0's
  test vector; the zero-personalization one-byte result matches the BLAKE2
  reference KAT.
- The constrained `Zcashivk` output matches the pinned ZIP-32 reference vector
  and the constrained `Zcash_nf` output matches the pinned Sapling
  key-component note-nullifier vector. Tampering with a message, output, or
  intermediate modular-addition witness makes the R1CS unsatisfied.
- The Spend and Output counts listed in the circuit sections are upstream
  reference assertions, not ZyCoin results. Gadget counts above are measured
  from ZyCoin's local systems.
- Phase 9.20.2 validation on CPython 3.10.11: full regression suite **70
  passed**; focused Sapling gadget tests **8 passed**; `compileall` and Ruff
  passed. Wheel/sdist builds and clean-target wheel imports passed.
- Phase 9.20.4 validation on CPython 3.10.11: full regression suite **77
  passed**; focused BLAKE2s tests **7 passed**; `compileall` and targeted Ruff
  checks for the new module/tests passed. Repository-wide Ruff reports 471
  diagnostics outside these new files; those unrelated findings were not
  changed. Wheel/sdist builds and clean-target wheel imports passed; the
  installed wheel imports `zycoin.blake2s_gadget` and packaged coin resources.
  The sdist contains the BLAKE2s module, tests, IVK vector, this report, and
  the reports index.
- Phase 9.20.5 validation on CPython 3.10.11: full regression suite **81
  passed**; fixed-base tests cover all six upstream bases, range boundaries,
  32/64-bit call widths, invalid bases, and scalar/selection/accumulator
  tampering. Targeted Ruff and `compileall` passed. Wheel and sdist builds
  passed; clean-target wheel installation verified imports of `zycoin` and
  `zycoin.sapling_gadgets`, packaged coin JSON resources, and the sdist module.
- Phase 9.20.6 validation on CPython 3.10.11: full regression suite **83
  passed**; focused value-commitment tests **2 passed**; targeted Ruff and
  `compileall` passed. Wheel and sdist builds passed. A clean-target wheel
  install verified `zycoin.sapling_gadgets` and packaged coin JSON resources;
  the sdist contains the gadget module, pinned value-commitment fixture, and
  this report.
- Phase 9.20.7 validation on CPython 3.10.11: full regression suite **85
  passed**; focused multipacking tests **2 passed**; targeted Ruff and
  `compileall` passed. Wheel and sdist builds passed. A clean-target wheel
  install verified `zycoin.sapling_gadgets` and packaged coin JSON resources;
  the sdist contains the gadget module, pinned multipacking fixture, and this
  report.
- Phase 9.20.8 validation on CPython 3.10.11: the combined nullifier-hash and
  multipacking vector test passes within the full regression suite (**85
  passed**); `compileall`, targeted Ruff for the updated test, Pylance
  diagnostics for the test and BLAKE2s module, and whitespace checks pass. A
  broader Ruff run over the circuit implementation files reports 45 existing
  `UP` modernization findings in `src/r1cs.py`, which was not changed in this
  phase. Wheel and sdist builds pass; a clean-target wheel install imports
  `zycoin.sapling_gadgets` and finds all eight packaged coin JSON resources.
  The sdist contains the updated report, integration test, and pinned
  multipacking fixture.
- Phase 9.20.9 validation on CPython 3.10.11: full regression suite **85
  passed**, `compileall` and targeted Ruff passed, and Pylance reports no
  diagnostics for `src/sapling_gadgets.py`, `src/r1cs.py`, or
  `tests/test_sapling_gadgets.py`. Wheel and sdist builds passed; clean-target
  wheel installation verified `zycoin.sapling_gadgets` and all eight packaged
  coin JSON resources. The sdist includes this report and the reports index.
  The Output circuit audit is documentation only; no Output API or circuit
  constraints were added.
- Phase 9.20.10 is a documentation-only audit. The pinned Output synthesis
  body and pinned note-encryption reference code were reviewed; no encryption
  operation is a missing Output constraint, so no gadget, API, or constraint
  count was added. The full regression suite (**85 passed**), compileall,
  targeted Ruff for the constrained Sapling modules/tests, and Pylance
  diagnostics for the related modules/tests passed. A broader Ruff command
  including the unmodified `src/note_decryption.py` reports eight existing
  `UP035`/`UP045` modernization findings there; this audit made no code
  changes. Wheel/sdist builds and clean-target package/resource checks passed.
- Phase 9.20.11 validation on CPython 3.10.11: focused ephemeral-key tests
  verify the pinned vector, Output public-input slots, 3,547 local constraints,
  scalar boundaries, malformed/invalid inputs, and tampering. The full suite
  passed (**87 tests**); compileall and targeted Ruff passed; Pylance reports
  no diagnostics for the gadget or tests. Wheel/sdist builds and clean-target
  wheel import/resource checks passed, and the sdist includes this report,
  reports index, and pinned ephemeral-key fixture.
- Phase 9.20.12 validation on CPython 3.10.11: Output assembly binds all five
  public inputs and satisfies 16,715 local constraints; tampering with public
  inputs and major witness categories fails. The focused Sapling test file
  passed (**19 tests**) after adding the fresh-R1CS ABI guard; the full suite
  passed (**88 tests**). `compileall`, targeted Ruff, and Pylance diagnostics
  passed; Pylance signature compatibility found all three existing note
  commitment call sites compatible. Wheel/sdist builds passed, and a clean
  target install imported `zycoin.sapling_gadgets` and found all eight coin
  JSON resources. The sdist includes this report, its index, and tests. The
  composed test at that phase combined independent component fixtures; the
  complete independent relation-vector was added in Phase 9.20.14. Setuptools
  emitted deprecation and namespace package warnings during the successful
  build.

Phase 9.20.13 validation on CPython 3.10.11: **88 full-suite tests pass**,
with the focused Sapling gadget file passing **19 tests**. The composed
Output system measures **10,170** local constraints, down from 16,715.

Phase 9.20.14 validation on CPython 3.10.11: the full suite passes **88
tests**, including the independent Output vector and tampering checks.
`compileall` and targeted Ruff pass; Pylance diagnostics return no findings
for `src/sapling_gadgets.py` and `tests/test_sapling_gadgets.py`. Wheel and
sdist builds pass. Clean-target wheel installation imports both
`zycoin` and `zycoin.sapling_gadgets` and finds all eight packaged coin JSON
resources. The built sdist contains the new independent fixture and both
updated reports. Setuptools emits existing license-classifier and explicit
package-configuration warnings for the coin/wordlist resource directories;
the resources are nevertheless present in the wheel.

Phase 9.20.15 validation on CPython 3.10.11: the full suite passes **89
tests**, including 20 Sapling gadget tests. Targeted Ruff and `compileall`
pass; Pylance reports no diagnostics for the Spend test or its Sapling gadget
dependencies. Wheel and sdist builds pass; a clean-target wheel installation
imports `zycoin` and `zycoin.sapling_gadgets` and finds all eight coin JSON
resources. The sdist includes the partial Spend-reference manifest, its
regression test and source fixtures, this report, and the reports index.

Phase 9.20.16 validation on CPython 3.10.11: full suite **89 passed**;
targeted Ruff, `compileall`, and `git diff --check` passed. Pylance reported
no diagnostics in the reviewed Sapling source and test files. Wheel and sdist
builds passed; clean-target installation imported `zycoin` and
`zycoin.sapling_gadgets` and found all eight coin JSON resources. The sdist
contains the readiness report, reports index, and unchanged partial Spend
reference manifest.

## Status and blockers

| Capability | Status | Evidence / limitation |
|---|---|---|
| Generic scalar-field R1CS foundation | **Implemented, locally tested** | ZyCoin-only builder and serializer; no external wire-format compatibility claim. |
| Boolean, strict range, and bit packing gadgets | **Implemented, locally tested** | Bit constraints are local R1CS equations; not compared against the full Bellman gadget shape. |
| Jubjub membership, representation, addition, doubling, and variable-base multiplication | **Partially implemented, locally tested** | Pinned equations and bit order; subgroup checks and independent Bellman constraint comparison are not implemented. |
| Fixed-base Jubjub multiplication | **Implemented, independently generator-vector-tested** | All six pinned bases and the 3-bit/84-window semantics are represented by R1CS; the lookup relation uses Bellman's three-constraint `lookup3_xy` shape. Scalar range handling and full-circuit allocation/order equivalence are not established. |
| Sapling value commitment | **Implemented, fixture-tested** | Value and randomness multiplications, point addition, and public `cv` binding are constrained. The standalone API retains strict canonical `rcv`; Output synthesis uses the upstream full-bit-width semantics. Not a complete Spend or Output circuit. |
| Sapling nullifier multipacking | **Implemented, fixture-tested** | Little-endian 254+2-bit digest packing is bound to the exact two Spend public slots; a published nullifier digest, derived Bellman packing values, boundary digests, and tampering are tested. The hash-to-packing boundary is integrated and vector-tested; the complete Spend circuit is not. |
| BLAKE2s-256 R1CS gadget | **Implemented, vector-tested** | Full compression constraints, personalization, counters, and digest extraction; fixtures cover Sapling IVK/nullifier outputs and boundary lengths. The nullifier hash-to-packing composition passes its published vector. Bellman's constraint count differs by 524 for the recorded 512-variable-bit fixture, and no Bellman shape equivalence is claimed. |
| Sapling IVK and nullifier BLAKE2s interfaces | **Implemented, fixture-tested** | Pinned ZIP-32 IVK and note-nullifier vectors pass; these do not synthesize the surrounding circuit. |
| Sapling Pedersen lookup and group additions | **Implemented with two representations, vector-tested** | Edwards remains the default. The optional Montgomery path's NoteCommitment matrix matches the pinned Bellman-source Python transcription for Output and Spend note hashes; 32 Merkle levels are regression-tested. A Bellman-exported matrix is not available. |
| Note commitment constraints | **Partially implemented, fixture-tested** | Complete preimage and `rcm` randomization are constrained; the Output-specific Montgomery Pedersen route is source-transcription matched. Full Output-circuit equivalence remains unverified. |
| Sapling Output ephemeral-key relation | **Implemented, independently vector-tested** | The 252-bit little-endian variable-base relation binds `g_d`, `esk`, and public `epk.u/v` at 3,539 local constraints after removing identity initialization and the first addition. Diversifier bytes/hash derivation remains host-side; this is not a full Output circuit. |
| Sapling Output witness/public-input assembly | **Verified against one independent relation-vector; not circuit-equivalence verified** | One complete `zcash-test-vectors` note-encryption case matches all five public values and the value commitment, ephemeral key, diversified-base relationship, and `cmu.u`; tampering fails. Phase 9.20.68 local synthesis is 7,827 rows and matches its Bellman-source Pedersen transcription, but no full upstream matrix export is available. |
| 32-level Merkle authentication-path constraints | **Partially implemented, fixture-tested** | One upstream path fixture passes with tamper checks; conditional zero-value anchor semantics and full Spend-circuit equivalence are unimplemented. |
| Complete Sapling Spend circuit | **Unsupported / not implemented** | Fixed-base, value-commitment, nullifier-multipacking, and constrained nullifier-hash-to-packing boundaries exist; BLAKE2s/Pedersen structure, conditional path semantics, key/position/value wiring, exact full witness/public-input synthesis, and complete independent vector evidence remain missing. No ZyCoin full-circuit count or hash. |
| Bellman-compatible / independently verified Sapling Output circuit | **Unverified / blocked** | Output now has 7,827 local rows and the isolated NoteCommitment Pedersen matrix matches a source-derived transcription. The full local allocation/constraint order still differs and no independent full upstream matrix is available; parameter compatibility and Groth16 readiness are not claimed. |
| Groth16 proving parameters and proof generation | **Unsupported** | Not part of this phase; no parameters or prover were added. |
| Sapling spending | **Unsupported; remains gated** | Circuits, parameters, proofs, signatures, transaction assembly, and network-specific requirements are incomplete. |

The Pedersen gadget supports at most 1,128 message bits after its six
personalization bits (six 63-window generators); this is the pinned generator
capacity, not an assertion that all Sapling circuit inputs are implemented.
Note commitment and authentication-path gadgets pass their available
independent fixture outputs, but remain components rather than complete
circuits. Output witness relationships are now composed locally, but a full
independent Output witness and Bellman-compatible shape/hash verification
remain unavailable. Conditional zero-value anchor semantics and other Spend
requirements also remain unimplemented. Reproducible whole-circuit
comparisons against the pinned circuit are still required before circuit
compatibility can be claimed.

## References and provenance

- [Pinned upstream Sapling circuit implementation](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
- [Pinned upstream Spend and Output deterministic witness-generation tests](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
- [Pinned upstream Spend synthesis and deterministic Spend tests](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
- [Pinned Output witness and field declarations](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs#L32-L105)
- [Pinned Output value-commitment helper](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs#L108-L146)
- [Pinned Output synthesis implementation](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs#L431-L545)
- [Pinned Output count, circuit hash, and public-input tests](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs#L970-L1063)
- [Pinned Jubjub ECC gadgets](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/ecc.rs)
- [Pinned Sapling Pedersen hash](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pedersen_hash.rs)
- [Pinned Sapling circuit constants](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/constants.rs)
- [Pinned Sapling dependency manifest](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/Cargo.toml)
- [Bellman 0.15.0 BLAKE2s gadget source](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/blake2s.rs)
- [Bellman 0.15.0 TestConstraintSystem and circuit-hash implementation](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/test/mod.rs)
- [RFC 7693: BLAKE2](https://www.rfc-editor.org/rfc/rfc7693)
- [Independent BLAKE2 test vectors](https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json)
- [Pinned Sapling ZIP-32 IVK reference vectors](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/sapling_zip32.json)
- [Pinned upstream Jubjub circuit gadgets](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs)
- [Pinned upstream Jubjub point witness, small-order validation, and multiplication](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs#L86-L249)
- [Pinned Bellman 0.15.0 Jubjub scalar bit decomposition](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/boolean.rs#L262-L315)
- [Pinned Bellman 0.15.0 3-bit lookup gadget](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/lookup.rs)
- [Pinned upstream Pedersen circuit gadget](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/pedersen_hash.rs)
- [Pinned upstream Pedersen hash and personalization](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pedersen_hash.rs)
- [Pinned Pedersen generator definitions and six-generator capacity](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/constants.rs)
- [Pinned circuit generators and Montgomery constants](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/constants.rs)
- [Pinned upstream package features and dependencies](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/Cargo.toml)
- [Pinned upstream Bellman 0.15.0 multipacking gadget and capacity rule](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/multipack.rs)
- [Pinned independent Sapling nullifier reference vectors](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/sapling_key_components.json)
- [Pinned independent Sapling Merkle-tree reference implementation](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/merkle_tree.py)
- [Pinned independent Sapling Merkle-tree fixture](../tests/fixtures/sapling_merkle_tree_reference.json)
- [Partial Spend relation-reference manifest](../tests/fixtures/sapling_spend_partial_reference.json)
- [Pinned upstream Sapling value-commitment formula](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/value.rs)
- [Pinned independent Sapling note-encryption reference vectors](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/test-vectors/json/sapling_note_encryption.json)
- [Pinned independent Sapling note-encryption reference implementation](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/note_encryption.py)
- [Pinned independent ephemeral-key vector fixture](../tests/fixtures/sapling_ephemeral_key_reference.json)
- [Pinned note-encryption KDF and outgoing-key PRF](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/note_encryption.py#L17-L29)
- [Pinned note key agreement and ChaCha20-Poly1305 wrapper](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/note_encryption.py#L31-L52)
- [Pinned note plaintext serialization and external encryption flow](https://github.com/zcash/zcash-test-vectors/blob/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling/note_encryption.py#L55-L93)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf), Sapling protocol and circuit definitions.
- [Sapling Groth16 proof-generation readiness](sapling-groth16-proof-generation.md)

#### Phase 9.20.32: independent pure-Python seeded Spend reproduction

**Outcome: the pinned test's deterministic Spend witness has now been
reproduced through a separate pure-Python implementation.** The new test-only
[`sapling_spend_independent_reference.py`](../tests/sapling_spend_independent_reference.py)
does not import the ZyCoin Spend reference generator, verifier, R1CS gadgets,
or Sapling arithmetic modules. It uses affine twisted-Edwards addition and
double-and-add multiplication rather than ZyCoin's projective implementation.
The test compares its complete serialized witness field-by-field with the
existing non-circuit implementation under test; that implementation is not
used to calculate the independent result.

The reproduction is pinned to `zcash/sapling-crypto` 0.9.0,
`88a7946b4a3066787776e11f0a502654167e022d`, and the circuit test
`test_input_circuit_with_bls12_381` in `src/circuit.rs`. It uses that test's
seed `5862be3d763d318d17db37325406bce5`, `rand_xorshift` 0.5.0,
`rand_core` 0.10.1 byte/word order, and its exact sampling order. In
particular, the upstream expression
`vec![Some((Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); tree_depth]`
evaluates one copyable pair and repeats it 32 times; it does not sample 32
independent siblings. The ZyCoin reference generator was corrected to mirror
that behavior. The independent implementation generates one sibling scalar
and direction bit, repeats that pair, then derives the same 32-bit position
and root.

The primary source evidence is the pinned
[`circuit.rs` Spend test and witness loop](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs#L635-L745),
the pinned [`jubjub` 0.11.1 subgroup-point sampler](https://docs.rs/crate/jubjub/0.11.1/source/src/lib.rs#L1253-L1308),
and the pinned
[`zcash-test-vectors` Sapling primitive implementations](https://github.com/zcash/zcash-test-vectors/tree/78321beacb0e0477e33cd002b56585a107c2708c/zcash_test_vectors/sapling).
Regression fixtures identify their exact source revisions and source files;
they validate the relevant primitive calculations on their own cases, not the
sampled literals of the Spend test.

The field-by-field evidence classification is:

| Witness fields / relation | Phase 9.20.32 evidence | Boundary |
|---|---|---|
| `value`, `rcv` | **Checked only through upstream source semantics** | Reproduced from `next_u64` and 64-byte Jubjub-scalar sampling; the exact seeded literals are not printed by upstream. |
| `ak` | **Checked only through upstream source semantics** | Reproduced from `SubgroupPoint::random`: 64-byte base-field sample, sign word, point decode, cofactor clearing, and identity rejection. Curve and arithmetic implementations are exercised by the published Sapling vectors below. |
| `nsk`, `rcm` | **Checked only through upstream source semantics** | Reproduced as canonical Jubjub scalar samples in the exact source order; the exact seeded literals are not printed by upstream. |
| `nk`, `ivk`, diversifier, `g_d`, `pk_d` | **Independently recomputed from pinned protocol semantics** | The independent affine path derives these from the sampled inputs. The official key-component fixture independently exercises `nk`, diversifier, and `pk_d` on its own case. |
| Note contents and `cm` | **Independently recomputed; relation vector matched** | The independent Pedersen/note path is compared with the official key-component `cmu` case. That fixture is a separate note, not a literal expected `cmu` for this seeded sample. |
| `cv` | **Independently recomputed; relation vectors matched** | The affine value-commitment implementation matches all ten published upstream `cv.u/v` pairs. The seeded case's own coordinates are not directly printed by upstream. |
| `ar`, `rk` | **Independently recomputed; relation vector matched** | `ar` is reproduced as a source-defined scalar sample, and seeded `rk` is calculated from sampled `ak` and `ar`; a separate published RedJubjub vector checks both encoded coordinates for the relation. |
| Authentication path, position, anchor | **Independently recomputed; Merkle vector matched** | The repeated sibling/direction pair from the pinned RNG stream is hashed for all 32 levels. A separate official path/root fixture validates the Merkle algorithm and direction convention. |
| `nk`, nullifier, and two packed chunks | **Independently recomputed; relation vector matched** | The independent note/nullifier fixture checks the hash and encoding on its published case. The seeded digest is split little-endian at bit 254. |
| Seven application public inputs | **Independently recomputed; order checked against source** | The reproduced tuple is `rk.u`, `rk.v`, `cv.u`, `cv.v`, anchor, nullifier chunk 0, nullifier chunk 1. Bellman's implicit `ONE` remains separate. Upstream does not publish literal values for this seed. |

`tests/test_sapling_spend_reference.py` now checks all ten external value
commitments using the independent affine implementation; checks note
commitment/nullifier, Merkle path/root, and randomized-key formulas against
their pinned, separate fixtures; and compares every field of the deterministic
seeded witness against the implementation under test. The vector fixtures are
not joined into a synthetic complete witness. The seeded output is generated
by the test and deliberately is not labelled or checked in as an upstream
published fixture: its sampled literals are reproduced from source semantics,
not directly published by upstream.

This closes Phase 9.20.31's **seeded-reference reproduction** evidence gap:
the pinned RNG state is available and the independent source-semantic
implementation reproduces the complete witness, including all seven
application inputs. It does not establish Bellman constraint equivalence,
or a circuit hash match. Phase 9.20.33 uses this reference input in a complete
pure-Python Spend relation assembly.

#### Phase 9.20.33: complete Spend R1CS assembly

Added [`sapling_spend_circuit.py`](../src/sapling_spend_circuit.py), which
composes the existing constrained Sapling gadgets into one seven-application-
input Spend assignment. The new
[`test_sapling_spend_circuit.py`](../tests/test_sapling_spend_circuit.py)
converts the independent Phase 9.20.32 affine witness into the circuit's point
type and verifies the assembled assignment. The existing deterministic
generator is compared against the independent witness before use; neither
reference implementation is used as a substitute for any circuit constraint.

The assembly shares the same variables across dependent relations:

| Shared witness | Reused by |
|---|---|
| 64 value bits and one reconstructed value variable | Value commitment, note commitment, and conditional anchor |
| `ak` point and its 256-bit representation | Randomized key and IVK hash |
| `nsk` bits, derived `nk` point, and `nk` representation | IVK hash and nullifier PRF |
| IVK BLAKE2s output bits | Variable-base `pk_d` multiplication |
| `g_d`, `pk_d`, and their representations | Note commitment |
| Note commitment point and `cm.u` | Note hash output, first Merkle leaf, and nullifier `rho` |
| 32 path direction bits | Path selection, position encoding, and nullifier-position multiplication |
| Nullifier PRF output bits | Both ordered public multipacking inputs |

The circuit's public inputs are allocated in this exact order:
`rk.u`, `rk.v`, `cv.u`, `cv.v`, anchor, nullifier chunk 0, nullifier chunk 1.
R1CS variable zero is the implicit `ONE` and is not included in that tuple.
`R1CS` requires all public variables to be allocated before any private
variables, unlike Bellman's interleaved allocation. Private variables then
follow the upstream relation order: `ak` and `ar`/`rk`; `nsk`/`nk` and the
`ak`/`nk` representations plus IVK hash; `g_d`/`pk_d`; shared value and `rcv`
bits, `cv`, and `rcm`/note commitment; path position/siblings/selection/hash
levels and conditional anchor; finally `rho`, its representation, nullifier
hash bits, and packed chunks. The diversifier bytes are host-validated into
`g_d`; as in the pinned circuit, deriving `g_d` from those bytes is not an
R1CS relation.

Upstream `field_into_boolean_vec_le` decompositions do not impose an
additional less-than-`jubjub::Fr` comparison. The assembler therefore uses
252-bit `ar`, `nsk`, `rcv`, and `rcm` decompositions without that extra
comparator; the supplied witness values themselves are canonical scalars.
The existing Jubjub point-representation helper does enforce canonical
coordinates, and several reusable helpers allocate explicit fixed-base
generator points or extra reconstruction variables. These are sound
constraints for the accepted witness but add rows relative to the upstream
shape.

Measured deterministic assembly:

| Relation group | Constraints |
|---|---:|
| `ak` and randomized authorization key | 3,802 |
| `nsk`, `nk`, point representations, and IVK | 25,628 |
| `g_d` and `pk_d` | 4,815 |
| Value commitment and note commitment | 6,007 |
| Merkle path, position, and conditional anchor | 87,650 |
| `rho`, nullifier PRF, and multipacking | 23,728 |
| **Total ZyCoin R1CS** | **151,630** |

The deterministic independently reproduced witness satisfies all 151,630
constraints and emits exactly seven application public inputs. Regression
tests change each public input independently and tamper with `ak`, `ar`, `nsk`,
`nk`, IVK, `g_d`, `pk_d` representation, value, `rcv`, `rcm`, note commitment,
path sibling/direction, `rho`, its representation, and nullifier bits; every
mutation is rejected. The pinned upstream Spend test reports 98,777
constraints. ZyCoin's count is 52,853 rows higher and its variables,
allocations, and constraint ordering differ, so the count is evidence of this
local composition only—not Bellman shape or circuit-hash equivalence.

| Spend relation | Phase 9.20.33 assembly status | Evidence boundary |
|---|---|---|
| Seven public inputs and implicit `ONE` | **Verified** | Exact order, seven-input count, separate variable zero, and public-input tampering regressions. |
| `ak` curve/non-small-order and `rk = ak + [ar]G` | **Verified** | Constrained in assembly; independent published `(ak, ar, rk)` component vector remains separate supporting evidence. |
| `nsk -> nk -> ivk` | **Verified** | Fixed-base `nk`, point representations, and constrained `Zcashivk` hash compose through shared variables. |
| `g_d`, `pk_d = [ivk]g_d`, and note commitment | **Verified** | `g_d` curve/non-small-order, variable-base multiplication, note value and recipient representations, Pedersen hash, and `rcm` randomization are constrained. Diversifier-to-`g_d` remains host validation as in upstream. |
| Value commitment | **Verified** | The same value bits are reused by note commitment and conditional anchor; `rcv` and `cv` are constrained. |
| Merkle path, position binding, and conditional anchor | **Verified** | 32 direction bits select each path order, feed the shared position multiplication, and bind the root conditionally to the public anchor. |
| `rho = cm + [position]J`, nullifier PRF, and multipacking | **Verified** | Shared note point and path bits feed constrained `rho`, `Zcash_nf`, and the 254+2-bit public chunks. |
| Complete deterministic witness satisfaction | **Verified** | The independent Phase 9.20.32 witness satisfies the whole assembled assignment. This is semantic relation evidence for this witness, not a proof of all assignments. |
| Bellman constraint shape, hash, and Groth16 compatibility | **Not established** | Local and upstream counts/order differ; no Bellman-compatible matrix, circuit hash match, proving parameters, or proving support is provided. |

No Output circuit code changed. No Groth16 proving, authorization,
transaction-spending API, or Sapling spending capability was implemented or
enabled.

## Phase 9.20.34 — Spend constraint equivalence audit

This section supersedes the Phase 9.20.33 Spend constraint totals above. The
assembly now has **130,403** constraints, **129,714** variables, and seven
application public inputs. The pinned upstream Spend circuit has **98,777**
constraints. The remaining difference is **31,626**; the relation-level
accounting below explains all of it. Counts are not evidence of Bellman shape
or circuit-hash equivalence.

### Evidence and accounting method

The pinned Sapling source is
[`src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs),
[`src/circuit/ecc.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs),
and
[`src/circuit/pedersen_hash.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/pedersen_hash.rs)
at commit `88a7946b4a3066787776e11f0a502654167e022d`. The lockfile pins
Bellman 0.15.0 (crate checksum
`973b16549796a1274a63e00159a03250e66e8263e2ac6344b1c9fdfe9b7a8325`).
The upstream whole-circuit count is directly asserted by its Spend test.
Upstream per-relation counts below are **source-derived**, not emitted by an
upstream build; the source exposes the Pedersen count formula, while the other
figures follow the pinned gadget equations and allocation order. ZyCoin counts
were measured from the current deterministic assembly and are regression
asserted.

| Relation group | Pinned upstream | ZyCoin now | Difference |
|---|---:|---:|---:|
| `ak` and randomized authorization key | 1,030 | 1,031 | +1 |
| `nsk`, `nk`, point representations, and IVK | 23,560 | 25,116 | +1,556 |
| `g_d` and `pk_d` | 4,048 | 4,564 | +516 |
| Value commitment and note commitment | 4,031 | 5,498 | +1,467 |
| Merkle path, position, and conditional anchor | 44,226 | 71,266 | +27,040 |
| `rho`, nullifier PRF, and multipacking | 21,882 | 22,928 | +1,046 |
| **Total** | **98,777** | **130,403** | **+31,626** |

These are semantic groupings, not a row-by-row matrix correspondence. The
current local rows decompose as follows:

- **Point arithmetic and fixed-base multiplication:** both implementations
  use three-bit fixed-base windows (three lookup rows per full window), six
  rows per Edwards addition, and five per doubling. The local point-add,
  point-double, curve-membership, and small-order relations match those
  source formulas. `g_d` and `pk_d` are represented once and reused.
- **Strict point representations:** each of the five points `ak`, `nk`,
  `g_d`, `pk_d`, and `rho` contributes two 255-bit coordinates. Bellman's
  `to_bits_le_strict` source allocates 255 bits, uses 132 prefix-AND rows for
  the 133 one-bits of the modulus-minus-one, and adds one unpacking row:
  **388 per coordinate**. ZyCoin's generic comparator uses 255 Boolean rows,
  one reconstruction, 389 comparator multiplications, and one final
  comparison row: **646 per coordinate**. The stricter local implementation
  has the same canonical coordinate semantics but costs 258 extra rows each,
  or **2,580** across ten coordinates. These are differently structured
  checks, not duplicate checks; they remain in place.
- **Pedersen hashes:** the pinned source's `ph_num_constraints` gives 982 rows
  for the 576-bit note-content message and 867 per 510-bit Merkle message.
  ZyCoin measures 1,932 and 1,712 respectively. The local signed Edwards
  lookup and Edwards additions within each generator segment cost more than
  upstream's two-row lookup, three-row Montgomery additions, per-segment
  conversion, and Edwards segment combination. This contributes
  **950** extra note-hash rows and **845 × 32 = 27,040** extra Merkle rows,
  totaling **27,990**.
- **BLAKE2s:** Bellman's unit test reports 21,518 constraints for 512 allocated
  input bits. In Spend, those inputs are already Boolean representations, so
  subtracting their 512 allocation rows gives 21,006 per hash. ZyCoin's
  measured internal counts are 21,530 for IVK and 21,536 for the nullifier
  hash, for **524** and **530** more rows. Bellman uses `UInt32`/`MultiEq` and
  Boolean complement variants; ZyCoin materializes output/carry bits and
  complement variables. The six-row difference between the two local hashes
  comes from their different personalization-dependent constant complements.
  This accounts for **1,054** rows.
- **Value and scalar bindings:** ZyCoin retains one row tying its explicit
  `ar` variable to its bit decomposition and one tying its explicit note-value
  variable to the shared value bits. Upstream consumes `ar` bits directly and
  carries the note value as a linear-combination `Num`. These two local
  bindings account for **2** rows. The local 32-bit Merkle-position
  reconstruction adds one row, while using the public anchor directly saves
  upstream's separate anchor inputization row; those effects cancel.

Thus the remaining difference is exactly `2,580 + 27,990 + 1,054 + 2 =
31,626`. Variable allocation order (all local public inputs first versus
Bellman's interleaving) changes variable layout but adds no rows. The implicit
`ONE` remains separate from the seven application inputs.

### Safe reductions made

The reductions below preserve the existing relation semantics; they are not
deductions from the target total.

| Change | Rows removed |
|---|---:|
| Use the upstream fixed-base strategy for `ar` instead of generic variable-base multiplication and an allocated generator | 2,771 |
| Reuse already Boolean-constrained Merkle child bits at Pedersen boundaries (`32 × 510`) | 16,320 |
| Reuse the strict point-representation bits at both BLAKE2s input boundaries (`2 × 512`) | 1,024 |
| Reuse IVK output bits in `[ivk]g_d` multiplication | 251 |
| Reuse the path's Boolean position bits in `[position]J` | 32 |
| Avoid duplicate `pk_d` representation and `rcm` bit checks in Spend | 508 |
| Reuse constrained nullifier output bits when packing public chunks | 256 |
| Replace the local four-row-per-level conditional reversal with the exact two upstream equations | 64 |
| Remove a duplicate value-to-bits equality | 1 |
| **Total reduction from the Phase 9.20.33 assembly** | **21,227** |

Each skip flag is used only where the same variables have already been
constrained in the assembled system; standalone gadget defaults continue to
constrain their inputs. Regression coverage confirms witness satisfaction,
rejection of invalid mutations, and shared path-position wiring. No
constraint was removed solely to approach 98,777.

### Current Spend coverage matrix

| Relation / property | Status | Evidence and remaining boundary |
|---|---|---|
| Seven public inputs and separate implicit `ONE` | **Verified** | Exact order and each public slot is tamper-tested. |
| `ak`, `ar`, and `rk` | **Verified** | Fixed-base multiplication, key addition, scalar boundaries, bit-width rejection, and independent component vector coverage. |
| `nsk → nk → ivk` | **Verified** | Shared fixed-base key, strict point representations, constrained IVK hash, and public/witness mutation tests. |
| `g_d`, `pk_d`, and note commitment | **Verified** | Shared `g_d`/`pk_d` representations feed the note hash and commitment randomization. Diversifier-to-`g_d` remains host-validated, as upstream. |
| Value commitment | **Verified** | `value`, `rcv`, and both public coordinates are linked; value bits are reused by the note and anchor. |
| Merkle path, direction/position, and conditional anchor | **Verified** | Thirty-two direction bits drive both parent selection and position multiplication; sibling, direction, and anchor behavior are covered. |
| `rho`, nullifier PRF, and multipacking | **Verified** | Shared note point and path bits feed the `rho` relation, BLAKE2s, and both ordered public chunks. |
| Bellman matrix shape, circuit hash, or Groth16 compatibility | **Not established** | Relation semantics and a satisfying deterministic witness do not establish matrix, variable-order, or circuit-hash equivalence. |

The Output circuit implementation and its default shared-gadget constraint
behavior remain unchanged. Groth16 proving and Sapling spending remain
disabled.

## Phase 9.20.35 — Spend Bellman matrix equivalence

### Determination

The matrices are **not equivalent**. The ZyCoin deterministic Spend assembly
has 130,403 ordered rows; the pinned Bellman Spend test asserts 98,777. Unequal
row counts alone rule out exact matrix equality, regardless of witness
satisfaction, variable renumbering, row permutations, or coefficient
normalization. The mismatch is not repaired by changing the circuit.

The pinned source is `zcash/sapling-crypto` commit
`88a7946b4a3066787776e11f0a502654167e022d`, using Bellman 0.15.0. Its
`test_input_circuit_with_bls12_381` test asserts both the 98,777 row count and
Bellman's `TestConstraintSystem` digest
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`.
Neither the test nor its checked-in fixtures export the ordered upstream A,
B, and C matrices. The digest is generated by Bellman's own test-system hash
algorithm; it is not the SHA-256 digest of a portable matrix serialization,
so comparing it to ZyCoin's serialization digest would be invalid.

### Reproducible ZyCoin matrix snapshot

`R1CS.serialize()` already records every local ordered A/B/C linear
combination, the BLS12-381 scalar modulus, column indices, variable kinds,
local names, labels, and public-input count without witness values. It is
sufficient to reconstruct ZyCoin's local matrix, but its labels and names are
ZyCoin metadata and it does not encode Bellman's separate `Input` and `Aux`
index types as such.

Phase 9.20.35 adds `R1CS.serialize_matrix()` and
`R1CS.matrix_fingerprint()`. The former exports only the field modulus,
column count, implicit-ONE column, public/auxiliary boundaries, ordered
variable-kind columns, and the ordered A/B/C terms; coefficients are
canonical decimal representatives modulo the BLS12-381 scalar modulus. It
excludes witness values, names, and labels. Phase 9.20.36 specifies the exact
canonicalization and hash domain below.

Using the Phase 9.20.32 deterministic case 0 witness and its seven public
inputs, the current Spend assembly reproduces:

| Property | ZyCoin result | Upstream evidence |
|---|---:|---:|
| Application public inputs | 7, in `rk.u, rk.v, cv.u, cv.v, anchor, nf[0], nf[1]` order | 7; same source order, plus implicit `ONE` |
| Implicit `ONE` | Column 0 | Bellman `TestConstraintSystem` has implicit input zero |
| Variables / columns | 129,714 | No upstream matrix export available |
| A/B/C rows | 130,403 | 98,777 asserted by pinned test |
| Field modulus | BLS12-381 scalar modulus | BLS12-381 scalar field |
| Versioned local matrix fingerprint | `b34b388723a41e4602e8779e9df04b114a74b8f4e2e6184f865e0f3285705a29` | Not comparable to Bellman's test hash |
| Local matrix snapshot size | 28,667,321 bytes | Not published |

The snapshot fingerprint is stable for the pinned deterministic witness and
current assembly. It fingerprints the matrix, not the witness; changing only
witness values does not change it. Regression tests also prove the
fingerprint changes when an ordered row or a coefficient changes, and assert
the Spend-specific public slots and implicit-ONE column. A same-count witness
test is not used as a proxy for upstream matrix equality.

### Mismatch classification and limits

| Dimension | Finding | Classification / evidence |
|---|---|---|
| Public application inputs | Same seven values and order | **No known mismatch.** Bellman's implicit `ONE` is separate in both descriptions. |
| Field and coefficient domain | Both use the BLS12-381 scalar field; ZyCoin reduces coefficients to canonical field representatives | **No known modulus mismatch.** Exact coefficient-by-coefficient comparison is unavailable without upstream rows. |
| Auxiliary allocation | ZyCoin allocates all seven public inputs first and then its private variables. Bellman input and auxiliary indices use separate namespaces and are allocated as synthesis proceeds | **Allocation / serialization difference.** A type-aware index normalization can map columns, but the upstream auxiliary allocation trace is not exported for machine comparison. |
| Constraint order | ZyCoin emits its local relation groups in assembly order. Bellman emits rows through its pinned gadgets in upstream synthesis order | **Ordering difference not row-enumerated.** The unequal row counts prohibit a one-to-one complete ordered-row match. |
| A/B/C coefficients | ZyCoin's exact terms and coefficients are present in its matrix export | **Uncompared against upstream.** The pinned count/hash do not reveal upstream matrix terms. |
| Missing or additional relation rows | Phase 9.20.34 source-derived accounting explains the +31,626 local rows: strict point decomposition +2,580; Pedersen structure +27,990; BLAKE2s structure +1,054; two local bindings +2 | **Additional local rows / structurally different relations**, not an identified missing Spend relation. The detailed row-to-row correspondence remains unverified. |
| Serialization | Local canonical export contains matrix terms without witness data; Bellman's test digest is a different representation | **Serialization difference.** The local export can represent an R1CS matrix but cannot reconstruct a Bellman matrix that was not published. |

The exact per-row mismatch set is therefore **not available** from the pinned
test artifacts. To produce it, a future evidence phase must acquire either
the upstream ordered A/B/C rows with typed `Input`/`Aux` columns for the same
seeded assignment, or implement an independently reviewed pure-Python
translation of the exact pinned Bellman/Sapling synthesis and gadgets. The
current phase does not infer unknown rows from counts or from Bellman's
one-way test hash.

### Verification boundary

Tests establish deterministic local matrix serialization, matrix-sensitive
mismatch detection, the seven public-input ordering, the separate implicit
`ONE`, and the local fingerprint for the seeded witness. The definitive
equivalence result is **non-equivalent by constraint-row count**. Exact
upstream auxiliary-column, row-order, and A/B/C coefficient diffs remain
unclassified because upstream matrix rows are unavailable. No circuit
semantics were changed; Output behavior, Groth16 proving, and Sapling
spending remain unchanged and disabled.

## Phase 9.20.36 — Matrix serialization and fingerprint audit

### Versioned format

`R1CS.serialize_matrix()` emits deterministic UTF-8/ASCII-safe compact JSON
with sorted object keys and these fields:

| Field | Meaning |
|---|---|
| `format` | `zycoin-r1cs-matrix-v1`; format changes require a new version. |
| `field_modulus` | Decimal BLS12-381 scalar modulus. |
| `column_count` | Total number of columns, including implicit `ONE`. |
| `one_column` | Always column 0. |
| `public_input_count` | Number of application inputs; their columns are `1..n`. |
| `auxiliary_variable_count` | Number of private columns after the public columns. |
| `variable_kinds` | Column-kind array indexed by column number (`one`, `public`, `private`). |
| `constraints` | Ordered rows, each containing exactly the A, B, and C term arrays in that order. |

Each term is `[column_index, coefficient]`; the coefficient is a decimal
string so JSON consumers cannot lose integer precision. For every linear
combination, duplicate column indices are summed modulo the field modulus,
zero residues are omitted, and the remaining terms are sorted by ascending
column index. Thus the order in which terms are inserted does not affect the
matrix bytes. Constraint rows are deliberately not sorted: their insertion
order is part of the serialized matrix and fingerprint. Column allocation
order is also significant; there is no implicit alpha-renaming or permutation
of public or auxiliary columns.

The fingerprint algorithm is explicitly versioned:

```text
SHA-256(
  UTF8("zycoin-r1cs-matrix-fingerprint-v1") ||
  0x00 ||
  serialize_matrix()
)
```

Changing the JSON schema/canonicalization requires a new
`zycoin-r1cs-matrix-vN`; changing the fingerprint preimage requires a new
`zycoin-r1cs-matrix-fingerprint-vN` domain. This yields the deterministic
Spend fingerprint
`b34b388723a41e4602e8779e9df04b114a74b8f4e2e6184f865e0f3285705a29`
and a 28,667,321-byte matrix snapshot for the Phase 9.20.32 case 0 witness.

### Audit and regression coverage

The serializer is witness-independent and omits variable names and constraint
labels, which could contain caller-supplied secrets. Tests compare matrices
and fingerprints built with different witness values and names. Edge coverage
includes the zero-constraint ONE-only system, zero terms, duplicate terms,
negative coefficients, coefficients equal to and above the modulus,
canonical field-boundary residues, and rejection of negative or out-of-range
column indices. Tests also verify byte/fingerprint invariance under term
insertion reordering, and sensitivity to changes in row order, each A/B/C
side, coefficient, column order/count, and public-versus-auxiliary boundary.
Matrix serialization validates the column structure and every referenced
column before producing bytes.

The seeded Spend test asserts column 0 is `ONE`, the following seven columns
are the application public inputs in the documented order, and all remaining
columns are private auxiliaries. It pins the format version, row count,
column count, and deterministic fingerprint. The fingerprint is a convenient
change detector, **not proof of circuit correctness, witness satisfaction, or
Bellman equivalence**. The previously established non-equivalence by row
count remains unchanged; no Spend or Output circuit semantics changed.

## Phase 9.20.37 — Spend constraint soundness audit

### Verdict and method

No confirmed missing or disconnected Spend relation was found in the
deterministic assembled case. All seven public inputs have an explicit
constrained use, all 129,713 non-`ONE` columns occur in at least one R1CS row,
and perturbing any one column by `+1` or `-1` modulo the BLS12-381 scalar
field breaks at least one incident row for this assignment. No exact duplicate
A/B/C row triples were present. These checks audit connectivity and local
mutation sensitivity; they do not prove global circuit soundness or
Bellman/Groth16 compatibility.

The audit followed `constrain_sapling_spend` through `_prepare_witness`,
every called gadget and `R1CS.enforce`/`range_check`/`is_satisfied`. Host
preparation checks were distinguished from equations in the exported R1CS.
No constraint was removed or weakened.

### Public-input dependency map

| Public input | Constrained use |
|---|---|
| 1. `rk.u` | `ak + [ar]G` point addition result is equated to this public coordinate. |
| 2. `rk.v` | Same randomized authorization-key relation, `v` coordinate. |
| 3. `cv.u` | Value commitment point `[value]G_v + [rcv]G_r` is equated to this public coordinate. |
| 4. `cv.v` | Same value commitment relation, `v` coordinate. |
| 5. `anchor` | Appears in `(computed_root - anchor) × value = 0`; it is enforced equal to the root for nonzero `value`, intentionally unconstrained by this equation when value is zero. |
| 6. `nf[0]` | Equated to the little-endian packing of constrained nullifier digest bits 0–253. |
| 7. `nf[1]` | Equated to the little-endian packing of constrained digest bits 254–255. |

Variable zero is the constant `ONE`, not an application input. Tests assert
the public column order and that each expected relation label contains its
corresponding public column; they also mutate every public slot separately.

### Private-variable dependency map

| Private witness family | Defining constraints | Downstream use |
|---|---|---|
| `ak.u/v`, `ar`, 252 `ar` bits | Jubjub curve equation; three doublings and nonzero-`u` inverse; scalar-bit Boolean/range/reconstruction; fixed-base multiplication and point addition | `rk.u/v` public outputs and `ak` representation in IVK. |
| 252 `nsk` bits and `nk.u/v` trace | Boolean scalar bits; fixed-base proof-generation multiplication | Strict `nk` representation, IVK, and nullifier PRF. |
| `ak`/`nk` representation bits and IVK BLAKE2s state | Strict coordinate range checks, bit reconstruction, BLAKE2s Boolean/XOR/addition equations | 251 IVK bits drive `[ivk]g_d`; shared `nk` repr enters nullifier PRF. |
| `g_d.u/v` and `pk_d` multiplication trace | Curve and non-small-order relation for `g_d`; per-bit selection and affine addition for multiplication; strict `pk_d` representation | Note commitment preimage. |
| 64 value bits and `value` | Boolean/range and reconstruction through fixed-base value multiplication; `value` is tied back to those bits by note commitment | Value commitment opening, note contents, and conditional anchor. |
| 252 `rcv` bits and value-commitment points | Boolean bits, fixed-base multiplication and point addition | Bound to public `cv.u/v`. |
| 252 `rcm` bits, note Pedersen and randomization traces | Explicit Boolean constraints; message bits feed Pedersen hash; fixed-base multiplication; point addition | Note commitment `u` is the Merkle leaf; full point plus path position feeds `rho`. |
| Path position and 32 bits | 32-bit Boolean decomposition and reconstruction | Direction selection at each level and nullifier-position multiplication. |
| 32 siblings, selected left/right nodes, Pedersen intermediates | 255-bit decompositions; two direction-controlled selection equations per level; Pedersen constraints per level | Root is the conditional-anchor input. |
| `rho.u/v`, representation bits, nullifier digest bits and BLAKE2s state | `rho = cm + [position]J`; strict coordinate representation; nullifier-personalized BLAKE2s | Both public nullifier chunks via constrained 254+2-bit multipacking. |

The witness type also carries `diversifier`, path direction booleans, and
32-byte `nullifier` metadata. They are not separate R1CS variables:
`_prepare_witness` validates the diversifier-to-`g_d` derivation and checks
path directions against the position; the circuit then constrains `g_d` and
the position-derived direction bits. The supplied nullifier bytes are checked
against the constrained digest during assembly, while the digest—not those
bytes—is what is packed into public inputs. These are explicit host admission
checks, not proof equations.

### Encoding and relation checks

- **Field and coordinates:** R1CS assignments are canonicalized modulo the
  BLS12-381 scalar modulus. Jubjub coordinate representations used by IVK and
  nullifier hashing have 255 Boolean bits, reconstruction, and a strict
  `< field_modulus` bound.
- **Jubjub scalars:** `ar`, `nsk`, `rcv`, and `rcm` use 252 little-endian
  Boolean bits. Host witness admission requires canonical values below the
  Jubjub scalar modulus. The circuit bits are tied to the scalar where a
  scalar variable exists (`ar`) and used directly for the other scalar
  relations. As documented in Phase 9.20.26, the pinned Bellman bit gadget
  does not add a scalar-modulus comparator; a detached R1CS assignment can
  encode a 252-bit integer at or above the Jubjub modulus. Such a bit string
  is not admitted by the assembly API, which accepts only canonical host
  scalars. This is the pinned host-type boundary, not a defect in the circuit
  relation or a claim that the R1CS proves canonical scalar encoding.
- **Value and position:** the value is represented by 64 Boolean bits tied to
  its field variable. Position is a 32-bit Boolean decomposition tied to its
  field variable. The 254+2 digest chunks are injective in the field and
  exactly tied to the seven public columns.
- **Points:** `ak` and `g_d` receive curve and non-small-order constraints;
  `nk`, `pk_d`, note commitment, value commitment, and `rho` are derived
  through constrained fixed-base or point-addition relations. Strict point
  representations are used before BLAKE2s hashing. The circuit does not
  separately constrain `ak` to the prime subgroup: witness construction
  requires it, while the pinned circuit's in-circuit rule is on-curve and
  non-small-order.
- **Merkle path and anchor:** each position bit controls exactly one ordering
  of `(current, sibling)`; each selected 255-bit node is the corresponding
  Pedersen input. All 32 position bits also feed `[position]J`. The final
  root is conditionally compared to the public anchor using the same
  64-bit-constrained value.
- **Note, nullifier, and commitments:** the one constrained value bit vector
  is shared by value commitment, note contents, and anchor. The note
  commitment feeds the path leaf and `rho`; `nk` representation and `rho`
  representation feed the personalized nullifier hash; its output bits feed
  both public chunks.
- **Randomized key:** `ar` bits feed the spending-generator fixed-base
  multiplication; the result is added to constrained `ak`; both resulting
  coordinates are bound to public `rk`.

### Findings and disposition

| ID | Severity | Affected relation | Finding and evidence | Remediation / status |
|---|---|---|---|---|
| SND-01 | **Informational boundary** | `ak` subgroup membership | Host witness creation requires a prime-subgroup `ak`; the R1CS enforces curve membership and non-small-order, not `[r]ak = 0`. The pinned Spend circuit uses the same in-circuit check and obtains the validating key through its host type. | Admission is enforced before allocation; consuming a detached matrix does not preserve this host invariant. |
| SND-02 | **Informational boundary** | Diversifier and `g_d` | The byte diversifier is not an R1CS variable. `_prepare_witness` checks `g_d = group_hash("Zcash_gd", d)`; the R1CS constrains `g_d` on-curve/non-small-order and uses it for `pk_d` and note commitment, but does not hash `d` in-circuit. This matches pinned Spend synthesis. | Admission is enforced before allocation; the matrix alone does not prove the diversifier relation. |
| SND-03 | **Informational boundary** | Jubjub scalar encodings | Host admission rejects noncanonical `ar`, `nsk`, `rcv`, and `rcm`; in-circuit 252-bit Boolean decompositions do not impose `< jubjub::Fr`, matching the pinned Bellman gadget. | Admission is enforced before allocation; the matrix alone does not prove canonical scalar encoding. |
| SND-04 | **No defect found** | All other relations and variables | All seven public inputs have labeled relation uses; all 129,713 non-`ONE` columns are used; every column's `±1` mutation breaks an incident row in the deterministic assignment; no duplicate A/B/C row triples were found. Existing field, point, Boolean, path, anchor, commitment, nullifier, and `rk` mutations pass. | No code defect confirmed. The exhaustive connectivity/mutation check is retained as a regression. |

No confirmed soundness defect required a constraint change. The remaining
risks are explicit host-input preconditions inherited from the pinned circuit
semantics, not claims that the R1CS proves those omitted relations. This audit
does not establish soundness for every satisfying assignment, Bellman matrix
equivalence, or Groth16 readiness. Sapling spending remains gated.

## Phase 9.20.38 — Spend host-precondition and circuit-boundary audit

### Verdict

All three admission conditions are enforced before `constrain_sapling_spend`
allocates any R1CS variables. Their boundary matches the pinned Sapling API:
the host supplies typed keys, field elements, and a checked payment address;
the circuit is not responsible for revalidating all of those constructors'
invariants. No missing admission check or circuit-semantic defect was found.
The tests also confirm that rejection leaves a fresh R1CS untouched.

### Source-backed enforcement matrix

| Precondition | Pinned upstream enforcement | ZyCoin enforcement | Circuit boundary and result |
|---|---|---|---|
| Prime-subgroup, non-identity `ak` | `SpendValidatingKey` wraps a Jubjub subgroup point; its byte parser decodes a subgroup point and rejects identity. `ProofGenerationKey` stores this type. `Spend::synthesize` separately applies the on-curve/non-small-order circuit check. | `_prepare_witness` invokes the randomized-key witness constructor before other witness relations or allocations. That constructor rejects off-curve, small-order, and non-subgroup keys. | Subgroup membership is a host/type invariant in upstream and ZyCoin; the R1CS proves only its pinned curve and non-small-order conditions. Off-curve, identity, and on-curve non-subgroup cases are rejected at admission. |
| Valid diversifier and exact `g_d` derivation | `Diversifier::g_d` applies the Sapling diversify hash. `PaymentAddress` construction checks the diversifier and its `g_d`; `Spend::synthesize` obtains `g_d` from the checked address, then witnesses the point and checks it in-circuit. The hash from `d` to `g_d` is not an R1CS relation. | `_prepare_witness` requires an 11-byte diversifier and checks `group_hash(b"Zcash_gd", d)` equals the supplied `diversifier_base` before allocation. | Host admission enforces the address invariant. The R1CS constrains the `g_d` point and its dependents, not the diversifier bytes/hash. An invalid `d` and a valid but mismatched `(d, g_d)` are rejected. |
| Canonical `jubjub::Fr` scalars (`rcv`, `nsk`, `rcm`, `ar`) | Upstream fields are typed as `jubjub::Fr`, whose constructor/parser admits canonical field elements. The Spend circuit decomposes the scalars into 252 bits without a `< r` comparator; upstream comments explicitly note that `nsk` bits need not be constrained to the field range for its circuit use. | `_prepare_witness` accepts exact Python integers only in `[0, SCALAR_MODULUS)`; booleans, negatives, and values `>= r` are rejected before allocation. | Canonicality is a typed host-input invariant, not a proof established by the detached matrix. The 252-bit relation intentionally remains unchanged; no extra range constraint was added. |

Pinned source references:

- [`Spend::synthesize`, `src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs) — circuit point checks, scalar bit decompositions, and checked-address `g_d` use.
- [`SpendValidatingKey`, `ProofGenerationKey`, and `Diversifier`, `src/keys.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/keys.rs) — subgroup and address/key host-type boundaries.
- [`PaymentAddress`, `src/address.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/address.rs) — checked diversifier/address construction.
- [Sapling diversify hash definition](https://zips.z.cash/protocol/protocol.pdf#concretegrouphashjubjub) — protocol group-hash semantics.
- [`jubjub` 0.11.1 `Fr` implementation](https://docs.rs/jubjub/0.11.1/jubjub/struct.Fr.html) — scalar type used by the pinned Sapling dependency.

Regression coverage retains the existing independent valid randomized-key
vector and adds assembly-API rejection cases for an off-curve key, identity,
an on-curve non-small-order point outside the subgroup, an invalid
diversifier, a valid diversifier paired with the wrong `g_d`, and each scalar
field set to `r`, `-1`, or `True`. Every invalid case is checked to fail
before variable or constraint allocation. The adversarial point/diversifier
values are locally specified negative cases, not published protocol vectors;
the valid vector remains the independent expected-value evidence.

This closes the API admission gap for these three preconditions only. A
serialized matrix used outside this API does not carry the host-side checks.
No Bellman matrix equivalence, Groth16 readiness, or Sapling spending support
is claimed; spending remains gated.

## Phase 9.20.39 — Output host-precondition and circuit-boundary audit

### Verdict and method

The five Output application inputs are bound to their intended relations, and
the complete local assignment is satisfied for the pinned independent Output
vector. The audit traced `constrain_sapling_output` through the value,
ephemeral-key, and note-commitment gadgets and distinguished host admission
from equations in the serialized R1CS. No Output constraint semantics changed.

Output synthesis now validates the complete host witness before allocating
public inputs. It checks scalar/value encodings, point and address invariants,
then rebuilds and compares the deterministic component witness traces. This
rejects inconsistent nested witness traces at the API boundary rather than
leaving a partially allocated R1CS. The point check also now rejects an
identity transmission key, matching the pinned `PaymentAddress` invariant.

### Application public-input dependency map

| Public slot | Value | Enforcing relation |
|---:|---|---|
| 1 | `cv.u` | The `u` coordinate of the constrained value commitment `[value]G_v + [rcv]G_r`. |
| 2 | `cv.v` | The `v` coordinate of that same value commitment. |
| 3 | `epk.u` | The `u` coordinate of the constrained variable-base multiplication `[esk]g_d`. |
| 4 | `epk.v` | The `v` coordinate of that same ephemeral key. |
| 5 | `cmu` | The `u` coordinate of the constrained note commitment `Pedersen(value, g_d, pk_d) + [rcm]R`. |

Tests assert these five public columns are allocated first at variable indices
1–5, in the order above, compare their values with the independent
`zcash-test-vectors` fixture, and mutate each public slot independently to
confirm unsatisfied constraints.

### Private witness dependency map

| Private witness family | Defining constraints | Dependent relation |
|---|---|---|
| 64 value bits and the private value variable | Boolean/range decomposition; the shared bit vector encodes the value variable | Value commitment and note-content Pedersen preimage |
| 252 `rcv` bits; value and randomness fixed-base multiplication traces; commitment point | Scalar bits feed the two fixed-base multiplications and point addition | Public `cv.u/v` |
| `g_d.u/v` and its representation | Curve equation, non-small-order check, strict coordinate representation | `epk` multiplication and note-content preimage |
| 252 `esk` bits, variable-base multiplication bases/selections/accumulators, result point | Boolean bits, repeated base doubling, conditional selection, and affine additions | Public `epk.u/v` |
| 256 `pk_d` representation bits | Boolean representation of the `v` coordinate and `u` sign bit; intentionally no in-circuit curve-membership relation | Note-content Pedersen preimage |
| 252 `rcm` bits, Pedersen selected points/accumulators, randomizer multiplication trace, full commitment point | Note-content hash; fixed-base multiplication by the note-commitment randomness generator; point addition | Public `cmu` is commitment `u`; commitment `v` remains private |

The value bit vector is shared between the value commitment and note hash.
The host `diversifier` bytes do not become R1CS variables; they are used to
derive `g_d` before synthesis. No Output relation uses a Merkle path, anchor,
nullifier, ZIP-212 PRF expansion, or transaction-level field.

### Host precondition and circuit-boundary matrix

| Property | Pinned upstream boundary | ZyCoin boundary | Classification |
|---|---|---|---|
| 64-bit note value | `NoteValue` wraps `u64`; the circuit booleanizes exactly 64 bits. | Requires an exact Python `int` in `[0, 2^64)`; the circuit also range-checks and binds the shared bits. | Host type plus R1CS range relation. |
| Value commitment opening (`rcv`) | `ValueCommitmentOpening.randomness` is `jubjub::Scalar` (the Jubjub scalar field). The circuit decomposes the typed scalar to bits, without a separate `< r` comparator. | Requires an exact canonical Python integer in `[0, r)` before allocation; the same 252-bit circuit decomposition is retained without an added range constraint. | Canonicality is a host/type invariant; commitment derivation and public binding are constrained. |
| Diversifier and `g_d` | `PaymentAddress` guarantees a valid diversifier. `Output::synthesize` obtains `g_d` via the checked address, witnesses it, and constrains it on-curve and not-small-order. The diversifier hash is not in the R1CS. | Requires 11 bytes, recomputes `group_hash(b"Zcash_gd", d)`, and verifies it equals the witness base before allocation. The circuit retains its curve/non-small-order and dependent relations. | Diversifier-to-base derivation is host admission; point requirements are also constrained. |
| Ephemeral secret `esk` | Typed as `jubjub::Fr`; `field_into_boolean_vec_le` decomposes it for multiplication, without an in-circuit `< r` comparison. | Requires an exact canonical integer in `[0, r)` before allocation; 252 bits feed the same multiplication relation. | Canonicality is a host/type invariant; `epk = [esk]g_d` is constrained. |
| Transmission key `pk_d` | `PaymentAddress` guarantees prime-subgroup membership and non-identity. `PaymentAddress::from_parts` checks valid `d` and rejects identity but explicitly cannot verify that `pk_d` is derived from `d`/an IVK. The Output circuit intentionally witnesses its representation without checking curve membership. | Requires an on-curve, prime-subgroup, non-identity point before allocation. It does not claim `pk_d` is derived from an IVK, which Output does not receive. | Type/API invariant checked at host admission; no `pk_d` membership equation in R1CS. |
| Note commitment inputs and result | The circuit consumes the checked address, `NoteValue`, and typed `jubjub::Fr` randomness; it computes Pedersen note contents and adds the randomness point, exposing only `cm.u`. | Rebuilds the component witness from validated inputs before allocation; R1CS then binds its full Pedersen/randomizer trace and public `cmu`. | Input types/relationships checked at host boundary; commitment derivation and exposed coordinate constrained. |
| Value commitment point | Output does not accept an unrelated external `cv`; it derives the point from the value and typed randomness and exposes both coordinates. Upstream `ValueCommitment` documentation notes the derived point can be small order for the all-zero opening; no separate non-small-order check is in this circuit. | Derives `cv` from validated opening and constrains both coordinates. It does not add a small-order rejection that would change upstream semantics. | Derived and constrained; zero opening remains allowed by the pinned circuit. |
| `rcm` | Typed as `jubjub::Fr`; its circuit decomposition does not add a `< r` check. | Requires an exact canonical integer in `[0, r)` before allocation, then uses the pinned 252-bit relation. | Canonicality is a host/type invariant; note-commitment relation is constrained. |

The upstream payment-address constructor deliberately cannot establish the
relationship between diversifier and transmission key. ZyCoin validates the
diversifier-to-`g_d` relationship and separately enforces the `pk_d` point
type invariants, but—like the upstream constructor—does not claim that `pk_d`
is derived from an incoming viewing key.

### Serialization, witness independence, and regression evidence

For the independent Output vector, ZyCoin serializes 10,170 ordered local
constraints over 9,914 columns, including five public columns, with matrix
fingerprint
`a5627ac622db6ef1528255352376694459695864e06a03c1c538cd590242ec0f`.
The test repeats serialization and assembles a second valid Output witness
with a different note value; both matrices and fingerprints are identical.
The serialized bytes exclude witness assignments. This is a deterministic
local matrix identity only: it is not an upstream matrix comparison or proof
of correctness. The pinned upstream test reports 7,827 constraints; the local
10,170-row circuit remains structurally different and Bellman matrix
equivalence and Groth16 readiness are not claimed.

Adversarial API tests cover invalid value widths/types; invalid and valid-but-
mismatched diversifiers; mismatched `g_d`; off-curve, identity, and
non-subgroup transmission keys; `rcv`, `rcm`, and `esk` at `r`, below zero,
and Boolean values; inconsistent value/note component fields; and a tampered
ephemeral multiplication trace. Every rejected assembly leaves variable,
public-input, and constraint counts at their fresh-system values. The valid
independent vector still checks all public relations and representative
private-bit/intermediate mutations.

Pinned evidence:

- [`Output` fields and `expose_value_commitment`, `src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs#L32-L146) — host field types and 64-bit/value-commitment synthesis.
- [`Output::synthesize`, `src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs#L431-L545) — public-input order, `g_d`, `esk`, `pk_d`, note commitment, and `cmu`.
- [`PaymentAddress` invariants and constructors, `src/address.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/address.rs) — valid diversifier and non-identity prime-subgroup `pk_d` contract; constructor’s derivation caveat.
- [`Diversifier` and diversified transmission key, `src/keys.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/keys.rs) — diversify hash and subgroup point APIs.
- [`NoteValue`, `src/value.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/value.rs) and [`Rseed`, `src/note.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/note.rs) — unsigned 64-bit value and note-randomness types.
- [`jubjub::Fr` canonical field parser](https://docs.rs/jubjub/0.11.1/jubjub/struct.Fr.html) — scalar representation is canonicalized by the upstream field type.
- [Pinned independent Output relation fixture](../tests/fixtures/sapling_output_reference.json) — coherent note-encryption vector and provenance.

The audit closes the host API admission gaps found here. A detached R1CS
matrix still does not prove host-side canonicality, diversifier derivation,
or `pk_d` subgroup/non-identity properties. Output remains a local
constraint assembly only; Sapling spending remains gated.

## Phase 9.20.40 — Shared Spend/Output primitive and composition audit

### Scope and conclusion

The audit traced the reusable host helpers, constrained gadgets, and R1CS
builders consumed by `constrain_sapling_spend` and
`constrain_sapling_output`. Both assemblies use one Jubjub parameter set,
one BLS12-381 scalar field for R1CS arithmetic, shared fixed-base and
Pedersen/note-commitment helpers, and common Boolean/range machinery.
No inconsistent generator, field, bit-order, or serialization parameter was
found. The deliberate differences are documented below: BLAKE2s and
nullifier multipacking are Spend-only; Output uses variable-base multiplication
for `epk`, not the fixed-base helper; and Output's `pk_d` representation
deliberately lacks an in-circuit curve check, relying on validated address
admission as the pinned circuit does.

### Primitive-to-consumer and semantic comparison

| Shared primitive | Spend consumers | Output consumers | Upstream comparison, cross-circuit behavior |
|---|---|---|---|
| Jubjub field, curve, affine addition/doubling, encoding, and subgroup checks | `ak`, `g_d`, `nk`, `pk_d`, note/commitment points, `rho`, and all derived point relations | `g_d`, `epk`, `pk_d` host representation, `cv`, and note commitment | `FIELD_MODULUS` is exactly the BLS12-381 scalar modulus used by `R1CS`; the separate Jubjub subgroup scalar order has bit width 252. Host `Point` affine formulas and compressed encoding use these same constants in both paths. Both circuits constrain curve points using the pinned twisted-Edwards equation and non-small-order test where upstream does so. Prime-subgroup membership is an admission/type invariant for points that upstream supplies as subgroup types; it is not substituted for the circuit's cheaper non-small-order relation. |
| Fixed-base scalar multiplication | `ar → rk`, `nsk → nk`, value and `rcv` → `cv`, `rcm` randomization, and `[position]J` | Value and `rcv` → `cv`, `rcm` randomization | Both use the same generator lookup and 3-bit window machinery. Six named bases map to their pinned Sapling personalization/message pairs and are checked against upstream coordinate limbs. Upstream circuit scalar decompositions are little-endian. The host APIs require canonical scalar values; the circuit deliberately does not add `< r` comparators where Bellman's source only decomposes field bits. |
| Variable-base scalar multiplication | Derived `pk_d = [ivk]g_d` | `epk = [esk]g_d` | Both use the same little-endian bit, conditional-select, doubling, and affine-addition gadget. The Output base receives its circuit curve and non-small-order checks; the Spend base is validated as part of the shared address/Spend admission and is circuit-checked. No fixed-base table is used for Output `epk`. |
| Pedersen hash and note commitment | Note commitment preimage and 32-level Merkle hashes | Note commitment preimage | One six-bit personalization plus three-bit lookup tables, point accumulators, and pinned Sapling generators serve both. Both note relations share the value, `g_d`, `pk_d` representation, and `rcm` semantics; Output exposes only `cm.u`, while Spend feeds its note leaf into the authentication path and later nullifier relation. Existing MerkleCRH and note-commitment fixtures provide independent expected outputs. Local signed lookup and affine point-addition constraint shapes differ from upstream Bellman. |
| BLAKE2s-256 and Sapling personalizations | IVK hash uses `Zcashivk` and takes low 251 bits; nullifier PRF uses `Zcash_nf` and consumes all 256 bits | Not used | The shared module uses eight-byte BLAKE2s personalization, little-endian-within-byte input/output bits, and constrained compression with Boolean carry/XOR relations. Independent blank/BLAKE2 known-answer, ZIP-32 IVK, nullifier, length-boundary, and tampering tests cover it. This is intentionally a Spend dependency, not an Output constraint. |
| Field/scalar encodings and bit decomposition | 64-bit value; canonical host `rcv`, `nsk`, `rcm`, `ar`; 252-bit scalar decompositions; 255-bit coordinate representations | 64-bit value; canonical host `rcv`, `rcm`, `esk`; 252-bit decompositions; 255-bit coordinate representations | BLS12-381 scalar field and Jubjub coordinate field are the same modulus; Jubjub `Fr` order is a distinct 252-bit modulus. R1CS `range_check` is little-endian, Boolean-constrained, reconstructs the value, and supports strict upper bounds. The note/`cv` scalar bit decompositions intentionally preserve the upstream no-modulus-comparator behavior; canonicality is checked at the host API. Output's 256-bit `pk_d` representation is intentionally unchecked as a point in-circuit, unlike strict representations used for Sapling hash inputs. |
| R1CS Boolean, range, ownership, and field helpers | All relations, plus IVK/NF integration and nullifier packing | All Output relations | A single builder enforces equations over the BLS12-381 scalar modulus, ensures variable ownership, and serializes canonical ordered A/B/C rows without assignments. Boolean constraints are `b(b-1)=0`; range checks bind little-endian Boolean decompositions and optional strict bounds. No separate field implementation or cross-circuit modulus is introduced. |
| Nullifier multipacking | Splits `nf` into 254-bit then 2-bit chunks and binds Spend public slots 6–7 | Not used | Width is selected from the BLS12-381 scalar-field capacity and is injective for both chunks. Output has five public slots and no nullifier; it does not call or allocate this helper. |

### Shared composition, independent evidence, and adversarial coverage

The Phase 9.20.39 Output regression now explicitly rebuilds `cv` and the note
commitment through the standalone shared witness helpers and requires exact
equality with the component traces embedded in the assembled Output witness.
It checks the independent note-encryption vector's compressed `cv` and
little-endian `cmu`, confirms the Jubjub-coordinate/R1CS-modulus equality and
the distinct 252-bit Jubjub scalar order, and exercises zero and maximum
`u64`/canonical scalar openings plus negative, Boolean, and `r` scalar
rejection. This test complements, rather than replaces, the independent
Spend seeded-witness comparison, exact fixed-base generator-limb checks,
fixed-base scalar/boundary tests, Pedersen and note-vector tests, constrained
IVK/nullifier vectors, field/bit alias tests, subgroup/encoding adversarial
cases, R1CS ownership/range/serialization tests, and nullifier packing vector
and mutation tests.

The existing deterministic full-assembly tests continue to pin:

| Assembly | Public inputs | Rows | Matrix fingerprint |
|---|---:|---:|---|
| Spend | 7 application inputs plus separate `ONE` | 130,403 | `b34b388723a41e4602e8779e9df04b114a74b8f4e2e6184f865e0f3285705a29` |
| Output | 5 application inputs plus separate `ONE` | 10,170 | `a5627ac622db6ef1528255352376694459695864e06a03c1c538cd590242ec0f` |

The Output test additionally builds a different valid witness and proves that
the witness-free matrix bytes and fingerprint are unchanged. Fingerprints are
local deterministic change detectors only; matching or stable fingerprints
do not establish semantic correctness or upstream matrix equivalence.

### Differences retained and evidence limits

- The pinned upstream Spend and Output circuits use Bellman's exact lookup,
  allocation, and constraint ordering; ZyCoin's local affine/lookup gadgets
  have different constraint shapes and row counts. No semantic change or
  constraint removal was made to approach upstream counts.
- Upstream witness fields use typed Jubjub scalars and checked address/key
  types. ZyCoin validates canonical scalar values and address point invariants
  before assembly, but the detached R1CS does not prove every host invariant.
- Output `pk_d` is not curve-checked inside the pinned Output circuit. ZyCoin
  host admission verifies its on-curve, prime-subgroup, and non-identity
  conditions to match the upstream `PaymentAddress` type; it does not claim
  that `pk_d` is derived from an IVK.
- `g_d = group_hash("Zcash_gd", d)` is checked before synthesis in both
  host flows; the diversifier bytes/hash relation is not represented in
  either circuit matrix.
- BLAKE2s and nullifier multipacking have no Output consumer. They remain
  independently covered within Spend and are not composed into Output.
- The pinned upstream test reports 98,777 Spend and 7,827 Output constraints;
  ZyCoin reports 130,403 and 10,170 respectively. Neither local matrix is
  Bellman-equivalent, and no Groth16 readiness or spending support is claimed.

### Provenance

- [Pinned Sapling Spend/Output synthesis, circuit fields, and count tests](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
- [Pinned Jubjub circuit arithmetic and fixed-base multiplication](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs)
- [Pinned Sapling Pedersen lookup implementation](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/pedersen_hash.rs)
- [Pinned Sapling generator constants](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/constants.rs)
- [Bellman 0.15 Boolean and field-bit decomposition](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/boolean.rs)
- [Bellman 0.15 BLAKE2s gadget](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/blake2s.rs)
- [Bellman 0.15 multipacking gadget](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/multipack.rs)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [Independent Output relation vector](../tests/fixtures/sapling_output_reference.json)
- [Independent Sapling key, note, and nullifier fixtures](../tests/fixtures/sapling_nullifier_reference.json)

No confirmed shared-primitive defect was found. The non-equivalent Bellman
constraint strategies, host-only invariants, Output-specific unchecked
representation, and Spend-only BLAKE2s/multipacking surfaces are explicit
boundaries, not silently harmonized behaviors. Spend and Output circuit
semantics and the established matrix fingerprints remain unchanged.

## Phase 9.20.41 — Groth16 parameter compatibility

### Official parameter artifacts and provenance

The official Zcash download endpoints previously served two distinct
parameter files during the Phase 9.20.41 streamed-hash audit:

| Parameter set | Official source | Bytes | Prior streamed SHA-512 | Zcash-published BLAKE2b-512 | Intended circuit |
|---|---|---:|---|---|---|
| Sapling Spend | [sapling-spend.params](https://download.z.cash/downloads/sapling-spend.params) | 47,958,396 | `320fbb5754c8b3f4ecb3dd4c2e3dbe1d138c4b343f073c7e31612d26fe769cdba8edab426a7f2c42e317bebdb2ca6f73af1312affa1fcf599a31d499ad4cb4e5` | `8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c` | Spend |
| Sapling Output | [sapling-output.params](https://download.z.cash/downloads/sapling-output.params) | 3,592,860 | `a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152` | `657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028` | Output |

The SHA-512 values were computed by streaming the public URLs through CPython
3.10.11 and match the independent SHA-512 pins in the
[Z23 Sapling parameter checks](https://github.com/z23c/z23/blob/7df112acb8584c0a0df4858838b868e0f20e0396/core/modules/sapling/src/params_init.c).
They differ from the current `librustzcash` BLAKE2b-512 pins because they are
different hash algorithms, not because of a parameter-file discrepancy.
Zcash's [parameter constants](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/lib.rs)
are checked with its BLAKE2b-based
[HashReader](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/hashreader.rs).
The current audit streamed both public URLs again and independently matched
the exact byte lengths, SHA-512 digests, and BLAKE2b-512 digests above. It
also scanned the Bellman section headers/counts and found the 52,836-byte
transcript trailer in each file. No parameter file was written to disk or
used for proving; the full point sections were not passed through the Python
curve/subgroup decoder.
The pinned upstream `sapling-crypto` source identifies version 0.9.0 and
declares Bellman 0.15, Groth16 0.2, and `bls12_381` 0.9 in its
[Cargo manifest](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/Cargo.toml).
The official
[Sapling MPC repository](https://github.com/zcash/sapling-mpc/tree/7934d34502745f3a8c03a7f98355a990d42930b7)
documents the network-upgrade multiparty computation. Its pinned
[`compute.rs`](https://github.com/zcash/sapling-mpc/blob/7934d34502745f3a8c03a7f98355a990d42930b7/src/bin/compute.rs)
shows the contribution hash generation, while
[`split_params.rs`](https://github.com/zcash/sapling-mpc/blob/7934d34502745f3a8c03a7f98355a990d42930b7/src/bin/split_params.rs)
extracts separate Spend and Output parameter files. These sources establish
the intended parameter family and how the artifacts are produced, but are
not a participant-by-participant ceremony transcript. No distinct release
version or circuit revision is encoded in the parameter filenames or proven
by the parameter-file bytes alone.

In the pinned
[`sapling-crypto` circuit source](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs),
the two parameter wrapper types are `SpendParameters` and
`OutputParameters`. Their `read` methods both parse generic Bellman Groth16
parameters; their separate prover implementations associate them with
`Spend` and `Output`, respectively, in
[`prover.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/prover.rs).
This is the source-level circuit association. No cryptographically
self-identifying circuit ID in the parameter encoding was established in
this audit; a filename, wrapper type, or matching verification-key input
length is not such an ID. The upstream reader also documents that disabling
point-encoding verification is only appropriate when another integrity
check, such as a trusted file hash, is performed.

### Circuit dimensions and identity evidence

| Circuit | Upstream application inputs (plus implicit `ONE`) | Upstream test rows | Upstream test hash | ZyCoin application inputs | ZyCoin columns / rows | ZyCoin matrix fingerprint |
|---|---:|---:|---|---:|---:|---|
| Spend | 7 (8 total inputs) | 98,777 | Bellman test-system hash `d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89` | 7 | 129,714 / 130,403 | `b34b388723a41e4602e8779e9df04b114a74b8f4e2e6184f865e0f3285705a29` |
| Output | 5 (6 total inputs) | 7,827 | Bellman test-system hash `c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee` | 5 | 9,914 / 10,170 | `a5627ac622db6ef1528255352376694459695864e06a03c1c538cd590242ec0f` |

The pinned upstream source and local assemblies use the same application
input order: Spend is `rk.u, rk.v, cv.u, cv.v, anchor, nf[0], nf[1]`;
Output is `cv.u, cv.v, epk.u, epk.v, cmu.u`. Bellman's implicit `ONE` is the
first input in both, not an additional application input.

The upstream row counts, input counts, and test hashes come from the pinned
`circuit.rs` tests. The tests do not publish upstream auxiliary-variable
counts or ordered A/B/C matrix exports. ZyCoin's column counts and
fingerprints are reproducible local measurements; its fingerprint format is
versioned, witness-free, and not Bellman's test hash format. Thus the
fingerprints cannot be compared to upstream hashes. The local and upstream
row counts differ by 31,626 for Spend and 2,343 for Output. This alone
disproves direct matrix identity for both local assemblies; matching semantic
relations, public-input counts, or a future proof-verification result would
not erase this difference.

The parameters are network-wide Sapling circuit artifacts, not coin-specific
variants. A coin JSON declaration of the filenames does not verify that the
files it distributes are byte-identical to these upstream artifacts or that
the coin uses the same circuit synthesis. The hashes and association above
apply to the exact streamed Zcash artifacts and the pinned Zcash circuit
reference only.

### Python implementation boundary and decision

`src/bls12_381.py` implements field and group arithmetic, compressed G1/G2
encoding/decoding, subgroup checks, Miller loop, and reduced pairing.
`src/r1cs.py` implements ZyCoin constraint construction, witness evaluation,
and its own matrix serialization. Neither module parses Bellman parameter
files, represents Groth16 proving/verifying queries or keys, converts an
R1CS to the required QAP, or implements Groth16 proof verification. No
multi-scalar multiplication / query evaluation pipeline is present. The
pairing primitive alone is therefore insufficient for parameter validation
or proof verification; it is also variable-time Python and not a production
secret-handling backend.

| Circuit / capability | Decision | Evidence |
|---|---|---|
| Authentic Zcash Spend parameters as a source artifact | **Verified identity of the streamed artifact** | Official URL, byte length, and computed SHA-512 match the independent pin above. No local parameter file or loader was added. |
| Spend circuit with ZyCoin assembly and official parameters | **Blocked / not eligible** | Local and upstream row counts differ (130,403 vs 98,777); no upstream matrix export is available for exact coefficient/ordering comparison. |
| Authentic Zcash Output parameters as a source artifact | **Verified identity of the streamed artifact** | Official URL, byte length, and computed SHA-512 match the independent pin above. No local parameter file or loader was added. |
| Output circuit with ZyCoin assembly and official parameters | **Blocked / not eligible** | Local and upstream row counts differ (10,170 vs 7,827); no upstream matrix export is available for exact coefficient/ordering comparison. |
| ZyCoin parameter parsing, authentication, and Groth16 verification | **Unsupported** | No Groth16 key/parameter representation, parser, authenticated loader, QAP, or verifier exists. |
| Sapling proof generation / spending | **Unsupported; gated** | Circuit identity is not established, and proving, authorization/binding signatures, transaction assembly, and independent verification remain absent. |

Before any authentic parameters are used with ZyCoin, all of the following
gates must pass:

1. Pin the official source, exact bytes, file size, cryptographic hash, and
   applicable network/circuit version; validate the full parameter encoding,
   canonical field/group encodings, subgroup membership, and key/query
   consistency before use.
2. Establish the exact per-circuit association, application public-input
   order (with implicit `ONE` handled as the backend expects), and complete
   auxiliary-variable and constraint dimensions. A filename or input count
   is insufficient.
3. Compare the complete ordered A/B/C matrices and coefficients with an
   authoritative export of the exact circuit, or provide an equivalent
   independently authenticated circuit-identity proof. Constraint-count
   equality, local fingerprints, or a satisfied witness are insufficient.
4. Implement and independently test a pure-Python parameter/key parser and
   Groth16 verifier against authoritative positive and tampered-proof
   vectors. Do not treat successful parsing or pairing alone as circuit
   compatibility.
5. Keep proof generation and spending disabled until a separately audited,
   safe proving path and all transaction-level Sapling requirements are
   complete.

### Phase verification

- CPython 3.10.11 streamed both official parameter files without persisting
  them; observed lengths and SHA-512 values are recorded above.
- Source inspection covered the pinned upstream circuit/prover wrappers,
  parameter MPC tooling, local assembly dimensions, and BLS12-381/R1CS
  surfaces.
- CPython 3.10.11 full suite: **119 passed**; focused Sapling tests: **40
  passed**; R1CS: **13 passed**; BLS12-381: **9 passed**.
- `compileall` passed. Ruff correctness rules (`E4,E7,E9,F`) passed on the
  audited modules. The broader default targeted Ruff check still reports 14
  existing import-order, modernization, and line-length findings in
  untouched Python files; these were not in scope for this documentation
  audit.
- Pylance diagnostics returned no findings for BLS12-381, R1CS, Spend, or
  shared Sapling gadget modules.
- Updated report links and the Phase 9.20.41 anchor passed; `git diff
  --check` passed for all three changed reports.
- Wheel and sdist built from a temporary source copy. A clean-target wheel
  install imported the packaged circuit/crypto modules and accessed the
  packaged BitcoinZ coin JSON. The sdist and wheel contain the relevant
  circuit source/report/resources and do not bundle `.params` files.
- No circuit semantics, fingerprints, package resources, or spending gates
  were changed by this audit.

## Phase 9.20.42 — Spend/Output upstream shape reconciliation

This addendum supersedes earlier local row/column counts and fingerprints
where they describe the current Spend and Output assemblies. Earlier phase
sections remain historical records of the measurements made at that time.
The pinned reference remains `zcash/sapling-crypto`
`88a7946b4a3066787776e11f0a502654167e022d` with Bellman 0.15.0. Upstream
whole-circuit counts are asserted in its tests; its per-relation figures in
the comparison below are source-derived, not separately emitted by an
upstream build.

### Safe strict-coordinate reduction

`constrain_jubjub_repr` now decomposes each coordinate using the strict
prefix-AND comparator pattern from Bellman 0.15's
`AllocatedNum.to_bits_le_strict`, rather than the generic `R1CS.range_check`
comparator. This preserves a 255-bit little-endian representation that is
strictly below the BLS12-381 scalar-field modulus and still reconstructs the
original field variable. For the pinned modulus, `modulus - 1` has 133
one-bits and 122 zero-bits, so each coordinate uses 133 Boolean rows, 132
prefix-AND rows, 122 conditional-zero rows, and one reconstruction row:
**388 rows**, versus 646 before. The saving is 258 rows and 257 auxiliary
columns per coordinate.

The reduction covers the ten checked coordinates of the five Spend points
(`ak`, `nk`, `g_d`, `pk_d`, and `rho`) and Output's two checked `g_d`
coordinates. It does not alter the generic range-check helper, the Output
circuit's intentionally unchecked `pk_d` representation, any point/hash
gadget, or application public inputs. Regression tests exercise the valid
`modulus - 1` boundary and reject bit aliases for `modulus` (zero) and
`modulus + 1` (one); the complete deterministic Spend and Output witnesses
remain satisfied.

### Current measured structure

| Circuit/relation group | Pinned upstream | ZyCoin after Phase 9.20.42 | Difference |
|---|---:|---:|---:|
| Spend: `ak` and randomized authorization key | 1,030 | 1,031 | +1 |
| Spend: `nsk`, `nk`, point representations, and IVK | 23,560 | 24,084 | +524 |
| Spend: `g_d` and `pk_d` | 4,048 | 4,048 | 0 |
| Spend: value and note commitment | 4,031 | 4,982 | +951 |
| Spend: Merkle path, position, and conditional anchor | 44,226 | 71,266 | +27,040 |
| Spend: `rho`, nullifier PRF, and multipacking | 21,882 | 22,412 | +530 |
| **Spend total** | **98,777** | **127,823** | **+29,046** |
| **Output total** | **7,827** | **9,654** | **+1,827** |

Spend's current per-group counts are measured and regression-pinned locally.
The upstream per-group values remain source-derived semantic groupings, not a
row-by-row matrix correspondence. The complete difference is still
accounted for: **27,990** rows from the differing Pedersen hash structure,
**1,054** from BLAKE2s structure, and **2** explicit local value/scalar
bindings. Strict-coordinate decomposition no longer contributes an excess.
The 27,040-row Merkle component remains the dominant measured difference.

The Output assembly has no independently emitted upstream per-relation
counts that would support a reliable finer-grained breakdown. Its checked
`g_d` representation saves 516 rows; the remaining 1,827-row difference is
retained and reflects the already audited local Pedersen coordinate/allocation,
affine-addition, scalar decomposition, and variable-base structure. This
attribution is component-level evidence, not an ordered-row comparison.

| Circuit | Application inputs (plus separate `ONE`) | Local columns | Local rows | Upstream rows | Local fingerprint v1 |
|---|---:|---:|---:|---:|---|
| Spend | 7 (8 total inputs) | 127,144 | 127,823 | 98,777 | `8fbe0deea3c3386e28cdf582a98658a9c37c49ca1d353c77050d9643fef482f8` |
| Output | 5 (6 total inputs) | 9,400 | 9,654 | 7,827 | `8078509dd71169f7931212dc38b0809e68d389e729853c8301d84b9f35a02cac` |

The Spend and Output fingerprints changed because the strict comparator rows
and allocated prefix variables changed; the versioned serialization itself
was not changed. The two complete deterministic assemblies satisfy their
local R1CS systems and retain the established public-input order. Their
different row counts already disprove direct matrix identity with the pinned
upstream circuits. No ordered upstream A/B/C matrix is available here, so
this phase makes no claim of matrix equivalence, Groth16 compatibility, or
proving readiness. No constraint was removed merely to approach an upstream
count. Sapling spending remains gated.

### Phase 9.20.42 verification

- CPython 3.10.11 full suite: **120 passed**. Focused Spend, Output, and
  shared Sapling gadget regressions: **30 passed**; strict representation and
  note-commitment boundary regressions: **2 passed**.
- Tests verify the `modulus - 1` boundary, reject noncanonical `modulus` and
  `modulus + 1` bit aliases, assert the 388-row-per-coordinate result, pin
  updated Spend relation counts and both deterministic matrix fingerprints,
  and preserve complete witness satisfaction and existing mutation checks.
- `compileall`, targeted Ruff correctness checks, Pylance diagnostics for the
  changed gadget and tests, and `git diff --check` passed.
- Wheel and sdist builds passed. The wheel/sdist include the updated circuit
  source; the sdist includes the circuit report. A clean-target wheel install
  reproduced the deterministic Spend witness, 127,823-row assembly, and
  fingerprint, and accessed the packaged coin JSON resources.

## Phase 9.20.43 — Pedersen hash Bellman reconciliation

This section supersedes prior Pedersen and current-circuit counts where they
describe the present Spend/Output assembly. The upstream reference is pinned
to `zcash/sapling-crypto`
`88a7946b4a3066787776e11f0a502654167e022d`, Bellman 0.15.0. Evidence was
read from upstream
[`pedersen_hash.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pedersen_hash.rs),
[`circuit/pedersen_hash.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/pedersen_hash.rs),
[`circuit/constants.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/constants.rs),
and Bellman's 0.15.0
[`lookup.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/lookup.rs).
The pinned source exposes the hash gadget's row-count formula and test
assertions; it does not export an ordered upstream R1CS matrix.

### Relation semantics and implementation comparison

| Relation | Pinned upstream Bellman | ZyCoin |
|---|---|---|
| Personalization and input order | Six constant bits. `NoteCommitment` is six ones; `MerkleTree(depth)` is the six-bit little-endian encoding of `depth`. Message bits follow in supplied order. | `make_pedersen_witness` and the gadget accept the same six little-endian personalization bits followed by message bits. Composed note and Merkle paths pass the corresponding pinned values. |
| 3-bit window encoding | Consume `a,b,c` little-endian; digit is `(1 + a + 2b) * (-1)^c`. Missing terminal bits are constant zero. | Same expression, bit order, padding, and signed digit. `_pedersen_tables` uses points for multipliers 1, 2, 3, 4 and advances each window base by 16. |
| Segment construction | 63 windows per circuit generator. Each window uses the segment's precomputed Montgomery table; each segment accumulates in Montgomery form. | Same 63-window generator segments and `Zcash_PH || index_le32` group-hash generators, but allocates selected Edwards `(u,v)` points and performs affine Edwards additions inside each segment. |
| Lookup and conditional negation | Bellman's lookup returns Montgomery `x` as a linear combination and allocates `y`; the signed lookup enforces its conditional sign in one row. A three-bit unsigned precomputation AND and coordinate relation produce two rows, less rows when input bits are constant. | The lookup binds the Edwards `v` coordinate and conditionally negates Edwards `u`. A constrained `a*b` precomputation is shared by the coordinate expressions. Before this phase, the `c * base_u` temporary and the `u` equality were separate rows. |
| Point additions and segment output | Three rows per within-segment Montgomery addition; two rows convert each segment to twisted Edwards; six rows combine each later segment in Edwards form. | Six rows per within-segment affine Edwards addition and six per later segment combination; there is no intermediate Montgomery representation or segment conversion. |
| Result | The final result is an Edwards point, combining converted segment results. | The final result is an Edwards-coordinate pair used by note commitment or Merkle parent extraction. |

Thus, the bit order, personalization, signed-digit scalar, generator selection,
63-window segmentation, and final semantic Jubjub point agree in the
independent upstream test vectors and local reference tests. The synthesis
representations do not agree: local selected points are both allocated
Edwards coordinates, while Bellman's selected Montgomery `x` remains a
linear expression. That representation difference explains why the local
lookup cannot be reduced to Bellman's two rows merely by deleting a row.

### Per-window and per-segment accounting

Counts below exclude message-bit Boolean constraints on both sides. ZyCoin
hash rows are from the actual composed witness relation, with constant
personalization and terminal padding folded as the local builder permits.
Bellman rows use its pinned `ph_num_constraints` formula. Segment-combination
rows are attributed to the segment being combined; the first segment has no
such rows.

Note-commitment input is 576 message bits: 194 windows in segments
`[63, 63, 63, 5]`. MerkleCRH input is 510 message bits: 172 windows in
segments `[63, 63, 46]`.

| Hash / segment | Windows | ZyCoin lookup | ZyCoin Edwards additions | ZyCoin segment combine | ZyCoin total | Bellman lookup | Bellman Montgomery adds | Bellman conversion | Bellman segment combine | Bellman total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Note / 0 | 63 | 187 | 372 | 0 | 559 | 124 | 186 | 2 | 0 | 312 |
| Note / 1 | 63 | 189 | 372 | 6 | 567 | 126 | 186 | 2 | 6 | 320 |
| Note / 2 | 63 | 189 | 372 | 6 | 567 | 126 | 186 | 2 | 6 | 320 |
| Note / 3 | 5 | 15 | 24 | 6 | 45 | 10 | 12 | 2 | 6 | 30 |
| **Note total** | **194** | **580** | **1,140** | **18** | **1,738** | **386** | **570** | **8** | **18** | **982** |
| Merkle / 0 | 63 | 187 | 372 | 0 | 559 | 124 | 186 | 2 | 0 | 312 |
| Merkle / 1 | 63 | 189 | 372 | 6 | 567 | 126 | 186 | 2 | 6 | 320 |
| Merkle / 2 | 46 | 138 | 270 | 6 | 414 | 92 | 135 | 2 | 6 | 235 |
| **Merkle total** | **172** | **514** | **1,014** | **12** | **1,540** | **342** | **507** | **6** | **12** | **867** |

The two fewer lookup-precomputation rows in the first note segment come from
the first two windows being fully fixed by the six constant personalization
bits. The Merkle hash likewise uses constant personalization bits in the
composed path. ZyCoin's composed call sites preconstrain message bits where
the upstream circuit already receives Boolean representations; those input
bitness rows are not counted as Pedersen-internal rows here.

Boundary lengths follow the same pinned upstream test cases around the first
63-window boundary. The local values below include the Pedersen gadget rows
but exclude the message-bit Boolean rows; upstream values are
`ph_num_constraints`.

| Message bits | Windows by segment | ZyCoin internal rows | Bellman rows | Difference |
|---:|---|---:|---:|---:|
| 183 | `[63]` | 559 | 312 | +247 |
| 184 | `[63, 1]` | 567 | 321 | +246 |
| 185 | `[63, 1]` | 568 | 322 | +246 |
| 510 | `[63, 63, 46]` | 1,540 | 867 | +673 |
| 576 | `[63, 63, 63, 5]` | 1,738 | 982 | +756 |

The test asserts these ZyCoin counts and independently compares all resulting
points for zero-filled inputs against the pure-Python Sapling host reference.
Pinned upstream `test_vectors.rs` boundary cases independently check
`NoteCommitment` with no message bits, one zero bit, and one one bit; these
exercise the six-bit prefix, little-endian message order, and resulting `u`
and `v` coordinates. The existing pinned Zcash MerkleCRH fixture checks
depth-personalization order and `u`; its `v` is cross-checked against the
independent host reference.

### Soundness-preserving reduction

The conditional Edwards-`u` selection previously allocated
`sign_product = sign * base_u`, then separately enforced
`selected_u = base_u - 2 * sign_product`. These are replaced by the single
R1CS equation

`sign * (2 * base_u) = base_u - selected_u`.

Given the already Boolean-constrained sign bit, this is algebraically the same
relation for both signs. The coordinate `v` lookup and the constrained
`a*b` precomputation are unchanged. Exhaustive tests cover all eight
three-bit patterns, assert three rows for a fully variable window, and reject
each changed bit and either selected-coordinate tampering. Constant inputs
continue to be constrained by the equations without adding assumptions about
their values.

This removes one multiplication row and one auxiliary product column per
Pedersen window: 194 rows for the note hash and 172 per Merkle hash. Across
the composed Spend and Output paths, the measured saving is **5,698 rows and
columns** (194 + 32 × 172). It does not change note or Merkle semantics. The
remaining per-hash differences are not removed: signed Edwards lookup still
requires an additional row relative to Bellman's Montgomery `x`/`y`
representation, and local within-segment Edwards additions use six rows
versus Bellman's three-row Montgomery additions plus explicit segment
conversion.

### Current Spend/Output counts and fingerprint history

| Circuit/relation group | Bellman pinned | ZyCoin current | Difference |
|---|---:|---:|---:|
| Spend: `ak` and randomized authorization key | 1,030 | 1,031 | +1 |
| Spend: `nsk`, `nk`, point representations, and IVK | 23,560 | 24,084 | +524 |
| Spend: `g_d` and `pk_d` | 4,048 | 4,048 | 0 |
| Spend: value and note commitment | 4,031 | 4,788 | +757 |
| Spend: Merkle path, position, and conditional anchor | 44,226 | 65,762 | +21,536 |
| Spend: `rho`, nullifier PRF, and multipacking | 21,882 | 22,412 | +530 |
| **Spend total** | **98,777** | **122,125** | **+23,348** |
| **Output total** | **7,827** | **9,460** | **+1,633** |

The current Spend Pedersen excess is 756 note-hash rows plus
673 × 32 = 21,536 Merkle rows, totaling **22,292**. Together with 1,054
BLAKE2s rows and two explicit value/scalar bindings, this accounts for the
23,348 Spend gap. Those BLAKE2s and binding relations were not altered in
this phase. Output's 1,633-row gap includes the same 756-row note-hash
difference and previously documented non-Pedersen value, scalar, and
variable-base structure; no additional Output relation was changed.

| Circuit | Phase 9.20.41 | Phase 9.20.42 | Phase 9.20.43 current |
|---|---|---|---|
| Spend rows / columns / fingerprint | 130,403 / 129,714 / `b34b388723a41e4602e8779e9df04b114a74b8f4e2e6184f865e0f3285705a29` | 127,823 / 127,144 / `8fbe0deea3c3386e28cdf582a98658a9c37c49ca1d353c77050d9643fef482f8` | 122,125 / 121,446 / `5a30865162cc958176e1be6efbc2a72486fa3cabbb41a1ff339bbf7860bd6b2a` |
| Output rows / columns / fingerprint | 10,170 / 9,914 / `a5627ac622db6ef1528255352376694459695864e06a03c1c538cd590242ec0f` | 9,654 / 9,400 / `8078509dd71169f7931212dc38b0809e68d389e729853c8301d84b9f35a02cac` | 9,460 / 9,206 / `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` |

Fingerprints use the existing witness-free `zycoin-r1cs-matrix-v1`
serialization. Only circuit rows and auxiliary-column allocations changed;
the format version did not. Fingerprints are deterministic local change
detectors, not circuit-correctness proofs or Bellman identity evidence. Both
complete deterministic witnesses remain satisfied, but unequal row counts
(Spend 122,125 vs 98,777; Output 9,460 vs 7,827) continue to disprove direct
matrix identity. No ordered upstream A/B/C matrix comparison or Groth16
compatibility claim is made. Sapling spending remains gated.

### Phase 9.20.43 verification

- CPython 3.10.11 full suite: **123 passed**. Focused Pedersen, Spend,
  Output, and R1CS suites: **46 passed**.
- The pinned upstream empty/one-bit point vectors, 510-bit Merkle vector,
  and 183/184/185/510/576-bit segment-count boundaries are covered.
- `compileall`, targeted Ruff correctness checks, Pylance diagnostics for
  the changed gadget and tests, and `git diff --check` passed.
- Wheel and sdist builds passed. The sdist contains the new upstream-vector
  fixture and circuit report. A clean-target wheel install assembled and
  satisfied the deterministic Spend witness at 122,125 rows / 121,446
  columns and reproduced fingerprint
  `5a30865162cc958176e1be6efbc2a72486fa3cabbb41a1ff339bbf7860bd6b2a`;
  packaged coin resources loaded.
- No BLAKE2s or explicit value/scalar binding relation was modified.

## Phase 9.20.44 — BLAKE2s gadget Bellman reconciliation

This section supersedes the Phase 9.20.43 Spend row/column counts,
fingerprint, and BLAKE2s structural-gap accounting. It does not change
Pedersen or Output. The circuit source is pinned to
[`zcash/sapling-crypto` commit `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/tree/88a7946b4a3066787776e11f0a502654167e022d);
its `Cargo.lock` pins Bellman 0.15.0 with checksum
`973b16549796a1274a63e00159a03250e66e8263e2ac6344b1c9fdfe9b7a8325`.
Sapling's pinned `src/circuit.rs` calls Bellman's BLAKE2s gadget for the
incoming-viewing-key and nullifier hashes. The compared sources are Bellman's
[`blake2s.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/blake2s.rs),
[`uint32.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/uint32.rs),
[`boolean.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/boolean.rs),
and [`multieq.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/multieq.rs).

### Function semantics and consumer wiring

| Property | Pinned upstream | ZyCoin |
|---|---|---|
| Parameters | Unkeyed 32-byte BLAKE2s digest; parameter block encodes digest length 32, key length 0, fanout 1, depth 1. `h[0]` is `IV[0] ^ 0x01010000 ^ 32`. | `hashlib.blake2s(..., digest_size=32, person=...)` supplies the witness digest; the R1CS independently builds the same IV and parameterized state. |
| Personalization | Exactly 8 bytes; little-endian 32-bit halves XOR into `IV[6]` and `IV[7]`. | Same length check, byte order, initial words, and `Zcashivk` / `Zcash_nf` personalizations. |
| Input and blocks | Boolean bits are little-endian within bytes. Blocks contain 512 bits, words are little-endian, incomplete words/blocks are zero-padded, and empty input synthesizes one zero block. Counter is the number of input bytes; only the last block sets `f = 0xffffffff`. | Same bit order, 512-bit block split, padding, empty-input behavior, byte counter, and final flag. |
| Compression | BLAKE2s IV and ten rounds; pinned `SIGMA` schedule; each `G` performs modular additions and XORs with right rotations 16, 12, 8, 7. Final state is `h[i] ^ v[i] ^ v[i+8]`. | Same IV, schedule, operations, rotation permutation, and feed-forward. |
| Digest and consumers | State words are emitted as little-endian bits. Spend truncates IVK to the low 251 bits and uses all 256 nullifier digest bits. | Same output encoding and truncation. Spend hashes `repr(ak) || repr(nk)` with `Zcashivk` and `repr(nk) || repr(rho)` with `Zcash_nf`; no Output relation consumes BLAKE2s. |

### One-block operation counts

The comparable case is Bellman's pinned 512-variable-bit constraint test:
one full 64-byte message block, one compression, all 512 message bits
variable, and a constant personalization. Its upstream test asserts 21,518
constraints. The table counts the same input-bit constraints on both sides.
The “before” column is the pre-Phase-44 ZyCoin construction; “after” is the
current shared gadget.

| Operation | Per compression / round | Bellman 0.15.0 | ZyCoin before | ZyCoin after |
|---|---:|---:|---:|---:|
| Input Boolean constraints | 512 input bits | 512 | 512 | 512 |
| Addition output/carry Boolean constraints | 32 additions per round; 16 three-word (34 result bits) and 16 two-word (33 result bits): 1,072 per round | 10,720 | 10,720 | 10,720 |
| Modular-addition equalities | 320 total; one bounded equality per operation is packed across the ten rounds | 46 packed rows | 320 rows | 46 packed rows |
| `G`-function XOR equations | Round 0: 768; rounds 1–9: 1,024 each | 9,984 | 9,984 | 9,984 |
| Final feed-forward XOR equations | 8 words × 2 XORs × 32 bits | 256 | 256 | 256 |
| Constant-one XOR/complement constraints | Round-zero and final-state constants use Boolean negation aliases | 0 | 250 (`Zcashivk`); 256 (`Zcash_nf`) | 0 |
| **Total, `Zcashivk`** | **one 512-bit input block** | **21,518** | **22,042** | **21,518** |
| **Total, `Zcash_nf`** | **one 512-bit input block** | **21,518** | **22,048** | **21,518** |

The per-round local row profile after the change includes packed-equality rows
attributed to the first addition in each batch. Each round has 1,072
addition-result Boolean constraints. Its XOR row counts are 768 in round 0
and 1,024 in each later round. The batch attribution is 5, 5, 4, 5, 4, 5, 4,
5, 5, 4 rows (46 total). Round 0's lower XOR count comes from the first four
column `G` calls XORing variable words with initial constant state words;
Bellman's Boolean layer represents these as aliases or `Not` values, not
constraints. The final feed-forward contributes 256 rows, and the 512 input
Boolean rows are outside the ten round namespaces.

### Reductions and soundness argument

1. **Bounded addition packing (274 rows per full block).** Previously each of
   the 320 additions allocated the same Boolean low-word and carry bits as
   upstream, but enforced its integer reconstruction in a separate row.
   Bellman's `MultiEq` combines these equations with radix coefficients while
   the sum of their bit widths stays below the BLS12-381 scalar capacity.
   ZyCoin now uses that same threshold and ordering: two-word additions have
   33 bounded result bits; three-word additions have 34. For Boolean input,
   output, and carry decompositions, every residual is strictly bounded by
   its declared width; the capacity bound prevents field wrap or nonzero
   residual cancellation. The 320 equalities therefore remain enforced, in
   46 rows, without relaxing any bit or arithmetic relation.
2. **Boolean negation aliases (250/256 rows per Spend hash).** A constant-one
   XOR previously allocated a complement variable and an equality row.
   Bellman's `Boolean::Not` instead represents `1 - b` as a linear
   combination over the already Boolean-constrained `b`. ZyCoin now carries
   the same complemented-bit form through the word operations and folds it
   into addition/XOR linear combinations. The base bit's Boolean constraint
   remains, and output vectors stay ordinary variables/constants at their
   existing boundary. The 250 IVK and 256 nullifier complement rows disappear.

Together these soundness-preserving reductions remove 524 rows for the IVK
hash and 530 for the nullifier hash, **1,054 rows total**. The output/carry
Boolean variables are unchanged; only the 506 complement auxiliaries are
removed from the composed Spend assembly.

### Vectors, tampering, and remaining evidence limits

Tests cover the pinned Bellman blank personalized digest, the BLAKE2s known
answer vector, little-endian bit serialization, and message lengths 0, 1, 3,
63, 64, and 65 bytes against Python's independent `hashlib` implementation.
The IVK and nullifier outputs continue to match their pinned Sapling vectors.
Input, digest, and modular-addition witness mutations fail satisfaction. A
full 64-byte variable-input compression asserts Bellman's 21,518-row count,
the 512 input-bit rows, 10,720 addition Boolean rows, 46 packed equalities,
10,240 XOR rows, and per-round profile. This is operation-count evidence,
not an ordered A/B/C matrix comparison.

Bellman's variable-variable XOR relation is written as
`(2a) * b = a + b - x`; ZyCoin uses the algebraically equivalent
`a * b = (a + b - x) / 2` over the same odd prime field. Their R1CS
coefficients and matrix rows are not identical. Matching the BLAKE2s count,
known-answer outputs, or witness satisfaction therefore does not prove
Bellman matrix equivalence. The complete Spend and Output matrices remain
ineligible for authentic Sapling proving parameters; Sapling spending remains
gated.

### Current Spend dimensions and fingerprint

| Circuit | Phase 9.20.43 | Phase 9.20.44 current |
|---|---|---|
| Spend rows / columns / fingerprint | 122,125 / 121,446 / `5a30865162cc958176e1be6efbc2a72486fa3cabbb41a1ff339bbf7860bd6b2a` | 121,071 / 120,940 / `9cf4d3458d4bd02acfbdc179b031d9cdc7314d927f9310c4f118bb338f9add6f` |
| Output rows / columns / fingerprint | 9,460 / 9,206 / `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` | 9,460 / 9,206 / `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` |

The Spend gap to Bellman's 98,777 rows is now **22,294**: 22,292
Pedersen rows plus the same two explicit local value/scalar bindings. The
1,054-row BLAKE2s gap is removed. Output semantics and its fingerprint are
unchanged. Fingerprints retain the `zycoin-r1cs-matrix-v1` format; they are
change detectors, not correctness or compatibility proofs.

### Phase 9.20.44 verification

- CPython 3.10.11 full suite: **125 passed**; focused BLAKE2s/Spend/Output
  and gadget tests: **45 passed**.
- `compileall`, targeted Ruff correctness checks, Pylance diagnostics for the
  changed Python files, and Phase 9.20.44 whitespace checks passed.
- Wheel and sdist builds passed. A clean-target wheel install assembled and
  satisfied the deterministic Spend witness at 121,071 rows / 120,940
  columns, reproduced fingerprint
  `9cf4d3458d4bd02acfbdc179b031d9cdc7314d927f9310c4f118bb338f9add6f`, and
  accessed packaged coin resources. The sdist contains this circuit report.

## Phase 9.20.45 — BLAKE2s XOR gadget Bellman equivalence

This section supersedes Phase 9.20.44's Spend dimensions, fingerprint, and
BLAKE2s row-gap explanation. The pinned references are Bellman 0.15.0's
[`boolean.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/boolean.rs),
[`blake2s.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/blake2s.rs),
and [`multieq.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/multieq.rs),
with Bellman checksum
`973b16549796a1274a63e00159a03250e66e8263e2ac6344b1c9fdfe9b7a8325` in the
pinned `sapling-crypto` 0.9.0 `Cargo.lock`.

### XOR relation and variable representation

Bellman's `AllocatedBit::xor` allocates the result bit `x` and enforces

`(2a) * b = a + b - x`.

For ZyCoin's ordered A/B/C terms this is exactly
`A = 2a`, `B = b`, `C = a + b - x`. ZyCoin previously encoded the same
Boolean truth table as
`a * b = (a + b - x) / 2`; because 2 is invertible in this field, that was
algebraically equivalent, but the A/B/C coefficients differed. The local
implementation now allocates the raw XOR bit first and emits Bellman's exact
coefficient placement and signs. Canonical field serialization stores `-1`
as `SCALAR_MODULUS - 1`.

| Bellman operands | Upstream synthesis | ZyCoin synthesis now |
|---|---|---|
| `Is(a)`, `Is(b)` | Allocate `x = a XOR b`; add row `(2a) * b = a + b - x`. | Same allocation order and row terms. |
| `Not(a)`, `Not(b)` | Reuse `AllocatedBit::xor(a,b)`; `NOT(a) XOR NOT(b) = a XOR b`. | Same raw-bit row and direct output alias. |
| `Is(a)`, `Not(b)` or reverse | Reuse `AllocatedBit::xor(a,b)` and return `Not(x)`. | Same raw-bit row and `_NegatedBit(x)` output alias. |
| Constant zero | Return the other operand unchanged. | Return the other bit/alias unchanged. |
| Constant one | Return the other operand's Boolean negation. | Return the same complemented-bit alias or constant. |

Inputs remain Boolean-constrained by their producing relations (and external
input representations are constrained at admission). The XOR output does
not need a separate Boolean row: with Boolean inputs, the exact relation
forces `x` to their XOR and therefore to `{0,1}`. Regression tests exhaust all
four bit pairs for positive operands and all sixteen value/polarity
combinations for `Is`/`Not` operands. They inspect canonical A/B/C terms and
confirm raw output allocation precedes the row. Thirty-two-bit tests check
the bitwise result and all 32 relation rows; invalid input and output
assignments fail the Boolean or XOR constraints.

### One-block comparison and remaining structural differences

For a complete 512-bit variable message block, each implementation has 320
modular additions, 10,240 variable-variable XOR rows, and 512 input Boolean
rows. The addition equalities are packed into Bellman's 46 capacity-bounded
rows; XOR constants and `Is`/`Not` combinations are represented as aliases.
ZyCoin's raw `constrain_blake2s` now returns those Boolean aliases directly,
as Bellman's gadget does. It has **21,518 constraints** and matches Bellman's
pinned one-block constraint count and per-round profile. The truth-table and
matrix-row tests establish exact XOR-relation A/B/C terms; the count does not
establish whole-gadget matrix equivalence.

At the public Sapling wrappers, local scalar-multiplication and multipacking
interfaces still require allocated `Variable` bits. Consequently the IVK
wrapper materializes its used complemented digest bits (130 rows/columns)
and the nullifier wrapper materializes its complemented digest bits (136
rows/columns). Bellman's downstream gadgets consume `Boolean::Not` aliases
directly. These **266 adapter rows/columns** are not XOR-relation
differences; they are the remaining local Boolean-to-variable boundary
difference. The IVK's unused top five digest bits are not materialized. The
standalone wrappers measure 21,648 rows for IVK and 21,654 for nullifier
when their 512 preimage bits are each allocated and Boolean-constrained.

The independent pinned vectors include Bellman's empty-input `12345678`
personalized digest, Bellman's 512-one-bit test input with digest
`36a9a0bbcfc4e31b22a6e0d9cc4e2d37153950bda51aff8cd904d77057da5b65`,
the BLAKE2s known-answer vector, and the Sapling ZIP-32 IVK and nullifier
fixtures. Lengths 0, 1, 3, 63, 64, and 65 bytes still match Python
`hashlib`. No semantic discrepancy remains in the XOR truth table or its
individual A/B/C relation. Local allocation/constraint sequences outside a
single XOR row, the 266 wrapper adapters, and the absence of an authoritative
ordered complete upstream A/B/C export still prevent a whole-gadget or
whole-circuit equivalence claim.

### Current Spend dimensions and fingerprint

| Circuit | Phase 9.20.44 | Phase 9.20.45 | Phase 9.20.46 current |
|---|---|---|---|
| Spend rows / columns / fingerprint | 121,071 / 120,940 / `9cf4d3458d4bd02acfbdc179b031d9cdc7314d927f9310c4f118bb338f9add6f` | 121,337 / 121,206 / `1f586c7fb91c078feed5a8cadc00350665a4b2a0e6627dd8e402811e0a0e4d91` | 121,337 / 121,206 / `72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6` |
| Output rows / columns / fingerprint | 9,460 / 9,206 / `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` | 9,460 / 9,206 / `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` | 9,460 / 9,206 / `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` |

The Spend gap to Bellman's 98,777 rows is 22,560: 22,292 Pedersen rows,
266 BLAKE2s output-interface adapters, and two explicit local value/scalar
bindings. The BLAKE2s compression/XOR relation counts and semantics are
reconciled as described above; adapter rows remain. Output was not modified.
The local fingerprint remains a versioned change detector and is not proof
of correctness or compatibility. Sapling spending remains gated.

### Phase 9.20.45 verification

- CPython 3.10.11 full suite: **129 passed**; focused XOR, BLAKE2s, Spend,
  Output, and Sapling gadget suites: **49 passed**.
- `compileall`, targeted Ruff correctness checks, Pylance diagnostics for
  changed Python files, and Phase 9.20.45 whitespace checks passed.
- Wheel and sdist built successfully. The wheel installed into a clean target;
  the installed package reproduced the satisfied deterministic Spend witness,
  **121,337 rows / 121,206 columns**, and fingerprint
  `1f586c7fb91c078feed5a8cadc00350665a4b2a0e6627dd8e402811e0a0e4d91`.
  Packaged coin JSON resources and the sdist report were verified. Spending
  remains gated.

## Phase 9.20.46 — Full BLAKE2s compression matrix reconciliation

This phase compares ZyCoin's complete one-block, 512-variable-bit BLAKE2s
compression matrix against a Python transcription of Bellman 0.15.0's pinned
`blake2s.rs`, `uint32.rs`, `boolean.rs`, and `multieq.rs` synthesis. The
transcription is in [`tests/bellman_blake2s_reference.py`](../tests/bellman_blake2s_reference.py);
the regression compares complete `zycoin-r1cs-matrix-v1` bytes. Rows remain
ordered by synthesis, columns retain allocation order, and A/B/C terms are
canonicalized by column with duplicate coefficients combined modulo the
scalar field. The pinned source and dependency checksum are recorded in Phase
9.20.44 above. This is a source-derived Python reference, not a matrix file
exported by Bellman's Rust test runner; this provenance limit remains explicit.

### Complete compression result

The deterministic 64-byte all-`0xff` message with personalization
`12345678` matches the Bellman test setup, including 512 allocated input
bits, the 64-byte counter, final-block flag, ten rounds, and feed-forward.
The complete canonical matrix is byte-identical to the Python reference:
**21,518 rows, 21,473 columns** (implicit `ONE`, 21,472 auxiliaries), with
fingerprint
`fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785`.
The deterministic witness satisfies both systems. Repeated local synthesis
produces the same full matrix bytes. No row, column, coefficient, or
constraint-order mismatch remains for this one-block compression case.

| Component | Bellman transcription and ZyCoin matrix structure | Classification |
|---|---|---|
| Input allocation / Boolean rows | 512 input columns allocated in bit order; 512 Boolean rows precede compression. Each is `(1 - x) * x = 0`. | Exact after the Boolean row correction below. |
| `addmany` allocation | 10 rounds × (16 three-word sums × 34 bits + 16 two-word sums × 33 bits) = **10,720** result/carry columns; allocation follows each sum's low-to-high bit order. | Exact. |
| Addition output/carry Boolean rows | 10,720 rows in output/carry bit order, using `(1 - x) * x = 0`. | Exact after the Boolean row correction below. |
| Bounded `MultiEq` additions | 320 equalities batch into **46** rows at Bellman's 254-bit capacity; each row is `packed_lhs * ONE = packed_rhs`. | Exact after the packed-row correction below. |
| XOR outputs | 9,984 round XOR rows (768 in round zero, 1,024 in each later round) plus 256 feed-forward rows. Each dynamic bit uses `(2a) * b = a + b - x`; `Not` and constants remain aliases. | Exact. |
| Rotations | Right rotations 16/12/8/7 permute bit references without allocating columns or rows. | Exact. |
| Initialization / counter / finalization | IV and personalized initial state, counter-low XOR, final flag XOR, and `h[i] XOR v[i] XOR v[i+8]` feed-forward use identical constants, order, and alias handling. | Exact. |
| Totals | 512 input rows + 10,720 result/carry Boolean rows + 46 packed-addition rows + 10,240 XOR rows = **21,518 rows**; 512 + 10,720 + 10,240 = **21,472 auxiliary columns**. | Full canonical matrix match. |

The round ledger below excludes the 512 input Boolean rows and the 256
feed-forward XOR rows. The packed-row count reflects the exact point where
`MultiEq` flushes while processing additions; the final total includes the
last partial batch.

| Round | 3-word / 2-word additions | Addition Boolean rows / columns | XOR rows / columns | `MultiEq` rows | Round rows / columns |
|---:|---:|---:|---:|---:|---:|
| 0 | 16 / 16 | 1,072 / 1,072 | 768 / 768 | 5 | 1,845 / 1,840 |
| 1 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 5 | 2,101 / 2,096 |
| 2 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 4 | 2,100 / 2,096 |
| 3 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 5 | 2,101 / 2,096 |
| 4 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 4 | 2,100 / 2,096 |
| 5 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 5 | 2,101 / 2,096 |
| 6 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 4 | 2,100 / 2,096 |
| 7 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 5 | 2,101 / 2,096 |
| 8 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 5 | 2,101 / 2,096 |
| 9 | 16 / 16 | 1,072 / 1,072 | 1,024 / 1,024 | 4 | 2,100 / 2,096 |

### Structural corrections

The full comparison exposed two algebraically equivalent but structurally
different encodings that the prior count and XOR-only comparisons did not
detect:

1. Local Boolean rows used `x * (x - 1) = 0`. Bellman's `AllocatedBit`
   synthesizes `(1 - x) * x = 0`. ZyCoin now emits the upstream A/B/C
   placement for input and addition result/carry bits. This changes neither
   the Boolean relation nor its soundness.
2. Local packed additions used `(packed_lhs - packed_rhs) * ONE = 0`.
   Bellman's `MultiEq` emits `packed_lhs * ONE = packed_rhs`. ZyCoin now uses
   that exact placement for each flushed batch. The packing widths and
   capacity bound are unchanged; no equality was removed or weakened.

These were coefficient/linear-combination-placement differences, not
allocation, ordering, or semantic differences. After correction, every row
and column in the canonical one-block matrix matches the transcription.
Term spelling/order inside raw linear-combination builders is normalized by
the documented matrix serializer; duplicate columns are combined modulo the
field before byte comparison.

### Phase 9.20.45 wrapper increase ledger

The **266 rows and auxiliary columns** added to Spend in Phase 9.20.45 are
outside the compression matrix. Bellman's consumer APIs preserve `Boolean`
and `Boolean::Not` aliases; ZyCoin's current IVK and nullifier wrappers
materialize complemented digest bits because their downstream APIs accept
ordinary `Variable` bits:

| Consumer | Returned bits | Already ordinary | Complement aliases materialized | Added rows / columns |
|---|---:|---:|---:|---:|
| Sapling IVK (low 251 digest bits) | 251 | 121 | 130 | 130 |
| Sapling nullifier hash (256 digest bits) | 256 | 120 | 136 | 136 |
| **Total** | **507** | **241** | **266** | **266** |

Each adapter allocates one Boolean-valued column and enforces
`adapter + source = 1` with one equality row. These rows preserve the bit
value; they are not additions or differences within the compression circuit.
Eliminating them would require extending the downstream APIs to accept
complement aliases and is not part of this phase.

### Consumers, circuit dimensions, and evidence boundary

The IVK and nullifier ZIP-32/reference-vector tests still pass, as do
input/output/addition/carry mutation checks. The Spend relation dimensions
and row count are unchanged; only the matrix encoding fingerprint changes:

| Assembly | Rows / columns | Phase 9.20.45 fingerprint | Phase 9.20.46 fingerprint |
|---|---:|---|---|
| One-block BLAKE2s | 21,518 / 21,473 | Not recorded | `fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785` |
| Spend | 121,337 / 121,206 | `1f586c7fb91c078feed5a8cadc00350665a4b2a0e6627dd8e402811e0a0e4d91` | `72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6` |
| Output | 9,460 / 9,206 | `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` | Unchanged |

The matrix comparison covers the complete pinned one-block compression test
case, including initialization, all rounds, carries, permutations, and
feed-forward. It does not compare the full variable-length `blake2s`
multi-block wrapper against a Bellman-generated matrix, nor does it compare
the composed Spend matrix. The 266 adapter rows, 22,292 Pedersen rows, and
two explicit local bindings remain in the Spend-vs-Bellman shape accounting;
no whole-Spend equivalence, Groth16 readiness, or Sapling spending support is
claimed.

### Phase 9.20.46 verification

- CPython 3.10.11: **129 full-suite tests passed**; **20** focused
  BLAKE2s/Spend tests and **13** focused R1CS tests passed. The full ordered
  compression-matrix comparison, exact Boolean/MultiEq row assertions,
  repeat-synthesis determinism, witness satisfaction, and existing input,
  output, intermediate, and carry mutation checks passed.
- `compileall`, targeted Ruff, Pylance diagnostics for changed Python files,
  report-table/link checks, and whitespace checks passed.
- Wheel and sdist built successfully. The clean-target wheel installation
  reproduced the complete 21,518-row / 21,473-column compression matrix and
  matched its source-derived Bellman transcription byte-for-byte, with
  fingerprint
  `fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785`.
  Packaged coin JSON resources and the sdist regression reference/report
  were verified. Sapling spending remains gated.

## Phase 9.20.47 — Complete Sapling BLAKE2s hash gadget reconciliation

The test-only [`Bellman 0.15.0 Python transcription`](../tests/bellman_blake2s_reference.py)
now follows the complete `blake2s` wrapper, not just one compression: it
initializes the 32-byte unkeyed parameter state, applies the eight-byte
personalization to `IV[6..7]` in little-endian word order, divides the
little-endian input bits into 512-bit blocks and 32-bit words, zero-pads each
short final block, uses byte counters for non-final and final blocks, sets
the final flag only for the last block, feeds the compressed state forward
for subsequent blocks, and emits all eight result words least-significant
bit first. The pinned source references and dependency checksum are listed
in Phase 9.20.44. The transcription remains a Python source-derived reference,
not an A/B/C matrix exported by a Rust Bellman runner.

### Complete hash matrix cases

The matrix tests allocate all message bit variables first, add Bellman-style
input Boolean admission rows, and synthesize the full local and reference
hashes. This mirrors Bellman's caller-provided `Boolean` input boundary for
an isolated hash. In the composed Spend circuit, `ak`, `nk`, and `rho`
representations are already constrained; its hash calls set
`input_bits_preconstrained=True` to avoid redundant Boolean rows. The
standalone matrix fingerprints below therefore describe complete hashes
with explicit input admission, not a reconstruction of the enclosing Spend
input relations.

| Complete hash configuration | Preimage and digest evidence | Matrix dimensions | Fingerprint |
|---|---|---:|---|
| Sapling IVK, `Zcashivk` | Pinned ZIP-32 vector with `ak` followed by `nk`; low 251 output bits match the fixture's IVK. | 21,518 rows / 21,473 columns | `1ec15b1eb11bc673d71aa761acb8e396a4bb74a5945940d302cfbfa6a429cc0d` |
| Sapling nullifier PRF, `Zcash_nf` | Pinned note vector with `nk` followed by `rho`; complete 256-bit digest matches `note_nf`. | 21,518 rows / 21,473 columns | `701c5a72f19a024a3f7b436f5364820efa4a824364b00753c9a06ef04d2ef569` |

For each configuration, the complete canonical serialized matrix from
ZyCoin equals the reference byte-for-byte, including ordered rows, columns,
and normalized coefficients. The preimage fixture and personalization
produce the same expected digest under the reference and independent pinned
vector. These remain source-transcription comparisons and do not imply
equivalence of the upstream callers or complete Spend matrix.

Full-hash matrix comparisons also cover input lengths **0, 1, 63, 64, 65,
127, 128, and 129 bytes**. These cases exercise empty-message synthesis,
partial word and block padding, exact one- and two-block final counters,
full non-final blocks followed by partial final blocks, and three-block
chaining with counters 64 and 128 before the 129-byte final counter.
Local/reference matrix bytes, output bytes, and witness satisfaction match in
each case. Existing
tampering tests continue to reject changed input, digest/output, modular-sum
bit, and carry assignments.

The one-block all-`0xff` compression test remains unchanged at 21,518 rows,
21,473 columns, fingerprint
`fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785`.
Since Phase 9.20.47 changed only the test reference and regression coverage,
the Spend assembly remains 121,337 rows / 121,206 columns with fingerprint
`72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6`.
The 266 wrapper adapters, 22,292 Pedersen rows, and two local bindings
remain; neither hash-level result proves whole Spend equivalence, Groth16
readiness, or spending support.

### Phase 9.20.47 verification

- CPython 3.10.11 full suite: **132 passed**. Focused suites: **19 BLAKE2s**,
  **4 Spend**, and **13 R1CS tests passed**. All eight block-boundary
  subcases and both Sapling-config matrix fingerprints pass.
- `compileall`, targeted Ruff, Pylance diagnostics for changed Python files,
  report-link/table checks, `git diff --check`, and changed-file whitespace
  checks passed.
- Final wheel and sdist build and clean-target installation confirmed after
  report updates; the installed package reproduced both Sapling hash matrix
  fingerprints and the complete 21,518-row compression matrix.

## Phase 9.20.48 — Sapling Spend Pedersen composition reconciliation

### Consumers and pinned source trace

The Spend synthesis has two Pedersen consumers:

1. The note-content hash uses `Personalization::NoteCommitment` and the
   576-bit message `value || repr(g_d) || repr(pk_d)`. Its output is then
   combined with the note-randomness fixed-base multiplication to form the
   note commitment.
2. The 32-level authentication path uses `Personalization::MerkleTree(depth)`
   and `left || right`, with 255 bits per child. Every level has 510 message
   bits and a depth-specific six-bit prefix.

The nullifier-related relations do not invoke Pedersen: the circuit derives
`rho = cm + [position]J`, constrains its point representation, and passes
`nk || rho` to the `Zcash_nf` BLAKE2s gadget. Note-commitment randomization
is a separate fixed-base multiplication and point addition.

The source trace is pinned to
[`sapling-crypto` 0.9.0, commit `88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/tree/88a7946b4a3066787776e11f0a502654167e022d):
`src/circuit/pedersen_hash.rs` defines the six-bit personalization and
segments of 63 three-bit windows; `src/circuit/ecc.rs` defines Montgomery
lookup additions and conversion to Edwards coordinates;
`src/circuit/constants.rs` derives the four-entry signed lookup tables from
the Sapling segment generators; and `src/circuit.rs` wires the note and
Merkle consumers. The dependency lock pins Bellman 0.15.0 with checksum
`973b16549796a1274a63e00159a03250e66e8263e2ac6344b1c9fdfe9b7a8325`.
Bellman's relevant lookup construction is in
[`gadgets/lookup.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/lookup.rs).

### Source-derived complete matrix comparisons

[`tests/bellman_pedersen_reference.py`](../tests/bellman_pedersen_reference.py)
transcribes the upstream allocation and enforcement order into the Python
R1CS builder: the low-two-bit lookup and sign bit, `a AND b` precomputation,
Montgomery affine additions within each segment, the two-row segment
conversion, and Edwards additions between segments. Its window coordinates
are generated from the pinned Sapling group-hash generators and Montgomery
map. The reference is test-only Python and is **not** a Bellman-exported
matrix.

The regression allocates the same message-bit columns and caller-side
Boolean admission rows before each implementation, synthesizes both complete
Pedersen matrices, compares their full canonical ordered A/B/C serializations,
and verifies the two results against the same note or path witness. Matrix
bytes are intentionally unequal; this comparison does not imply
primitive-level matrix equivalence. The NoteCommitment case is the actual
deterministic Spend note witness. All 32 Merkle cases use the Spend path
witness with their distinct depth personalization. Existing pinned upstream
empty/one-bit and Merkle vectors remain the independent point-output checks.

| Isolated configuration (including message-bit admission) | ZyCoin rows / columns | Bellman transcription rows / columns | ZyCoin fingerprint | Reference fingerprint |
|---|---:|---:|---|---|
| NoteCommitment, 576 message bits | 2,314 / 2,315 | 1,558 / 1,559 | `94febbae8187b627cc2fc95f6d923f3ce25ff45946d738d4310a9e14274b79d2` | `b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76` |
| MerkleTree(25), 510 message bits | 2,050 / 2,051 | 1,377 / 1,378 | `686c70259fd8cbf046c4cde6eee4510a0b84d0ab6dd7888107a157be10254185` | `706c8e1c013c93d98a05a0c47f43dc048d67bb3817e8623001bfc79b7b7c8c86` |

These are complete isolated-hash matrices, not complete Spend matrices:
Spend's caller has already constrained the value, point-representation, and
Merkle child bits, and the witness variables are shared with adjacent
relations. The test verifies the full serialized matrices for all 32 depth
prefixes, point outputs, witness satisfaction, tampering rejection, and
determinism at the 510- and 576-bit boundaries.

### Structural and composition ledger

| Spend Pedersen consumer | Windows by segment | ZyCoin lookup rows | Bellman lookup rows | ZyCoin within-segment Edwards additions | Bellman within-segment Montgomery additions | Bellman segment conversions | Segment-combination rows, both | Internal-row delta |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| NoteCommitment | `[63, 63, 63, 5]` | 580 | 386 | 1,140 | 570 | 8 | 18 | +756 |
| Each MerkleTree(depth) | `[63, 63, 46]` | 514 | 342 | 1,014 | 507 | 6 | 12 | +673 |
| All 32 Merkle levels | 32 × `[63, 63, 46]` | 16,448 | 10,944 | 32,448 | 16,224 | 192 | 384 | +21,536 |
| **Spend Pedersen total** |  |  |  |  |  |  |  | **+22,292** |

The principal differences are structural, not hash semantics. ZyCoin
allocates an Edwards `(u, v)` pair for every window and uses three lookup
rows for a variable window; Bellman keeps the Montgomery `x` lookup as a
linear combination, allocates `y`, and uses the conditional-sign lookup
relation plus its precomputation. ZyCoin's affine Edwards additions use six
rows per within-segment addition; Bellman's Montgomery additions use three.
Bellman then spends two rows per segment converting to Edwards coordinates.
Both implementations use six rows per between-segment Edwards addition.
Their variable allocation order and the placement of these rows also differ,
so equal host points and counts would not establish ordered matrix identity.

The 22,292-row Pedersen difference composes into the existing Spend shape;
there are no extra Pedersen calls in nullifier derivation and no duplicate
Pedersen relation within a hash. The existing report-level Spend gap also
includes the 266 BLAKE2s output-interface adapters and two local bindings.
No safe source-backed Pedersen structural correction was identified in this
phase; no production implementation or Output semantics changed.

The full Spend remains **121,337 rows / 121,206 columns**, fingerprint
`72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6`.
The BLAKE2s one-block compression fingerprint remains
`fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785`;
the complete IVK and nullifier hash fingerprints remain
`1ec15b1eb11bc673d71aa761acb8e396a4bb74a5945940d302cfbfa6a429cc0d`
and `701c5a72f19a024a3f7b436f5364820efa4a824364b00753c9a06ef04d2ef569`.
These primitive-level comparisons do not establish whole Spend matrix
equivalence, Groth16 readiness, or Sapling spending support.

### Phase 9.20.48 verification

- CPython 3.10.11 full suite: **133 passed**. The focused Pedersen, Spend,
  BLAKE2s, and R1CS suites passed **66 tests**; the final added upstream
  Pedersen-vector assertion also passed in a targeted rerun.
- `compileall`, targeted Ruff, Pylance diagnostics for both changed Python
  files, `git diff --check`, and report whitespace/table checks passed.
- Wheel and sdist built successfully in an isolated staging copy. A
  clean-target wheel installation imported the documented `zycoin` modules
  and accessed packaged coin JSON; the sdist contains the Python reference
  and updated circuit report.
- The source-derived matrix test compares every ordered A/B/C coefficient
  through the canonical matrix serialization; the output is explicitly not
  an upstream Bellman matrix export.

## Phase 9.20.49 — Spend explicit bindings and composition audit

### Upstream synthesis and binding classifications

The two rows previously attributed to local bindings were the `ar` scalar
reconstruction and note-value reconstruction. Both rows were needed only
because the local assembly introduced scalar variables that upstream does not
allocate. The pinned Spend source at
[`circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
shows the upstream boundaries:

| Binding | Pinned upstream synthesis | Previous ZyCoin composition | Classification and disposition |
|---|---|---|---|
| `ar` and its 252 Boolean bits | `Spend::synthesize` calls `boolean::field_into_boolean_vec_le` on `self.ar` and passes those bits directly to fixed-base multiplication. No separate `ar` variable is allocated or reconstructed. | Allocated a private `ar`, range-checked it into 252 Boolean bits, and added one reconstruction row. The scalar variable was otherwise unused. | Additional local consistency row, necessary only to link the otherwise-unused scalar variable to its bit encoding. Removed the scalar variable; direct private Boolean bits now feed the same multiplication. Host admission still requires a canonical Jubjub scalar, matching the upstream field type. |
| Note value and its 64 Boolean bits | `expose_value_commitment` returns `u64_into_boolean_vec_le` bits. Spend accumulates those exact bits into `value_num` using `Num::add_bool_with_coeff` and uses the same bits in the note hash. | Allocated a private note-value scalar, added one equality row to the 64-bit opening, then used the scalar for the conditional anchor. | Additional local consistency row, necessary only to prevent substitution of a separate scalar witness. Removed the scalar variable and row; the conditional anchor now uses the linear combination of the same constrained value bits, matching upstream's `Num`. |

Bellman's `field_into_boolean_vec_le` delegates to bit allocation and does
not add a separate scalar reconstruction. Its `u64_into_boolean_vec_le`
allocates the 64 Boolean bits directly. The upstream Spend assembly also has
no independent note-value variable: the `Num` is an expression over the
opening bits. These source facts justify the two local structural corrections;
they do not authorize any weakening of the value, scalar-bit, multiplication,
or conditional-anchor relations.

In the previous local allocation, the `ar` scalar appeared only as the input
to `range_check`; its resulting bits were the actual fixed-base multiplication
inputs. The separate note-value variable was only consumed by the conditional
anchor, while its 64 value bits were independently consumed by the value
commitment and Pedersen message. The respective equality rows were therefore
the only circuit links between those scalar temporaries and the bit-level
relations. The revised assembly removes those temporaries and routes the
existing bit decomposition directly to every consumer.

### Isolated adversarial evidence

[`tests/test_sapling_spend_bindings.py`](../tests/test_sapling_spend_bindings.py)
builds isolated R1CS witnesses for both cases:

- The direct-bit `ar` assembly satisfies the same randomized-key witness as
  the legacy scalar-variable form with one fewer row and one fewer column.
  Flipping an `ar` bit or changing the public randomized key violates the
  relation. A repeated direct synthesis has identical canonical matrix bytes.
- With a separately allocated note-value scalar, removing its equality allows
  a nonzero 64-bit opening to coexist with a forged scalar zero and a mismatched
  root/anchor; the conditional-anchor row then accepts that substituted
  witness. Keeping the equality rejects it. The revised composition instead
  supplies the bit-derived linear combination directly; a nonzero value with
  mismatched root and anchor is rejected, a zero value retains the intended
  dummy-note behavior, and bit tampering is rejected. This form removes the
  scalar column and its equality row rather than dropping the relation.

### Complete Spend composition and current shape

The composition audit found shared variables passed directly between the
existing relations rather than recomputed openings: the `ar` bits feed the
randomization multiplication; `value_bits` feed both the value commitment and
note-content hash and define the anchor expression; the same `g_d`, `pk_d`
representation, `ak`/`nk` representations, note commitment, Merkle position
bits, and nullifier digest bits flow to their consuming relations. `rcv`,
`rcm`, path siblings, and intermediate path hashes are each allocated for
their single intended relation chain. The regression checks every allocated
Spend witness variable for an incident relation and mutates representative
variables and all public inputs. No repeated Pedersen/BLAKE2s consumer or
inconsistent duplicate witness sharing was found.

The two scalar variables and their two reconstruction rows are gone. The
relation totals are now:

| Spend relation group | Rows |
|---|---:|
| `ak` and randomized authorization key | 1,030 |
| `nsk`, `nk`, point representations, and IVK | 23,690 |
| `g_d` and `pk_d` | 4,048 |
| Value commitment and note commitment | 4,787 |
| Merkle path, position, and conditional anchor | 65,762 |
| `rho`, nullifier PRF, and multipacking | 22,018 |
| **Spend total** | **121,335** |

The current matrix has **121,335 rows / 121,204 columns**, fingerprint
`73160f3bdcaff7a2a98fd62eab5cabc856224203239d4e757bf666dee3bc8733`.
This is two fewer rows and columns than the prior Phase 9.20.48 assembly.
The remaining 22,558-row difference from pinned Bellman's 98,777 Spend rows
is 22,292 Pedersen structure rows plus 266 BLAKE2s interface-adapter rows;
the two explicit local bindings are no longer part of the gap. Pedersen and
BLAKE2s fingerprints are unchanged. This source analysis and the existing
Python reference transcriptions are not an exported Bellman Spend matrix and
do not establish whole-circuit matrix equivalence or Groth16 eligibility.
Sapling spending remains gated.

### Phase 9.20.49 verification

- CPython 3.10.11 full suite: **135 passed**. The focused isolated-binding,
  complete Spend, and pinned note-commitment tests passed **7 tests**.
- `compileall`, targeted Ruff, Pylance diagnostics for all four changed
  Python files, Pylance signature-compatibility checks for all changed
  call surfaces, and report whitespace/table checks passed.
- `git diff --check` passed. Wheel and sdist built successfully; the clean
  target imported the packaged Spend modules and loaded coin JSON resources.
  The sdist contains the binding regressions and this updated circuit report.

## Phase 9.20.50 — Spend Pedersen and BLAKE2s composition reconciliation

### Composed row and auxiliary-column ledger

The pinned Spend totals **98,777 rows**. Current ZyCoin is **121,069 rows**,
so the exact remaining count difference is **22,292**. In the complete
composition the BLAKE2s wrapper output adapters are now passed as Bellman-like
complement aliases; their rows/columns are zero. The following table separates
rows emitted by each hash body from message-bit admission rows. In Spend, the
message bits are already Boolean-constrained by point representations,
value-opening bits, or Merkle child range checks.

| Composed gadget boundary | Call count | Input bits per call | Isolated local rows (incl. input admission) | Isolated Bellman-Python reference rows (incl. input admission) | Local rows in Spend (input admission reused) | Reference rows in Spend | Auxiliary columns per call, local / reference | Extra local rows |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| NoteCommitment Pedersen | 1 | 576 | 2,314 | 1,558 | 1,738 | 982 | 1,738 / 982 | +756 |
| MerkleTree(depth) Pedersen | 32 | 510 | 2,050 | 1,377 | 1,540 | 867 | 1,540 / 867 | +673 each |
| Sapling IVK BLAKE2s, `Zcashivk` | 1 | 512 | 21,518 | 21,518 | 21,006 | 21,006 | 20,960 / 20,960 | 0 |
| Nullifier PRF BLAKE2s, `Zcash_nf` | 1 | 512 | 21,518 | 21,518 | 21,006 | 21,006 | 20,960 / 20,960 | 0 |
| IVK output boundary adapters | 1 | 251 | 130 | 0 | 0 | 0 | 0 / 0 | 0 |
| Nullifier output boundary adapters | 1 | 256 | 136 | 0 | 0 | 0 | 0 / 0 | 0 |
| **Spend Pedersen total** |  |  |  |  | **51,018** | **28,726** | **51,018 / 28,726** | **+22,292** |
| **Spend BLAKE2s plus adapters** |  |  |  |  | **42,012** | **42,012** | **41,920 / 41,920** | **0** |

The 51,018 versus 28,726 Pedersen row totals include no repeated caller
Boolean admission: `1,738 + 32 × 1,540` and `982 + 32 × 867`, respectively.
The Pedersen structural delta is `756 + 32 × 673 = 22,292`. The BLAKE2s
isolated hash rows include 512 input-Boolean rows per call; in the enclosing
Spend, those 1,024 rows are already supplied by their input gadgets, leaving
21,006 body rows for each hash on both sides. Each hash has 20,960 auxiliary
columns beyond the implicit ONE and 512 shared input columns. The adapter
rows/columns previously measured as 130 IVK bits and 136 nullifier bits were
only materializations of a complemented bit alias; they are not part of the
hash compression or digest semantics.

The old equality adapters did not duplicate a BLAKE2s compression row: each
one linked a newly allocated ordinary variable to an already-defined
complement alias, because the old downstream signatures accepted only
variables. That link was necessary while the adapter variable was the
consumer input, but it does not add a new hash or consumer relation. The
revised consumer equations use the alias expression directly, retaining both
the upstream Boolean/hash constraints on its backing bit and the downstream
scalar/packing equation without allocating the intermediary.

The per-component row ledger (excluding repeated input admission) is:

| Spend row range / component | Local rows | Bellman transcription/source count | Delta |
|---|---:|---:|---:|
| Randomized authorization key | 1,030 | 1,030 | 0 |
| `nsk`, `nk`, point representations excluding IVK hash | 2,554 | 2,554 | 0 |
| IVK BLAKE2s hash body | 21,006 | 21,006 | 0 |
| `g_d` and `pk_d` | 4,048 | 4,048 | 0 |
| Value commitment, note randomness multiplication/addition, excluding Pedersen | 3,049 | 3,049 | 0 |
| NoteCommitment Pedersen | 1,738 | 982 | +756 |
| Merkle selection/range/anchor relations, excluding Pedersen | 16,482 | 16,482 | 0 |
| 32 depth-personalized Merkle Pedersen hashes | 49,280 | 27,744 | +21,536 |
| `rho` construction/representation and nullifier multipacking, excluding hash | 876 | 876 | 0 |
| Nullifier BLAKE2s hash body | 21,006 | 21,006 | 0 |
| **Total** | **121,069** | **98,777** | **+22,292** |

These are row counts only; column order and variable allocation are not
claimed to match upstream. The isolated Pedersen auxiliary-column figures are
1,738 local versus 982 reference for NoteCommitment, and 1,540 versus 867
for each Merkle invocation. The complete isolated BLAKE2s hash uses 20,960
auxiliary columns per configuration on both sides. In the complete Spend,
message and representation columns are shared with their producer relations,
so those isolated auxiliary counts must not be added as if each invocation
allocated a new copy of its input.

### Adapter and witness-sharing audit

`constrain_blake2s` can return `_NegatedBit` aliases where Bellman's Boolean
API would return `Boolean::Not(AllocatedBit)`. The default wrapper behavior
still materializes these bits for callers that require ordinary `Variable`
objects. Spend opts out: the 251 IVK bits flow directly into the shared
variable-base `[ivk]g_d` and fixed-base lookup relations, and all 256 nullifier
bits flow directly into little-endian multipacking. The scalar, lookup, and
packing equations now accept the affine bit expression `1 - backing_bit`;
they do not allocate conversion columns or rows.

The isolated regression in
[`tests/test_sapling_spend_bindings.py`](../tests/test_sapling_spend_bindings.py)
compares both materialized and alias-preserving hash-to-consumer matrices.
It also compares the complete local alias-preserving hash-to-consumer matrices
byte-for-byte with the existing source-derived Bellman Python transcription
for both `Zcashivk` followed by `[ivk]G` and `Zcash_nf` followed by public
multipacking. These are transcription comparisons, not Rust-exported Bellman
matrices. Both materialized and alias-preserving variants satisfy and produce
identical Jubjub results / public packed chunks; the materialized variants
have exactly 130 and 136 additional rows and columns. Repeated
alias-preserving synthesis produces identical matrix bytes. Flipping a
backing variable for a complemented bit violates the source hash constraints,
and output/public-result mutations violate the downstream consumer relations.
The complete Spend test also checks that no IVK/nullifier output-complement
rows are present and mutates representative variables from both outputs.

Input sharing is preserved: the 512 IVK bits are the existing constrained
representations of `ak || nk`; the nullifier hash uses the existing `nk || rho`
representation bits. NoteCommitment consumes the same 64 value bits used in
the value commitment and anchor expression, while each Merkle hash consumes
its selected, range-constrained child bits. The 32 depth-personalized Merkle
instances remain distinct and no additional Pedersen call is introduced.
The existing source-derived Python Bellman transcriptions compare all
NoteCommitment/Merkle matrices and complete BLAKE2s wrapper configurations;
these tests are not upstream Rust matrix exports.

### Current Spend dimensions and evidence boundary

| Spend relation group | Local rows after Phase 9.20.50 | Pinned Bellman rows | Difference |
|---|---:|---:|---:|
| `ak` and randomized authorization key | 1,030 | 1,030 | 0 |
| `nsk`, `nk`, point representations, and IVK | 23,560 | 23,560 | 0 |
| `g_d` and `pk_d` | 4,048 | 4,048 | 0 |
| Value commitment and note commitment | 4,787 | 4,031 | +756 |
| Merkle path, position, and conditional anchor | 65,762 | 44,226 | +21,536 |
| `rho`, nullifier PRF, and multipacking | 21,882 | 21,882 | 0 |
| **Total** | **121,069** | **98,777** | **+22,292** |

The final Spend matrix has **121,069 rows / 120,938 columns** (including the
implicit ONE column), fingerprint
`bf491500c18a6c2fbe1605f4921c0163a44c24d5b07a2271fad851cd00d493a2`.
Compared with Phase 9.20.49, this removes all 266 BLAKE2s output adapter
rows and columns; the remaining difference is exactly the Pedersen
lookup/addition structural delta documented in Phase 9.20.48. Counts and
component-level source-derived matrix comparisons do not prove whole Spend
equivalence. No authentic-parameter eligibility or spending support is
claimed; Sapling spending remains gated.

### Phase 9.20.50 verification

- CPython 3.10.11 `pytest -q`: **137 passed**. The first
  `unittest discover` attempt collected zero tests because this repository's
  tests are run through pytest; pytest was used for the complete suite.
- Focused Spend, BLAKE2s, Pedersen, and R1CS selection: **70 passed**.
- The isolated IVK-to-scalar and nullifier-to-multipacking matrices match
  their source-derived Bellman Python transcriptions byte-for-byte;
  materialized-boundary tests measure exactly 130/136 excess rows and
  columns. The complete Spend witness and complemented-bit/public-output
  mutation tests passed.
- Ruff passed on the changed Python files. Pylance diagnostics are clear for
  changed source and test files after cleanup, and signature-compatibility
  checks passed for all five changed public/internal consumer signatures.
- `compileall` passed. Wheel and sdist builds passed; installing the wheel
  into a clean target succeeded, with documented package imports, all eight
  coin JSON resources, and all nine wordlist resources accessible. The sdist
  contains the updated circuit report and regression test. `git diff --check`
  passed.

## Phase 9.20.51 — Pedersen constraint-structure reconciliation

The audit revisited pinned
[`pedersen_hash.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/pedersen_hash.rs),
[`circuit/pedersen_hash.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/pedersen_hash.rs),
[`circuit/ecc.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs),
[`circuit/constants.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/constants.rs),
and Bellman 0.15.0's
[`gadgets/lookup.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/lookup.rs).
`tests/bellman_pedersen_reference.py` is a source-derived Python
transcription, not an upstream-exported matrix. Its loop, table, and equation
structure was checked against these pinned sources and Bellman's pinned
`ph_num_constraints` assertions.

### Transcription and source-structure check

The transcription matches the pinned construction for the six constant
little-endian personalization bits followed by message bits; three-bit
little-endian chunks with false terminal padding; 63-window segment breaks;
the four-entry signed lookup table; and the segment generator tables. The
host algorithm uses the same digit `(1 + a + 2b) * (-1)^c` and advances the
window base by 16. The circuit tables are the pinned Montgomery
representations of the same generator multiples.

At synthesis, the transcription follows Bellman's conditional lookup:
`a*b` precomputation, a linear-expression Montgomery `x`, allocated and
conditionally-negated Montgomery `y`, followed by affine Montgomery
addition. Its three addition equations allocate lambda, x-prime, and
y-prime. Per-segment Montgomery-to-Edwards conversion allocates `u` and `v`
and constrains each with one equation. Segment results are then combined
with the six-equation Edwards addition (`U`, `A`, `B`, `C`, `u3`, `v3`).
These equations agree with the corresponding pinned `ecc.rs` formulas.
This source review increases confidence in the transcription's relation and
count model; it does not turn its generated matrices into Bellman matrices.

ZyCoin uses the same input chunking, personalization, generators, and signed
digit, but keeps selected points and within-segment sums in Edwards
coordinates. Each local lookup allocates both selected coordinates and uses
one constrained precomputation plus two coordinate equations. Local
within-segment affine Edwards additions use six rows and six allocated
values. It does not convert each segment before combining. Final segment
combination uses the same six-row Edwards relation as the transcription.
Both implementations constrain every returned coordinate through these
relations; there is no evidence that either implementation has removable
rows without changing the relation.

For `N = ceil((6 + message_bits) / 3)` windows and `S = ceil(N / 63)`
segments, the Spend cases have no terminal partial windows. The accounting
excludes message Boolean rows, which are supplied by the enclosing circuit:

| Structure | ZyCoin rows/columns | Bellman transcription rows/columns | Local minus reference |
|---|---:|---:|---:|
| Lookup windows | `3N - 2` | `2N - 2` | `N` |
| Within-segment additions | `6(N - S)` | `3(N - S)` | `3(N - S)` |
| Segment conversion | `0` | `2S` | `-2S` |
| Segment combinations | `6(S - 1)` | `6(S - 1)` | `0` |
| **Total** |  |  | **`4N - 5S`** |

Lookup precomputation is shared in row count and allocation except that the
first two windows have constant personalization inputs, so neither side
allocates an AND variable there. ZyCoin allocates two lookup coordinates per
window while Bellman's Montgomery `x` remains a linear combination and only
`y` is allocated; this accounts for one additional lookup column per window.
The addition and conversion allocation deltas follow the same counts as
their rows. Thus the reported column difference is also `4N - 5S`.

| Spend Pedersen configuration | Message bits | Windows `N` | Segments `S` | ZyCoin rows / auxiliary columns | Bellman rows / auxiliary columns | Difference |
|---|---:|---:|---:|---:|---:|---:|
| NoteCommitment | 576 | 194 | 4 | 2,314 / 1,738 | 1,558 / 982 | **756** |
| Each MerkleTree(depth), depth 0–31 | 510 | 172 | 3 | 2,050 / 1,540 | 1,377 / 867 | **673** |
| 32 Merkle configurations | 16,320 total | 5,504 total | 96 total | 65,600 / 49,280 | 44,064 / 27,744 | **21,536** |
| **Spend total** |  |  |  |  |  | **22,292** |

The calculation is `4*194 - 5*4 = 756` for NoteCommitment and
`4*172 - 5*3 = 673` for every Merkle depth. The depth changes only the
six-bit personalization value and generator table selection; it does not
change window or segment counts. Existing tests synthesize all 32 distinct
Merkle personalizations and check each local/reference output and matrix;
the note and Merkle boundary/vector tests also check the source transcription
against pinned point/count expectations. The composed Spend relation ledger
therefore remains 121,069 rows / 120,938 columns with fingerprint
`bf491500c18a6c2fbe1605f4921c0163a44c24d5b07a2271fad851cd00d493a2`.

No Pedersen constraint was removed or altered in this phase: the exact
structural differences are due to Edwards versus Montgomery intermediate
representations and their different addition/conversion allocation, not
identified redundant constraints. Output semantics were not changed. The
transcription and isolated matrices are not authoritative ordered Bellman
exports; no whole Spend equivalence or Groth16 eligibility is claimed.
Sapling spending remains gated.

### Phase 9.20.51 verification

- CPython 3.10.11 full pytest suite: **137 passed**. Focused Pedersen/vector/
  Merkle selection: **8 passed**; Spend assembly and R1CS suites: **17
  passed**.
- The all-consumer regression asserts the source-derived `4N - 5S`
  difference for both rows and auxiliary columns for NoteCommitment and all
  32 depth-personalized Merkle cases, in addition to the prior vectors,
  satisfaction, and adversarial-mutation checks.
- `compileall`, targeted Ruff, and `git diff --check` passed. Pylance
  diagnostics were empty for the changed gadget and test; signature
  compatibility passed for `constrain_pedersen_hash` and all five call sites.
- Wheel and sdist builds passed. A clean-target wheel installation imported
  the Sapling gadget/Spend modules and accessed all eight coin JSON and nine
  wordlist resources. The sdist contains the updated circuit and Groth16
  reports and Pedersen regression test.

## Phase 9.20.52 — Montgomery-representation Pedersen alignment

This addendum supersedes the earlier current-Spend Pedersen gap and the
121,069-row Spend measurement above. The existing Edwards Pedersen path
remains the default for standalone callers and Sapling Output. Spend opts
into the new pure-Python Montgomery-intermediate path through
`pedersen_representation="montgomery"` for its NoteCommitment and 32 Merkle
hashes. The circuit relation, personalization, generators, bit order, and
segment/window boundaries are unchanged.

### Montgomery synthesis and parity evidence

The new path follows the pinned Bellman construction in the earlier
Phase 9.20.51 source references:

1. For each three-bit window, use the four positive table multiples
   selected by `a + 2b`; constrain the `a*b` precomputation, retain the
   Montgomery `x` as a linear combination, allocate signed Montgomery `y`,
   and enforce `2*y_lookup*sign = y_lookup - y_allocated`.
2. For each within-segment addition, allocate `lambda`, `xprime`, and
   `yprime` in Bellman's order and enforce the three affine Montgomery
   equations.
3. Convert each segment to Edwards by allocating `u = scale*x/y` and
   `v = (x-1)/(x+1)`, each with its pinned equation. Convert each segment
   before combining it with the running Edwards accumulator using the six
   `U/A/B/C/u3/v3` equations.

The generator table is derived from the shared configured Jubjub points;
the regression compares every generated Montgomery table entry with the
existing source-derived Bellman table. The focused matrix test constructs
the note case and each of the 32 Merkle personalization depths with the
Edwards implementation, Montgomery implementation, and source-derived
Python transcription. For all 33 configurations, it asserts:

- The Montgomery result equals both the Edwards result and the expected
  pinned host point, with a satisfied R1CS witness.
- Canonical serialized ordered A/B/C matrix bytes and local fingerprints
  equal the transcription, and row and variable counts match exactly.
- Mutating a note input bit or final output coordinate violates the
  Montgomery constraints. Additional sign-bit, selected lookup ordinate,
  Montgomery addition slope, segment-conversion coordinate, and
  segment-combination intermediate mutations all violate constraints.

These are component-level comparisons against a Python transcription, not
an actual Bellman matrix export.

### Spend shape after integration

The isolated Pedersen rows and auxiliary columns now match the
source-derived reference for each composed configuration:

| Spend Pedersen configuration | Calls | ZyCoin rows / auxiliary columns | Bellman transcription rows / auxiliary columns |
|---|---:|---:|---:|
| NoteCommitment | 1 | 1,558 / 982 | 1,558 / 982 |
| MerkleTree, each depth 0–31 | 32 | 1,377 / 867 | 1,377 / 867 |
| **All Spend Pedersen calls** | **33** | **45,622 / 28,726** | **45,622 / 28,726** |

Spend now measures **98,777 rows / 98,646 columns**, fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
The 22,292 rows and auxiliary columns removed from the previous local Spend
shape are precisely the prior Edwards-versus-Montgomery Pedersen delta.
The R1CS fingerprint test, complete deterministic witness, all 33 isolated
Pedersen matrices, and unchanged Output/standalone Edwards tests pass.

Matching the pinned total row count and matching source-derived component
matrices do **not** establish whole Spend matrix identity or authentic
Groth16 parameter eligibility. There is still no authoritative ordered
upstream whole-circuit matrix export and no proof of exact whole-circuit
variable allocation/order. Sapling spending remains gated; Output semantics
are unchanged.

### Phase 9.20.52 verification

- CPython 3.10.11 full pytest suite: **137 passed**. Focused
  Pedersen/Spend/R1CS suites: **47 passed**.
- The all-consumer regression verifies matrix bytes, fingerprints, output
  points, and row/column counts across NoteCommitment and all 32 Merkle
  configurations. Adversarial input, sign-bit, lookup, Montgomery-add,
  conversion, segment-combination, and final-output mutations were rejected.
- `compileall`, targeted Ruff, and `git diff --check` passed. Pylance
  diagnostics were empty for changed source/tests; signature compatibility
  passed for the three updated public gadget APIs and all discovered callers.
- Wheel and sdist builds passed. A clean-target wheel installation imported
  the changed Sapling modules and accessed all eight coin JSON and nine
  wordlist resources; the sdist contains updated reports and tests.

## Phase 9.20.53 — Complete Spend composition reconciliation

The complete Spend assembler was synthesized twice from the same deterministic
independent witness. In the second synthesis, only the Pedersen and BLAKE2s
gadget entry points were replaced by the existing pinned-source-derived
Python transcriptions: all 33 Spend Pedersen calls (NoteCommitment and 32
depth-specific Merkle hashes) and both Sapling BLAKE2s configurations
(`Zcashivk` and `Zcash_nf`). The remaining Spend relations and the outer
composition use the existing ZyCoin implementations in both syntheses.

### Complete local composition comparison

The comparison verifies that the composed transcriptions preserve the full
local Spend matrix, not merely isolated component counts:

- The ordered six relation-group constraint counts are identical.
- Both syntheses have **98,777 rows**, **98,646 columns** including `ONE`,
  seven application public inputs, and 98,638 auxiliary columns.
- The implicit `ONE` and local public-first prefix (`rk.u`, `rk.v`, `cv.u`,
  `cv.v`, `anchor`, `nullifier_chunk_0`, `nullifier_chunk_1`) are unchanged.
- Canonical serialized ordered A/B/C matrices are byte-for-byte identical;
  both have fingerprint
  `f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
- The deterministic witness satisfies both systems.

This full-assembly substitution regression covers the boundaries, row order,
column allocation, and shared-variable wiring of the transcribed Pedersen
and BLAKE2s components in ZyCoin's assembly. It finds no adapter rows,
omitted calls, duplicated component rows, or matrix differences introduced
by substituting those transcriptions.

| Ordered Spend relation group | Local rows | Source-derived component substituted |
|---|---:|---|
| `ak` and randomized authorization key | 1,030 | None; local relations retained |
| `nsk`, `nk`, point representations, and IVK | 23,560 | IVK BLAKE2s only |
| `g_d` and `pk_d` | 4,048 | None; local relations retained |
| Value commitment and note commitment | 4,031 | NoteCommitment Pedersen only |
| Merkle path, position, and conditional anchor | 44,226 | All 32 depth-personalized Pedersen hashes only |
| `rho`, nullifier PRF, and multipacking | 21,882 | Nullifier BLAKE2s only |
| **Total** | **98,777** | **33 Pedersen and 2 BLAKE2s calls** |

This ledger makes the boundary explicit: equality of the complete serialized
matrix establishes parity under those substitutions, while each row group's
other constraints are still the local implementations and are not
independently compared with Bellman.

### Upstream-equivalence boundary

This is not a full independently reconstructed Bellman Spend matrix. The
other Spend gadgets are not independently transcribed in this comparison.
Bellman calls `inputize` during synthesis, while ZyCoin allocates all public
columns first; Bellman's input and auxiliary variable indices are separate,
however, so the seven public identities still map directly to Bellman input
indices 1–7 (with `ONE` at input index 0). Exact auxiliary identities and
whole-circuit row/column equivalence remain unverified. The source-derived
component transcriptions are not official matrix exports. The precise result
is **complete local assembly parity under Pedersen/BLAKE2s reference
substitution**, not whole-circuit Bellman matrix equivalence. No circuit
semantics or counts changed; the existing fingerprint remains unchanged.
Groth16 eligibility and Sapling spending remain gated.

### Phase 9.20.53 verification

- CPython 3.10.11 full pytest suite: **138 passed**. The focused
  complete-composition regression: **1 passed**.
- The regression asserts the exact Pedersen/BLAKE2s substitution count,
  personalization/configuration set, relation-group boundaries, matrix
  bytes, fingerprint, local column prefix, and witness satisfaction.
- `compileall`, targeted Ruff, Pylance diagnostics, the Spend signature
  compatibility check (all six call sites), and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel installation imported
  `zycoin` and the Spend module and verified access to all eight coin JSON
  and nine wordlist resources; the sdist contains the updated reports and
  regression test.
- This phase makes no native-code, proving, or circuit-semantic changes.

## Phase 9.20.54 — Bellman Spend variable allocation and synthesis order

The allocation trace uses pinned `sapling-crypto` 0.9.0
[`Spend::synthesize`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
and `expose_value_commitment`, pinned ECC allocation methods in
[`circuit/ecc.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs),
and Bellman 0.15.0's
[`TestConstraintSystem`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/test/mod.rs).
This is a source-order audit; no upstream circuit was synthesized and no
native or proving tool was used.

### Input identities: exact mapping

Bellman's test constraint system stores `Input` and `Aux` variables in
separate vectors. Its input vector starts with `ONE` at `Input(0)`;
`alloc_input` uses the current input-vector length and `alloc` uses the
current auxiliary-vector length. Therefore the source's calls to `inputize`
between private allocations do **not** make inputs appear at private
auxiliary column positions. The verified local-to-Bellman mapping is:

| ZyCoin local column | Bellman variable | Identity |
|---:|---|---|
| 0 | `Input(0)` | implicit `ONE` |
| 1 | `Input(1)` | `rk.u` |
| 2 | `Input(2)` | `rk.v` |
| 3 | `Input(3)` | `cv.u` |
| 4 | `Input(4)` | `cv.v` |
| 5 | `Input(5)` | anchor |
| 6 | `Input(6)` | first packed nullifier chunk |
| 7 | `Input(7)` | second packed nullifier chunk |

This mapping follows Bellman's input namespace and the pinned circuit's
`rk.inputize`, `cv.inputize`, `rt.inputize`, and final `pack_into_inputs`
order. It is not inferred from equal input counts. The existing public-first
local R1CS layout is compatible with this input mapping.

### Allocation and relation order

The pinned synthesis proceeds in this order; public allocation timing is
listed separately from the semantic component sequence:

1. Witness `ak` coordinates and constrain the point/small-order condition.
2. Allocate `ar` Boolean bits, fixed-base multiply, add to `ak`, then
   inputize `rk.u/v`.
3. Allocate `nsk` bits, compute `nk`, allocate `ak` then `nk`
   representations, and synthesize IVK BLAKE2s.
4. Witness/check `g_d`, compute `pk_d`.
5. In `expose_value_commitment`, allocate value bits, compute its fixed-base
   product, allocate `rcv` bits and compute that product, add them, then
   inputize `cv.u/v`.
6. Allocate `g_d` and `pk_d` representations for note contents, synthesize
   NoteCommitment Pedersen, then allocate `rcm` bits, compute its fixed-base
   product, and randomize the note commitment.
7. For each of 32 Merkle levels, allocate that level's direction bit and
   sibling, conditionally reverse the pair, decompose both children, and
   synthesize that level's personalized Pedersen hash.
8. Allocate the conditional anchor witness, constrain it, and inputize anchor.
9. Compute the path-position fixed-base product, add it to the commitment,
   allocate the rho representation, synthesize nullifier BLAKE2s, and
   allocate the two packed nullifier inputs last.

The local column order is deterministic but not the same private-allocation
sequence. In particular, ZyCoin reserves all seven public columns first;
materializes `pk_d` representation before the value commitment; allocates
`rcm` bits before entering the note-commitment gadget (whose Pedersen hash is
then synthesized); and allocates the position scalar and all 32 range bits
before the per-level Merkle loop. Bellman instead allocates `pk_d` bits after
the value-commitment inputization, allocates `rcm` bits after the note
Pedersen, and allocates each position bit inside its corresponding loop
iteration. Consequently some private `Aux(n)` indices and constraint-row
order differ.

The anchor and path-position encodings provide a concrete cancellation that
explains why this allocation change does not alter the published aggregate
row count. Upstream allocates 32 direction bits directly in the Merkle loop;
after the path, it allocates an auxiliary anchor `rt`, then `inputize` adds a
public input and an equality row tying that input to `rt`. ZyCoin instead
allocates a private 32-bit position scalar plus its 32 Boolean bits and one
reconstruction row, and uses the already-allocated public anchor directly in
the conditional-root equation. Thus this local encoding has one extra
position scalar/reconstruction row while omitting the upstream anchor alias
auxiliary/equality row. Those are two distinct witness/matrix representations
whose one-row/one-auxiliary differences cancel in the total; equal counts do
not make the rows or private variable identities equal. The regression pins
the local position reconstruction equation and direct use of the public
anchor, while the upstream allocation and `inputize` relation are established
from pinned source.

The audited source dataflow and ZyCoin's shared-variable regressions show the
intended joins (value bits into note/anchor, path direction bits into the
position and nullifier, and note commitment into Merkle/rho) are present for
the tested witness. They do not prove equality for all assignments or
provide a complete upstream witness-sharing map.

### Mapping limits and decision

ZyCoin has **98,638 local auxiliary columns** in the deterministic assembly.
That is a local count, not evidence that Bellman's `Aux` indices or count
match. Available pinned source gives allocation procedures and ordering but
does not provide an authoritative full Spend `(Aux(n) -> semantic identity)`
matrix export. The Pedersen/BLAKE2s Python transcriptions cover only those
components; they do not establish allocation identities for Jubjub
arithmetic, value commitment, multipacking, or the complete circuit.

The allocation regression pins the local `(kind, name)` manifest digest
`cc8289461de9acb811ff5ceacb239d035e00483d7c5d6227b7887e0cbc5f2be7`,
the 98,638 local auxiliary count, representative local indices for `ak`,
`ar`, `nsk`, value/commitment bits, and Merkle position, and the exact
`Input(0..7)` mapping above. It also checks the position-bit reconstruction
and that the conditional anchor row references the public input directly.
It supplements the existing matrix fingerprint, public-input order,
witness-satisfaction, and shared-value-bit assertions. These establish local
determinism and the stated source-backed semantic mapping, not a complete
upstream auxiliary identity map.

No Bellman-compatible allocation mode was added. A safe exact mode would
need to reproduce all nested private allocation and row-synthesis order; the
current API's public-first rule alone is not the blocker for input identity.
Changing only top-level order would assign wrong auxiliary identities and
would not establish a mapped matrix comparison. No circuit semantics or
default behavior changed.

**Status:** public-input and `ONE` identity mapping is **Verified**; local
auxiliary count and order are **Verified**; exact Bellman auxiliary identity,
complete allocation mapping, and whole-circuit row/matrix equivalence are
**Unverified**. Sapling spending and Groth16 eligibility remain gated.

### Phase 9.20.54 verification

- CPython 3.10.11 full pytest suite: **138 passed**. Focused Spend
  allocation/matrix regression: **1 passed**.
- Allocation test checks the explicit eight-input identity mapping,
  auxiliary count, representative local index assignments, and deterministic
  complete variable-manifest digest. It also checks the position
  reconstruction row and direct public-anchor wiring.
- `compileall`, targeted Ruff, Pylance diagnostics, the Spend signature
  compatibility check (all six call sites), and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel installation imported
  `zycoin` and the Spend module and verified access to all eight coin JSON
  and nine wordlist resources; the sdist contains the updated reports and
  allocation regression.

## Phase 9.20.55 — Remaining Spend gadget equivalence audit

This audit traced the remaining Spend relations to pinned
[`sapling-crypto` 0.9.0 `src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs),
[`src/circuit/ecc.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs),
[`src/circuit/constants.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/constants.rs),
and Bellman 0.15.0's
[`gadgets/lookup.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/lookup.rs),
[`gadgets/boolean.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/boolean.rs),
[`gadgets/num.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/num.rs),
and [`gadgets/multipack.rs`](https://docs.rs/crate/bellman/0.15.0/source/src/gadgets/multipack.rs).
`Spend::synthesize` is the call-order authority. The relations below are
compared to source equations and source-described allocation, not to an
official per-gadget or complete Spend matrix export.

### Per-gadget findings

| Spend gadget | Pinned relation and encoding | Local behavior and evidence | Status and remaining evidence |
|---|---|---|---|
| Jubjub membership | Twisted Edwards `-u² + v² = 1 + d u²v²`; `EdwardsPoint::witness` allocates `u,v`, then `interpret` enforces membership. | `constrain_jubjub_point` has the same equation and three coordinate products plus the curve row. | **Verified equations; matrix/allocation unverified.** Membership vectors and tampering are covered by point, `ak`, and `g_d` tests. |
| Non-small-order check | Three affine doublings followed by `u != 0` on `[8]P`; the curve cofactor is eight. This does not itself prove prime-subgroup membership. | Same three doubling relations and a nonzero inverse relation. Spend host admission additionally requires `ak` to be in the prime subgroup and nonidentity; this is stricter host admission than the circuit equation, not an added circuit constraint. | **Verified relation; host-domain difference documented.** Identity/small-order rejection and host admission are tested. |
| Addition and doubling | `EdwardsPoint::add`: allocate `U,A,B,C,u3,v3`, constrain four products and two coordinate equations. `double`: `T,A,C,u3,v3`, three products and two coordinate equations. | `constrain_jubjub_add` and `constrain_jubjub_double` use the same formulas and row counts (6 and 5). Local row labels and serialized coefficient/order parity have not been compared against an independent Bellman matrix. | **Verified equations/counts; matrix identity unverified.** Generic point arithmetic, result mutations, and new identity/inverse-point regressions exercise the relations. |
| Fixed-base multiplication | `fixed_base_multiplication` consumes little-endian bits in three-bit windows, uses an eight-entry `[0..7]` table (identity first), and accumulates selected points. The pinned constants build 84 windows per subgroup generator by advancing each window base by eight. | Same window width, table values, partial-window zero padding, and accumulation order. All six pinned generator coordinates are checked; a one-scalar case per generator, 32/64/252-bit widths, zero/one/maximum witness values, and selection/accumulator tampering are tested. The polynomial lookup rows and auxiliary allocation have not been compared by a separate source-derived matrix. | **Verified parameters/semantics; matrix structure partially verified.** No independent ordered matrix comparison. Spend host fields are canonical Jubjub scalars; field-to-bit R1CS decomposition does not impose an extra `< r` comparator, matching Bellman. |
| Variable-base multiplication | Little-endian bit loop: double current base after the first bit, conditionally select point versus identity, and add selected points in order. | Same sequence and selection equations; callers constrain the base point and bits. Independent ephemeral-key vector, scalar boundaries, bit-order reversal, intermediate/base/public-coordinate mutation are covered by shared-gadget tests. No independent Bellman variable-base matrix transcript exists. | **Verified relation semantics; matrix/allocation unverified.** |
| Value commitment | `cv = [value]G_v + [rcv]G_r`; value uses 64 little-endian Boolean bits, and `rcv` uses `jubjub::Fr` field bits. Bellman's field decomposition booleanizes but does not add a scalar-modulus comparator. `cv.u/v` are inputized in order. | The same formula and bit orders; Spend disables additional scalar-range rows, host witness admission checks canonical `rcv`, and both public coordinates are bound. Independent commitment fixture, zero/max boundary synthesis, public/bit/lookup/accumulator mutations pass. | **Verified relation and fixture behavior; matrix/allocation unverified.** Bellman inputization uses alias input variables plus equality rows; local public-first columns are wired by equality to a private result point. |
| Nullifier multipacking | `pack_into_inputs` processes Boolean output bits in 254-bit-capacity chunks, little-endian within each chunk, and allocates one public input per chunk. | Same 254+2 split and powers-of-two reconstruction; the composition consumes the BLAKE2s output aliases and ties each chunk to its public input. Pinned packed-value fixture, zero/max chunks, reversed-bit, bit and public-value tampering are tested. | **Verified packing semantics and fixture; exact matrix rows unverified.** Local equality equations are algebraically equivalent to Bellman's packing rows but have not been compared as serialized matrices. |
| Randomized authorization key | `rk = ak + [ar]SPENDING_KEY_GENERATOR`; `ar` is a 252-bit little-endian field decomposition; `ak` is constrained on-curve and not-small-order, then `rk.u/v` are inputized. | Same generator, scalar bits, addition and coordinate bindings. Pinned nonzero RedJubjub vector, scalar boundaries, invalid point classes, public-coordinate and witness tampering pass. Host admission also checks prime-subgroup membership for `ak`; Bellman's circuit-level check is only on-curve/non-small-order. | **Verified equation and vector; exact matrix and accepted host-domain identity unverified.** No extra circuit subgroup constraint was added. |
| Merkle position/path | Each loop allocates one direction bit and sibling, conditionally reverses `(cur, sibling)`, decomposes both values into 255 little-endian bits, and hashes with depth personalization. The same direction bits feed `g^position`. Anchor is a separately allocated witness inputized after the path and conditionally bound by `(root-anchor)*value=0`. | Direction bits are allocated by a 32-bit range decomposition before the path loop and shared into selection and rho. Node decompositions are 255-bit Boolean/reconstruction checks, not strict modulus comparisons, matching the source's non-strict `to_bits_le` use. Local anchor references the public input directly. | **Verified path semantics and shared wiring; allocation/matrix differs.** Pinned Merkle vectors, all direction-bit mutations, sibling/root/anchor mutations, zero/nonzero conditional-anchor behavior, and maximum position are tested. The position/anchor allocation delta is detailed below. |

### Allocation, encoding, and composition audit

The local fixed-base and point equations implement the pinned relations, but
there is no independent Bellman synthesis transcription for Jubjub
membership/arithmetic, the scalar-multiplication consumers, value
commitment, or multipacking. Matching equation counts or witness outputs
would not prove equal ordered rows or auxiliary identities, so no reference
matrix was manufactured for those gadgets.

The previously identified Merkle allocation difference is also a concrete
semantic representation difference: Bellman allocates path direction bits
inside each level and inputizes a private anchor witness after the path;
ZyCoin range-decomposes a private position scalar before the path, then uses
the public anchor directly in the conditional relation. The local
position-bit reconstruction row/variable and the upstream anchor
inputization equality row/variable account for a one-row/one-auxiliary
cancellation in this part of the assembly. The rows and witness identities
are not the same. Node selection still binds both ordered children to the
same level's direction bit.

No missing or duplicated circuit relation was found in the complete local
Spend wiring:

- The same 64 value bits feed the value commitment, note preimage, and
  conditional-anchor value.
- The constrained `g_d` feeds variable-base `pk_d`; the strict point
  representations feed note Pedersen and the IVK input.
- The note commitment's `u` coordinate is the Merkle leaf and the full point
  feeds rho; the path's direction bits feed both path ordering and rho's
  position multiplication.
- The derived rho and constrained `nk` representations feed the nullifier
  PRF, whose 256 bits feed the two public chunks.
- `g_d` curve/non-small-order checks are emitted once in the `g_d` relation
  group and are explicitly not repeated by NoteCommitment. No separate
  `pk_d` curve check is added, matching upstream's construction from a
  constrained base and scalar multiplication.
- As in the pinned circuit, Spend does not prove `ak = [ask]G`, verify an
  authorization signature, or impose a subgroup relation inside the R1CS;
  host types/admission enforce their respective input invariants.

Component semantic evidence does not establish a whole-circuit matrix
comparison. Previously verified Pedersen/BLAKE2s reference-substitution
parity is unchanged; the other relations remain locally assembled with the
documented equation and vector evidence. No production circuit behavior or
Output semantics changed. **Whole-circuit Bellman matrix equivalence and
Groth16 eligibility remain unverified; Sapling spending remains gated.**

### Phase 9.20.55 verification

- CPython 3.10.11 full pytest suite: **138 passed**.
- Focused `test_sapling_gadgets.py`, `test_sapling_spend_bindings.py`, and
  `test_sapling_spend_circuit.py`: **39 passed**.
- `py -3.10 -m compileall -q src tests`: passed. `ruff check
  tests/test_sapling_gadgets.py` and `git diff --check`: passed.
- Pylance diagnostics for the changed Python test module: no diagnostics.
  The `constrain_jubjub_add` signature compatibility check found all 10
  existing call sites compatible; no production function signature changed.
- Python 3.10.11 wheel and sdist builds passed. The sdist contains all three
  updated reports. A clean-target wheel install imports `zycoin`,
  `zycoin.coin_loader`, `zycoin.sapling_gadgets`, and
  `zycoin.sapling_spend_circuit`; all eight packaged coin JSON resources
  are readable.
- Existing Spend dimensions and fingerprint remain unchanged: 98,777 rows,
  98,646 columns, and
  `f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.

## Phase 9.20.68 — Output Pedersen constraint-shape reduction

The Output note-content Pedersen hash uses the pinned
NoteCommitment personalization and the 576-bit
`value || repr(g_d) || repr(pk_d)` message. The pinned source operates in
63-window Montgomery segments: low two bits select one of four points, the
third bit conditionally negates the signed digit, additions within each
segment use Montgomery coordinates, and each segment is converted to
Edwards coordinates before cross-segment combination.

ZyCoin already had this exact route behind the optional `montgomery`
representation of `constrain_pedersen_hash`, plus a test-only Python
transcription of pinned Bellman/Sapling synthesis. The Output assembler now
selects that representation only for its note Pedersen call. The general
helper still defaults to Edwards, and all Spend and Merkle callers retain
their existing behavior.

On the checked Output fixture, the 576-bit Pedersen matrices from the local
Montgomery route and the independent source-derived transcription are equal
byte-for-byte in ordered A/B/C serialization: 1,558 rows, 1,559 total
columns, 1,558 auxiliary columns, fingerprint
`b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76`.
The 1,558 auxiliary columns include the 576 caller-allocated message bits
and 982 Pedersen intermediates.

The complete local Output fixture now has 7,827 rows, 7,827 columns, and
7,821 auxiliary columns; its local matrix fingerprint is
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
Replacing only the Output Pedersen invocation with the independent
transcription produces the same complete local matrix, five public values,
and note-commitment output. The full-circuit regression rejects tampering
with public inputs, note/representation bits, a Pedersen lookup output,
Montgomery addition slope, segment conversion coordinate, and ephemeral-key
intermediate in both local variants.

The existing Spend regression still verifies all 32 depth-personalized
Merkle Pedersen matrices and the NoteCommitment matrix against the
transcription. No Spend or Merkle synthesis route changed.

Matching the 7,827 row count does not establish full Output Bellman
equivalence. ZyCoin's private allocation and constraint order differs from
the pinned `Output::synthesize` order, and the transcription is not an
independently exported Bellman matrix. Exact equivalence remains unverified
until an authoritative ordered A/B/C matrix and typed allocation mapping are
available. Parameter compatibility and Sapling spending remain blocked.

### Phase 9.20.68 verification

- Focused Output and Pedersen matrix tests: passed, including full-matrix
  equality against the source-derived Pedersen transcription.
- Spend Pedersen NoteCommitment and all 32 Merkle depths: passed; existing
  Spend circuit, R1CS, QAP, query, proof, and verification regressions passed.
- `compileall`, targeted Ruff, Pylance diagnostics, wheel/sdist builds, and
  isolated wheel import/resource checks: results recorded in the
  [Groth16 readiness report](sapling-groth16-proof-generation.md).
- The existing 45 Ruff findings in unchanged `src/r1cs.py` remain separate
  and were not modified.

## Phase 9.20.69 — Full Spend/Output allocation and matrix equivalence audit

The local Spend and Output assemblies were freshly synthesized from the
deterministic regression witnesses. This phase adds exhaustive local
allocation-range checks alongside the existing whole-manifest hashes,
matrix fingerprints, public-input checks, and witness-satisfaction tests.
The map below is the complete local auxiliary allocation sequence; it must
not be read as a Bellman `Aux(n)` export.

### Complete local allocation maps

Indices are zero-based columns, with `ONE` in column 0. Spend's seven public
inputs occupy columns 1–7; Output's five public inputs occupy columns 1–5.
Each local auxiliary prefix below is contiguous, and all ranges partition
the auxiliary columns.

| Spend allocation stage | Local columns | Count |
|---|---:|---:|
| `ak` coordinates | 8–9 | 2 |
| `ar` bits | 10–261 | 252 |
| Randomized authorization-key relation | 262–1,036 | 775 |
| `nsk` bits | 1,037–1,288 | 252 |
| `nk` multiplication | 1,289–2,038 | 750 |
| `ak` representation | 2,039–2,812 | 774 |
| `nk` representation | 2,813–3,586 | 774 |
| IVK BLAKE2s | 3,587–24,546 | 20,960 |
| `g_d` coordinates/checks | 24,547–24,567 | 21 |
| `pk_d` multiplication | 24,568–27,819 | 3,252 |
| `pk_d` representation | 27,820–28,593 | 774 |
| Value bits | 28,594–28,657 | 64 |
| `rcv` bits | 28,658–28,909 | 252 |
| Value-commitment intermediates | 28,910–29,856 | 947 |
| `rcm` bits | 29,857–30,108 | 252 |
| Note-commitment intermediates | 30,109–32,620 | 2,512 |
| Merkle path, position, and hashes | 32,621–76,813 | 44,193 |
| `rho` and representation | 76,814–77,685 | 872 |
| Nullifier PRF | 77,686–98,645 | 20,960 |
| **Total auxiliary columns** | **8–98,645** | **98,638** |

| Output allocation stage | Local columns | Count |
|---|---:|---:|
| Value bits | 6–69 | 64 |
| `rcv` bits | 70–321 | 252 |
| Value-commitment intermediates | 322–1,268 | 947 |
| `g_d` coordinates | 1,269–1,270 | 2 |
| `esk` bits | 1,271–1,522 | 252 |
| `g_d` checks and ephemeral-key multiplication | 1,523–4,806 | 3,284 |
| `pk_d` representation | 4,807–5,062 | 256 |
| `rcm` bits | 5,063–5,314 | 252 |
| Note-commitment intermediates | 5,315–7,826 | 2,512 |
| **Total auxiliary columns** | **6–7,826** | **7,821** |

The Spend manifest SHA-256 remains
`cc8289461de9acb811ff5ceacb239d035e00483d7c5d6227b7887e0cbc5f2be7`.
The new Output manifest SHA-256 is
`e5e930674ec2c15e14b553a576345b8a96a09f9ecac055c5058423b8cef330d2`.
Tests assert each prefix's count and exact first/last column, that its
indices are contiguous, and that all auxiliary columns are covered once.
The public columns and their order are separately pinned. Thus the local
dimensions reconcile independently:

| Circuit | Rows | Columns incl. `ONE` | Public inputs | Auxiliary columns | Local matrix fingerprint |
|---|---:|---:|---:|---:|---|
| Spend | 98,777 | 98,646 | 7 | 98,638 | `f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9` |
| Output | 7,827 | 7,827 | 5 | 7,821 | `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a` |

The matching pinned upstream aggregate row counts are verified as source
test assertions. They do not independently supply upstream column totals or
typed auxiliary identities. Bellman's test system stores `Input` and `Aux`
in separate namespaces: Spend's local columns 0–7 map to `Input(0..7)` as
`ONE`, `rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`, and the two nullifier
chunks; Output's 0–5 map to `Input(0..5)` as `ONE`, `cv.u`, `cv.v`,
`epk.u`, `epk.v`, `cmu`. These input identities are **Verified**. The
auxiliary identities and ordered matrix mapping are **Unverified**.

### Source order versus local order

Pinned Spend synthesis intersperses public inputization: `rk` follows the
randomized-key relation; `cv` follows value commitment; anchor follows the
Merkle path; and the packed nullifier inputs are last. It allocates
`pk_d` representation after the value commitment, `rcm` after note Pedersen,
direction bits at each Merkle level, and the anchor alias before inputization.
The local assembler reserves all public columns first, places `pk_d`
representation before value commitment, allocates `rcm` before note
Pedersen, and allocates its position scalar/bits before the level loop. Its
position reconstruction row/scalar differ from the upstream anchor
alias/equality row/auxiliary; the aggregate differences cancel but do not
establish matching rows or variables.

Pinned Output allocates value bits, completes the value-base multiplication,
then allocates `rcv` bits before inputizing `cv`. It checks and represents
`g_d` before `esk`, inputizes `epk` after multiplication, represents `pk_d`,
then builds Pedersen before allocating `rcm`; it inputizes `cmu` last. The
local Output builder reserves all five public inputs at entry, allocates the
value and `rcv` bit arrays before value-commitment intermediates, allocates
`esk` before the ephemeral-key relation, creates the `g_d` representation
within note-commitment assembly, and allocates `rcm` before note Pedersen.
These source-derived order differences remain even though aggregate row and
local column counts match.

The local relation-group row counts independently sum to 98,777 for Spend:
1,030 + 23,560 + 4,048 + 4,031 + 44,226 + 21,882. Output local rows sum to
7,827 as 1,265 value-commitment, 3,539 ephemeral-key and `g_d` checks, 776
`g_d` representation, 256 `pk_d` representation, 982 Pedersen, 1,002
`rcm`/fixed-base, and seven randomized-commitment/binding rows. These are
local row groups and not a proof of source-identical row ordering.

### Output local matrix changes and status

| Snapshot | Rows / columns / auxiliary | Local fingerprint | Change |
|---|---|---|---|
| Before Phase 9.20.67 | 9,460 / 9,206 / 9,200 | `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` | Pre-correction implementation |
| After Phase 9.20.67 | 8,583 / 8,583 / 8,577 | `4beaf11952ebd89819813c34df45e3c9a4084c6323cc6be54fae66f051f7719d` | Removed unsupported 876-row `rcm` range restriction plus redundant value equality |
| After Phase 9.20.68 | 7,827 / 7,827 / 7,821 | `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a` | Output-only Montgomery Pedersen removed 756 rows and auxiliaries |

Spend remains unchanged at 98,777 rows / 98,646 columns with fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
Fingerprints identify deterministic matrices in the local
`zycoin-r1cs-matrix-v1` format; they are not upstream circuit hashes.

Source equations, public-input identities, and selected component matrices
have evidence at their respective levels. No authoritative full ordered
upstream A/B/C matrix and semantic auxiliary map were found in the pinned
source or existing fixtures. Aggregate circuit hashes/counts cannot recover
that data, and matching totals cannot map proving-key queries unambiguously.
Whole Spend/Output matrix equivalence and exact parameter query mapping thus
remain **Unverified / Blocked**. A deterministic export from pinned
Bellman/Sapling synthesis containing ordered rows and typed allocation
identities is still required. No circuit equations changed, no external
runtime or native tooling was added, and Sapling spending remains gated.

### Phase 9.20.69 verification

- CPython 3.10.11 full test suite: **228 passed**; focused Spend/Output
  circuit tests: **38 passed**.
- `compileall` and targeted Ruff for the modified circuit tests passed.
  Pylance reported no diagnostics for those tests; all 6 Output and all 7
  Spend assembly call sites passed signature-compatibility checks.
- Wheel and sdist builds passed. A clean-target wheel install imported the
  Spend/Output modules and read all eight packaged coin JSON resources.
- The 45 existing Ruff findings in unchanged `src/r1cs.py` remain separate:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.70 — Bellman synthesis evidence and compatibility manifest

The machine-readable
[compatibility manifest](sapling-circuit-compatibility-manifest.json)
pins Sapling Crypto revision `88a7946b4a3066787776e11f0a502654167e022d`
and Bellman 0.15.0 revision `b726862a4ece8a627e7fea486d77b502a6edbb0b`.
It preserves the complete local Spend and Output allocation-manifest
digests, input lists, allocation ranges, matrix fingerprints, and source
comparison status.

The pinned Sapling [`src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
establishes each top-level synthesis stage and public inputization order.
Bellman's pinned `TestConstraintSystem` source establishes implicit
`Input(0)=ONE`, separate Input/Aux index spaces, and row append order at
`enforce`. Bellman's Groth16 setup source establishes that each input,
including ONE, receives a dummy constraint and that query vectors are
ordered by all inputs followed by all auxiliaries: A G1, B G1/G2, IC inputs,
L auxiliaries, and H with `domain_size - 1` entries. The source-derived
domains are 131,072 (Spend: 98,777 circuit rows plus eight input rows) and
8,192 (Output: 7,827 plus six).

The upstream Spend test asserts 98,777 constraints, eight total inputs, and
TestConstraintSystem hash
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`.
Output asserts 7,827 constraints, six inputs, and hash
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`.
Bellman's `TestConstraintSystem::hash` uses BLAKE2s-256 with default
parameters over dimensions and ordered A/B/C terms. These digests are not
canonical fingerprints in ZyCoin's matrix serialization.

No pinned test or available source artifact exports all upstream typed
`Aux(n)` identities and ordered A/B/C row terms. Those could be obtained by
executing the synthesizer with an observing constraint system, or by
implementing and running a complete equivalent synthesizer; neither is
within this phase's Python-only scope. The existing Pedersen and BLAKE2s
transcriptions are component-level Python references, not upstream matrix
exports. Therefore the source procedure and public input order are
**Verified**, aggregate rows and domain sizes are source-derived, and
whole-circuit matrix identity and exact query mapping remain **Unverified /
Blocked**. Equal counts or local names do not establish correspondence.

This audit also updated the runtime Output compatibility metadata from the
stale pre-Phase-9.20.68 snapshot to the current 7,827 rows, 7,827 columns,
7,821 auxiliaries, and local matrix fingerprint. The complete JSON structure,
evidence statuses, and deterministic serialization are regression-tested.
No circuit equations or allocation behavior changed; Sapling spending remains
gated.

### Phase 9.20.70 verification

- CPython 3.10.11 full test suite: **234 passed**; focused manifest,
  parameter compatibility, Spend/Output, and QAP set: **91 passed**.
- `compileall`, targeted Ruff, and `git diff --check` passed. Pylance
  diagnostics were empty for the changed Python files; all 7 compatibility
  assessment call sites passed signature checks.
- Wheel and sdist builds passed. The source archive includes the compatibility
  JSON, updated reports, and regression test. The installed wheel imports
  passed and all eight packaged coin configurations were readable.
- The unchanged `src/r1cs.py` Ruff baseline remains **45 findings**:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.21.18 — Authentic Sapling parameter-format audit

The pinned Bellman 0.15.0 writer serializes six uncompressed verification-key
points (G1/G2 encodings are 96/192 bytes), a big-endian u32 IC count and G1
points, then big-endian u32-prefixed H, L, A, B_G1, and B_G2 point sections.
The existing decoder enforces canonical field coordinates, curve membership,
and subgroup membership; its G2 Fp2 coordinate order follows the pinned
encoding (`c1`, then `c0`). The actual fixed VK and IC points passed those
checks. The parameter wire format has no scalar-field value sections; public
inputs are separately checked as canonical scalars in the Groth16 verifier,
with boundary coverage in synthetic tests.
Zcash's outer Sapling parameter files append the ceremony transcript after
the Bellman parameter serialization; the official loader consumes that tail
when hashing the complete file.

The pinned Bellman generator initializes dense A and B queries but removes
points at infinity from A and B independently before serialization. B_G1 and
B_G2 have the same sparse positions/count, but their count need not match A
or the full input-plus-auxiliary count. L is required to remain dense and H
has `domain_size - 1` points. The previous parser's requirement that A, B_G1,
and B_G2 each equal the full variable count was therefore incompatible with
valid Bellman parameters. The parser now checks A/B counts are bounded by the
variable count, checks B_G1/B_G2 counts against each other, and tests
independently sparse A/B cases.

The streaming reader now supports SHA-256 and BLAKE2b-512 manifests and
trusted expected digests. Strict EOF remains the default. An explicit,
bounded `allow_trailing_data` mode consumes and hashes wrapper transcript
bytes without retaining them; the manifest records their byte count. This
mode validates the Bellman parameter prefix and whole-file digest, not the
transcript's internal ceremony proof. Compact A/B sections are validated but
not expanded back to dense proving queries: doing so requires the exact
circuit-derived omitted-point positions. No authenticated loader currently
connects the parsed verification key or those sparse queries to the local
Groth16 prover/verifier.

Current `librustzcash` source declares the following canonical BLAKE2b-512
pins and exact official file sizes:

| Circuit | Bytes | Published BLAKE2b-512 |
|---|---:|---|
| Spend | 47,958,396 | `8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c` |
| Output | 3,592,860 | `657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028` |

These are source-declared values from
[`librustzcash/zcash_proofs/src/lib.rs`](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/lib.rs);
[`hashreader.rs`](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/hashreader.rs)
uses `blake2b_simd::State::new()`. They are different algorithms from the
previously streamed SHA-512 digests and independent Z23 SHA-512 pins listed in
Phase 9.20.41, so the two sets do not conflict. Both authentic files were
streamed in bounded chunks: their exact sizes, SHA-512 values, and BLAKE2b
values all matched. No file was retained.

Observed counts from the Bellman section prefixes are:

| Circuit | IC | H | L | A | B_G1 / B_G2 | Total variables | Transcript bytes |
|---|---:|---:|---:|---:|---:|---:|---:|
| Spend | 8 | 131,071 | 98,638 | 85,390 | 61,300 / 61,300 | 98,646 | 52,836 |
| Output | 6 | 8,191 | 7,821 | 6,298 | 4,850 / 4,850 | 7,827 | 52,836 |

These are observed from streaming the authentic files' count prefixes and
skipping the encoded point bodies; the independently verified whole-file
digests bind the observed byte streams to the official pins. The parser's
point-by-point canonical-encoding, curve, and subgroup checks were run on
the actual fixed verification-key and IC points, but not every authentic
query point. Thus the whole-file hashes, key/IC points, exact query counts,
and section structure are verified; query point validity/values, circuit
binding, verification-key compatibility, proving-key compatibility, and
proof compatibility remain unverified. Spend's semantic relation audit does
not establish exact ordered matrix alignment; Output's ordered matrix result
does not by itself establish authentic parameter query compatibility. No
official real Sapling Groth16 proof vector was available in the inspected
repository tests; Groth16 end-to-end tests remain synthetic.

### Phase 9.21.18 verification

- `tests/test_groth16_parameter_parser.py`: **39 passed**, **45 subtests**
  (including sparse A/B sections, BLAKE2b-512 digest checks, trailer hashing,
  malformed/truncated streams, point subgroup checks, and compatibility
  gates).
- Direct streaming matched both published digests and byte lengths and
  observed the real section counts above without retaining files. Full
  query-point decoding and parameter-to-circuit binding were not run; the
  actual verification-key and IC points were decoded and subgroup-checked.
  No result here upgrades Spend or Output Groth16 readiness.

## Phase 9.21.26 — Pure-Python Output proving performance benchmark

Added a repeatable, test-only benchmark at
[`benchmark_sapling_output_proving.py`](../tests/benchmark_sapling_output_proving.py).
It synthesizes the pinned Output matrix and Zcash note-encryption witness
(7,827 rows/columns; matrix fingerprint
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`),
uses the recorded official section counts and sparse mapping, and measures
witness validation, QAP work, each of the five query accumulations, and final
proof-element assembly. Query points are deterministic synthetic
prime-subgroup points, not points loaded from the official parameter file;
only synthetic proof elements are assembled for timing, and no authentic
proof is generated or serialized. Reproduce with
`python tests\benchmark_sapling_output_proving.py`.

The measured host was Python 3.12.10 on an Intel i5-9400F (6 cores). The
deterministic witness assignment hash is
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`, and
the official sparse query mapping fingerprint remains
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.
The recorded section counts are A 6,298, B_G1 4,850, B_G2 4,850, H 8,191,
and L 7,821; compact A/B queries are expanded to the 7,827-variable
interface with identities at absent sparse positions.

The previous affine scalar-multiplication implementation was profiled before
replacement: a 255-bit G1 multiplication took 0.140 s and made 408 modular
exponentiation inversions; G2 took 0.163 s with 408 Fp2 inversions. The new
projective implementations perform projective doubles/adds and convert once
at the end. Three-run medians on the benchmark's same 255-bit scalar were
G1 0.00468 s (30.8x faster) and G2 0.02611 s (6.2x faster). A 32-term
reference comparison using actual Output witness scalars matched exactly:
G1 affine 0.690 s vs windowed 0.0154 s (44.9x); G2 affine 0.0105 s vs
windowed 0.00398 s (2.63x). The lower G2 MSM ratio reflects the mostly small
scalars in this first 32-variable sample; it is not representative of the
full H query.

The new pure-Python windowed MSM uses projective bucket accumulation and
mixed affine/projective bucket additions. At the full Output interface, the
separate measured query accumulations were A/G1 1.243 s, B/G1 0.988 s,
B/G2 7.482 s, L/G1 1.632 s, and H/G1 2.664 s. Final proof-element
assembly, including assignment satisfaction and QAP quotient construction,
took 14.761 s. The first full-shape projective/windowed benchmark took
16.898 s for the same synthetic assembly; mixed additions and window tuning
reduced the latest run by 12.6% (timings vary between runs). The measured
QAP cost was 0.012 s for row evaluation, 0.274 s for
three-polynomial interpolation, and 0.662 s for the quotient transforms and
construction. Thus group-query MSMs, particularly B_G2, dominate; FFT/QAP
work is comparatively small.

A calibration estimate for the old affine query path counts actual nonzero
assignment/quotient scalar bit lengths and popcounts on the pinned sparse
supports, then applies the measured affine per-operation cost. It estimates
about 2,919 s (48.7 minutes) for query accumulation alone; the full-size old
affine path was not run. The new synthetic full assembly plus local witness
synthesis is about 16.2 s, after synthetic query objects have been prepared.
This is a compute-only estimate, not a measured authentic-parameter proof
time: parsing/validating authentic query points, parameter-to-circuit and
ceremony binding, and authentic point values are not included. Peak process
working set for the synthetic benchmark was 53,092,352 bytes (about 50.6
MiB). A separate 32-term Python-heap sample measured affine/windowed peaks
of 2,752/3,476 bytes for G1 and 2,880/5,080 bytes for G2; full Pippenger
uses bounded O(window-bucket-count) scratch, while parsed query arrays and
parameters remain the larger unmeasured memory cost.

The baseline scalar profile showed inversion cost dominating affine
multiplication. A post-change 512-term G2 MSM profile instead showed
projective Fp2 arithmetic/object allocation as the remaining hot path
(148,477 Fp2 multiplications and 268,929 Fp2 object constructions in that
profile); it performs no per-add inversion. The benchmark checks optimized
MSM outputs against an independent test-only affine implementation exactly.
Window tuning and mixed additions do not alter scalar order, query order,
field values, or proof equations. The matrix and query-mapping fingerprints
remain unchanged.

The focused arithmetic, pairing, query, FFT, QAP, proof, parser, and Bellman
QAP-reference run passed **119 tests**, with the opt-in authentic
Output-parameter interoperability test skipped because the external
parameter file is not present. Accordingly, no authentic Python proof was
attempted. The previous Bellman-to-Python proof result remains a separate
earlier-phase result, not a post-optimization interoperability validation.
Python proof assembly appears computationally feasible after validated
queries are available, but authentic query-value compatibility, ceremony
validity, Python-generated proof interoperability, and production readiness
remain **Unverified**.

## Phase 9.21.27 — Authentic Output proving-query MSM validation

The test-only
[`benchmark_sapling_output_authentic_msm.py`](../tests/benchmark_sapling_output_authentic_msm.py)
loaded the external `sapling-output.params` through the production streaming
parser. Its 3,592,860 bytes matched the pinned SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` and
BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
The 52,836-byte trailer was consumed as opaque transcript data; this run
does not validate the ceremony. No parameter file or decoded proving-query
fixture was added to the repository.

The deterministic Output witness retained assignment SHA-256
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`,
7,827 rows/columns, QAP domain 8,192, matrix fingerprint
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`,
and sparse mapping fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.
Parsed counts were H 8,191, L 7,821, A 6,298, B_G1 4,850, B_G2 4,850,
and IC 6. A/B were restored to the 7,827-variable interface using identity
points at absent sparse positions; B_G1/B_G2 maps agreed. H used ascending
quotient-coefficient order and L used auxiliary-variable order.

All full authentic-query accumulations matched exact group-point results from
independently partitioned runs of the optimized MSM. Beginning and ending
12-term subsets for H, L, A, B_G1, and B_G2 also matched a test-only affine
double-and-add oracle. This is not an independent affine oracle over every
full section. Accumulation timings were H/G1 2.588 s, L/G1 1.603 s, A/G1
1.236 s, B/G1 0.983 s, and B/G2 7.361 s (13.771 s total). The synthetic
benchmark total was about 14.0 s; aggregate timing is similar, with normal
run variation and B_G2 dominant in both. Parser and subgroup validation took
47.333 s; validated query-object construction took 47.031 s. Total run time
including witness reconstruction, validation, accumulations, cross-checks,
and boundary tests was 159.863 s. Peak process working set was 57,360,384
bytes (about 54.7 MiB).

Per-section result-encoding SHA-256 digests (not query fingerprints) were:
A/G1 `cb295442c584ea4e7c0eb79e7c09f096b216a7abcb757b91bfcfc86cd670fc50`,
B/G1 `614909d14465e5c3efcd25c4d4c6eaa8a70f8352b067dcf6abfec5e15dc0896d`,
B/G2 `c1a800fb1d844eac78fbfcf103157ed7dae0e0d20764bdc0580bd996c341be48`,
H/G1 `0890084670634c253500bb963e39122ba5a1035a9a057fcd4fc0b081dc9c6062`,
and L/G1
`25a4182518e2d9437cc60d9702968ca8a95791e76008fab0a21a6e77098ff666`.
Zero, one, modulus-minus-one, empty and identity-only queries, rejection of
the modulus scalar, and term counts 31/32/33, 127/128/129, and 511/512/513
passed. The focused arithmetic, optimized MSM, query, QAP/FFT, parser,
Output-reference, Output-query, and compatibility-manifest tests passed
**125 tests and 132 subtests**.
The additional Bellman synthesis and exact Output correspondence regressions
passed **51 tests and 36 subtests**.

No authentic proof was generated. These results establish exact optimized
MSM outputs on authentic points and affine agreement only for the stated
subsets; they do not establish complete independent MSM equivalence, Groth16
proof correctness, authentic query-to-circuit binding, ceremony validity,
Spend compatibility, or production readiness.

## Phase 9.21.30 — Production-safe Sapling Output proving API

Added [`sapling_output_proof.py`](../src/sapling_output_proof.py), a narrow
production API that loads the supported parameter file once into an opaque
validated parameter object, proves a [`SaplingOutputWitness`](../src/sapling_gadgets.py),
and verifies canonical compressed proof bytes against named public inputs.
It exposes no query accumulation controls and no RNG override. Parameter
loading requires the exact official Output SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4`,
BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`,
Bellman 0.15 format, pinned section counts, and the 52,836-byte trailer
boundary. The parser checks all encoded key/query points for curve and
subgroup membership. The A/B sparse supports are embedded as compressed
bitsets generated from the pinned mapping and are tested against the existing
mapping artifact fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.

Before any proof randomization, the API validates the witness components,
synthesizes a fresh Output R1CS, checks the 7,827-row/7,827-column matrix
fingerprint, five public-input order and values, 7,821 auxiliaries, 8,192
QAP domain, and every assignment constraint. It draws two independent
canonical scalars with Python `secrets.randbelow`; no deterministic mode or
caller-provided source is available. The API encodes proofs as 192-byte
compressed G1/G2/G1 and rejects noncanonical encodings. Verification requires
exactly five named 32-byte little-endian canonical inputs in order
`cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`.

The full authentic API test generated two different proofs for the same
`zcash-note-encryption-vector-0` witness. The Python verifier accepted both;
the independent test-only Bellman 0.15 verifier also accepted both after
checking all 7,827 constraints and reconstructing the public input vector.
Python and Bellman rejected an altered proof point, changed/reordered public
inputs, and malformed proof encodings. Tests also rejected malformed
parameter input and an inconsistent/unsatisfied witness before any randomizer
draw. The external parameter file and all proofs remained outside the
repository.

The production module is pure Python; Bellman/Rust remains test-only. Secret
intermediates are local to the proving call and are not cached, but Python
cannot guarantee zeroization of integers/objects. The parameter hash pins
identify exact bytes; they do not cryptographically validate the appended
ceremony transcript or establish general setup-to-circuit binding. The API
supports Output only; ceremony validity, broader parameter binding,
side-channel properties, and production readiness remain **Unverified**.

Validation: the full production API test passed (**5 tests**); after final
negative-case additions it passed again (**5 tests in 157.85 s**). Its focused
unit/witness rejection subset passed (**4 passed, 1 deselected**). The
existing BLS/Groth16/Output compatibility and authentic parameter suite
passed (**144 tests, 141 subtests**). Pylance reported no diagnostics for the
new module; targeted Ruff and Python compilation passed.
An isolated `build_py` check confirmed that `zycoin.sapling_output_proof.py`
is included in the distributable package.

## Phase 9.21.29 — Pure-Python authentic Output proof interoperability

The test-only driver
[`generate_verify_sapling_output_python_proof.py`](../tests/generate_verify_sapling_output_python_proof.py)
uses the production parameter parser, Output QAP, optimized proving-query
accumulations, `assemble_proof_elements`, and pure-Python verifier. It reads
the external official Output parameters only after matching the pinned SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` and
BLAKE2b-512; the parameter file is 3,592,860 bytes. The deterministic
`zcash-note-encryption-vector-0` assignment has SHA-256
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`,
with unchanged matrix fingerprint
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368` and
query-map fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.

The canonical public inputs are exported as five 32-byte little-endian
scalars in order `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`. The proof is
Bellman compressed G1/G2/G1 (192 bytes), SHA-256
`22b06dcd01c54e8329cc04ac4270a72de0919642452c478a64c783c4780bb6ef`.
The Python verifier accepted it; the independent pinned Bellman 0.15 runner
also accepted it after independently checking satisfaction for all 7,827
rows and reconstructing the public inputs from the pinned assignment.
Consumed query counts were IC 6 (including ONE), H 8,191, L 7,821, A 6,298,
B_G1 4,850, and B_G2 4,850.

Both verification paths rejected an altered proof point, changed public
input, reordered public inputs, truncated proof encoding, and malformed point
encoding. The test-only randomizers are fixed SHA-256-derived values; they
are deterministic and explicitly not suitable for production. The proof,
parameter copy, and exchange files were temporary and were not retained.

Python timings were QAP quotient 0.700 s, separately measured query
accumulations 14.998 s, proof assembly including its internal QAP/MSM work
16.038 s, and verification 1.484 s. Parameter parsing and subgroup
validation took 51.799 s; the complete driver took 164.769 s and peaked at
61,693,952 bytes working set. Bellman's verification of all cases, including
runner startup and parameter loading, took 18.259 s and peaked at
197,558,272 bytes RSS. The separate timing buckets overlap by design and
should not be summed.

The focused Python proof/query/verifier regressions passed 26 tests and 6
subtests. Validation recorded for this phase includes the focused Groth16,
Output QAP/query, and manifest regression set (130 tests and 135 subtests)
and the existing
authentic-parameter interoperability regression passed 1 test in 78.91 s.
Python compilation passed. Ruff passed for the proof driver and its changed
production module; the manifest test retains an unrelated pre-existing I001
import-order finding.
This proves one deterministic proof interoperability path only. Authentic
ceremony validity, general parameter-to-circuit binding, secure production
randomness, a production high-level prover, Spend, and production readiness
remain **Unverified**. The production Output matrix and query-map fingerprints
are unchanged.

## Phase 9.21.28 — Independent complete authentic Output MSM verification

Added a separate test-only Bellman 0.15 executable,
[`authentic_output_msm_reference.rs`](../tests/reference/sapling-output-qap/src/bin/authentic_output_msm_reference.rs),
and reproducible driver,
[`validate_sapling_output_authentic_msm.py`](../tests/validate_sapling_output_authentic_msm.py).
The reference executable loads the hash-pinned official Output parameters,
the pinned ordered row artifact, and the deterministic satisfying assignment.
It independently computes the QAP quotient using Bellman 0.15
`EvaluationDomain` transforms; it constructs A/B scalars from the witness
and compact query-index-to-variable mapping itself, rather than receiving
Python-generated scalar vectors. L uses the ordered auxiliary assignment.
The IC accumulator is independently formed from IC[0] times ONE and IC[1..5]
times the five public inputs. The runner exports only six canonical result
point encodings and metrics; it never creates a Groth16 proof.

The official file measured 3,592,860 bytes and matched SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` and
BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
The assignment hash is
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`;
the matrix fingerprint is
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`,
and the sparse query-map fingerprint is
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.
Counts were H 8,191, L 7,821, A 6,298, B_G1 4,850, B_G2 4,850, and IC 6.
The temporary Bellman result export was 723 bytes with SHA-256
`af22fb8571fefc1c3929e1e8949b098442042c2ad26e2d797747a3cab5e5b72e`;
it was deleted after comparison and is not retained in the repository.

Every full Python MSM result matched the independently computed Bellman
point by exact canonical uncompressed encoding: H, L, A, B_G1, B_G2, and IC.
The six IC scalars were checked to follow the constant ONE, then all five
public inputs. All six accumulated points were non-identity. The runner skips
zero scalar multiplications, and the Python zero-scalar, identity-only,
empty-vector, and window-boundary checks passed. Deliberately altering a
scalar, reordering query points, swapping sparse query indices, or changing
public-input order failed to match the Bellman result. Prior affine oracle
comparisons remain limited to the first/last 12 terms per section.

Bellman accumulation times were H 3.173 s, L 2.192 s, A 1.686 s, B_G1
1.311 s, B_G2 4.244 s, and IC 0.002 s; Bellman QAP quotient construction
took 0.029 s. Its wall time including Rust runner startup and parameter
loading was 27.118 s and peak RSS was 34,553,856 bytes. Python accumulation
times were H 2.606 s, L 1.582 s, A 1.215 s, B_G1 0.967 s, B_G2 7.189 s,
and IC 0.020 s (13.559 s total). Python's complete run, including witness
reconstruction, parameter parsing/subgroup validation, checks, and negative
mutations, took 165.009 s; reported process peak working set was 100,200,448
bytes.

The BLS12-381 arithmetic, projective MSM, query, QAP/FFT, parser, Output QAP
reference, Output query compatibility, Bellman synthesis, and compatibility
manifest regressions passed **165 tests and 168 subtests**. The pre-existing
authentic proof-interoperability test was not run because it generates a
Groth16 proof, expressly out of scope here. Matrix and query-map fingerprints
are unchanged. This establishes accumulation equivalence only; it does not
establish proof-generation correctness, authentic query-to-circuit binding,
ceremony validity, Spend compatibility, or production readiness.

## Phase 9.21.25 — Authentic Sapling parameter ceremony transcript audit

The official Sapling parameter files append a `phase2` 0.2.2 transcript
envelope after the Bellman parameter serialization. The inspected verifier is
`ebfull/phase2` revision
`0c2b25fe8879deeb46530e91a5654d353a9bf94c`. Its envelope is a 64-byte
initial-setup/circuit hash, a 4-byte big-endian contribution count, and one
544-byte record per contribution: three 96-byte uncompressed G1 points, one
192-byte uncompressed G2 point, and a 64-byte transcript digest. Both files
have a 97 count and satisfy `68 + 97 * 544 = 52,836` bytes. This is a
boundary/length check only; contribution records were not claimed as
cryptographically validated.

The independently inspected `MPCParameters::verify(circuit)` procedure
reconstructs the initial parameters from the circuit and the appropriate
Phase-1 Powers-of-Tau file, checks circuit/setup identity and unchanged
parameter material, validates each contribution's chained transcript digest
and proof-of-knowledge/ratio relations, and checks final delta and H/L
scaling. The Zcash `parse_parameters` loader instead parses the Bellman
prefix, drains the suffix, and validates the whole-file trusted digest; its
source explicitly states that it does not verify the transcript.

External official-file measurements (files were not kept in the repository):

| Circuit | File bytes | SHA-256 | SHA-512 | BLAKE2b-512 | Bellman prefix | Transcript SHA-256 | Setup hash |
|---|---:|---|---|---|---:|---|---|
| Spend | 47,958,396 | `8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13` | `320fbb5754c8b3f4ecb3dd4c2e3dbe1d138c4b343f073c7e31612d26fe769cdba8edab426a7f2c42e317bebdb2ca6f73af1312affa1fcf599a31d499ad4cb4e5` | `8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c` | 47,905,560 | `f8024c58347837c789fc1ae6ef8e8c983de3053260f4023e5664d7d05ff05962` | `2c36f3a1e5ec6dedc1bcb24906d613f0e7446a375395a351f51ecec481a40658704bf7eb0d08d18902c2915d624510781abf0a5d3d8d651aea6c8c048a50cdf2` |
| Output | 3,592,860 | `2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` | `a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152` | `657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028` | 3,540,024 | `7414e8d1fbd21548519e8660702d00fb449975b949a590e7ad1593c143c2752d` | `b5b1df34e0cf37e1029a1b6bd51244eada13c5c3032dbebb05df375f84a9b4a4ae8fb927f738bcc795c7fa3f06f9ef13a75fa373a018da54cee0f555a8ab3af1` |

The Phase-1 files required for reconstruction are absent:
`phase1radix2m17` for Spend (domain 131,072) and `phase1radix2m13` for
Output (domain 8,192). The exact ceremony-era circuit/setup implementation is
also not established by the current test runner. Therefore neither transcript
was passed to the cryptographic verifier. Parser regressions demonstrate
that changing or truncating data fails when checked against the trusted
whole-file digest, and that an opaque trailer can be consumed when a caller
supplies its own matching digest; these tests do not validate contribution
proofs. Invalid contribution-proof and full malformed-transcript rejection
tests remain unavailable without the verifier prerequisites.

The parser and compatibility-manifest suites passed **60 tests** (42 parser
and 18 manifest tests). The opt-in Output parser/Bellman comparison and proof
interoperability regression was rerun: **1 passed** in 75.51 seconds, again
matching all 32,016 points and accepting the same independent Bellman proof
(SHA-256 `8c8823da4046dc6e88640876018ec2bfeab2682d2f0a9dbfe5e085e18443c4c1`).
The official files were temporary external inputs and were removed after
the audit. Ceremony validity, Python proving readiness, and Spend
compatibility remain **Unverified**. This audit does not alter the separate
Phase 9.21.24 exact Output parser/Bellman point equality result.

## Phase 9.21.24 — Exact Sapling Output query decoding compatibility

The official 3,592,860-byte Output parameter file was downloaded to a unique
external temporary path and matched its pinned SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4`.
The test-only Bellman 0.15 runner
([`authentic_output_prover.rs`](../tests/reference/sapling-output-qap/src/bin/authentic_output_prover.rs))
independently loads the stream through `Parameters::read` and writes each
loaded IC/H/L/A/B_G1/B_G2 vector as canonical uncompressed point bytes to a
framed temporary export. ZyCoin's production parser independently decodes
the same file, and the test compares every re-encoded point byte-for-byte
against the Bellman export at the same section and index.

All **32,016** points match with zero missing, extra, reordered, altered, or
identity entries: IC 6, H 8,191, L 7,821, A 6,298, B_G1 4,850, and B_G2
4,850. The framed Bellman export is 3,539,187 bytes with SHA-256
`b56a9951fb00b54fee097a382fd78ebe19d98c6936461c14bd601d0414cf2bc1`.
Canonical uncompressed point-byte SHA-256 values by section are:

| Section | Points | SHA-256 |
|---|---:|---|
| IC | 6 | `ac5eebf2fd7bb932e5be502dee5b436e96d16a4f0551d584842ccd91e6b52ec8` |
| H | 8,191 | `78137bbb088d4d3bdbd556b74d4ee2967194b1e51a14c8ab30b358c85637d358` |
| L | 7,821 | `b8645446053e737e19e8c3e1048de54606ab04bd856e30688d0def4e0785e5e3` |
| A | 6,298 | `69f5a73657d7bd38e3496b42544e8a9baeceed6706b695063aa696c17fa0a847` |
| B_G1 | 4,850 | `dd33a8ae75462352aba65f8e2024f9592e9d3cc1b994e761b0858179ed9e646e` |
| B_G2 | 4,850 | `01f2aa322ee9f9d83162decc1ea06b81ce9a9349fd212bccd5a2016026db4e32` |

The IC order is ONE, `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`.
H indices 0–8190 are quotient-polynomial coefficient degrees in ascending
order, not constraint rows. L indices 0–7820 map to Aux(0–7820) in allocation
order. A's 6,298 and B's 4,850 serialized points are compact vectors; their
indices were checked against an independently regenerated matrix-support
mapping built from the pinned ordered-row artifact and complete variable
correspondence. The regenerated mapping equals the checked-in mapping with
fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`;
B_G1 and B_G2 indices are identical. Bellman's parameter wire format has no
per-point variable labels, so sparse variable identities are derived from
the pinned setup ordering and matrix support, not encoded in the parameter
file. No identity point occurs in any serialized section; omitted sparse
positions remain omitted rather than being treated as serialized identities.

The checker rejects altered or reordered encodings, missing/extra points,
section reordering/truncation, and incorrect sparse-index mappings. Its
six negative tests pass. The Bellman runner invocation (including parameter
loading, query export, and existing proof interoperability) took 12.99 s
with 33,840 KiB peak RSS. The exact Python comparison took 47.64 s; the
complete Python test process peaked at 219,467,776 bytes working set (this is
not an isolated comparator-only memory measurement). Temporary parameters,
query export, and proof were removed after the run.

**Conclusion:** exact equality between ZyCoin's parameter-parser output and
the corresponding Bellman 0.15-loaded Output vectors is verified for every
point and serialized index. This does not independently bind the authentic
point values to the pinned Output matrix or validate the appended ceremony
transcript. Authentic query-to-circuit/ceremony binding, Python proving,
Spend compatibility, and production readiness remain **Unverified**.

### Phase 9.21.24 verification

- Opt-in official-parameter exact query comparison and proof interoperability:
  **1 passed**; 32,016/32,016 exact point matches.
- Negative query order/encoding/count/section/sparse-index tests: **6 passed**.
- Combined parser, negative query, opt-in proof interoperability, query-map,
  Output correspondence/rows, QAP, and compatibility-manifest regressions:
  **105 tests passed**.
- Bellman test-only runner `cargo check --offline`: passed with Rust 1.97.0.
- Ruff passed for the changed Python tests.

## Phase 9.21.23 — Authentic Sapling Output Groth16 interoperability

The official Output parameter file was streamed from the external temp
location only; no parameter file or generated proof was retained in the
repository. Its size (3,592,860 bytes), SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4`,
SHA-512
`a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152`,
and BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`
match the published pins. Bellman 0.15.0's checked parameter reader decoded
the complete proving key and validated all query points. The existing
subgroup manifest accounts for all 32,010 query points once with no rejects;
the exact pinned query map has fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.

The test-only
[`authentic_output_prover.rs`](../tests/reference/sapling-output-qap/src/bin/authentic_output_prover.rs)
reconstructs the pinned 7,827-row Bellman matrix from the checked-in
upstream row artifact and uses the QAP fixture's pinned note-encryption
witness (assignment SHA-256
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`).
The matrix has 7,827 constraints, six inputs including ONE, and 7,821
auxiliaries. The parameter VK has six IC points; the prover consumes the
serialized H 8,191, L 7,821, A 6,298, B_G1 4,850, and B_G2 4,850 query
sections. Public inputs are `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`.

The deterministic test proof is 192 bytes (SHA-256
`8c8823da4046dc6e88640876018ec2bfeab2682d2f0a9dbfe5e085e18443c4c1`);
the canonical uncompressed VK fingerprint is
`d7a655f6f58745f17bf5344682d25d15967e39b575d072335e14ace0a871bd0c`.
Bellman 0.15 verified the proof, and the independent pure-Python verifier
accepted it with the five ordered public inputs. Python verification took
1.99 seconds with a 130,772,992-byte peak working set for the complete test
process. A changed public input and a validly encoded changed proof were
rejected; truncated proof encoding was rejected. The optimized Bellman
runner's end-to-end parameter read, proof, and verification took 3.84
seconds with 27,960 KiB peak RSS.

The proof uses a deterministic XorShift test RNG and is strictly an
interoperability fixture; its randomizers are not suitable for production.

The reverse direction was not run. The existing pure-Python assembler uses
per-point scalar multiplication; measured 255-bit operations were 0.144
seconds for G1 and 0.165 seconds for G2. This witness requires 25,222
nonzero G1 and 5,679 nonzero G2 query multiplications, an estimated 76
minutes before parameter validation, QAP work, and point-wrapper checks.
This is a performance estimate, not a Python proving result.

**Conclusion:** Bellman-to-Python proof interoperability is demonstrated for
this exact pinned Output matrix, official parameter file, and one witness.
This does not independently establish every query point's expected value,
validate the appended ceremony transcript, constitute a formal proof of
parameter-to-circuit binding, establish Python-to-Bellman interoperability,
or demonstrate production proof generation/readiness. Complete
query-value/proving-key compatibility remains **Unverified**; no Spend
conclusion is inferred.

### Phase 9.21.23 verification

- Opt-in authentic interoperability test: **1 passed**. Bellman proof
  creation/verification, Python verification, public-input/proof mutation
  rejection, and malformed encoding rejection passed.
- Targeted parser, BLS12-381, Groth16, Output, Bellman, QAP, and compatibility
  regressions: **191 passed, 1 opt-in test skipped, 166 subtests passed**.
  The opt-in interoperability test was run separately with the official
  parameter file: **1 passed**. Rust reference tests: **2 passed**.
- Ruff and compile checks passed for the new test; compatibility-test Ruff
  checks passed with the existing I001 import-order finding excluded.

## Phase 9.21.22 — Independent Sapling Output QAP reference

The previous Output QAP comparison used ZyCoin's Python implementation on
both the local and pinned-row systems. This phase adds an independent,
test-only reference runner under
[`tests/reference/sapling-output-qap`](../tests/reference/sapling-output-qap)
using Bellman 0.15.0 (`b726862a4ece8a627e7fea486d77b502a6edbb0b`). It consumes
the pinned upstream Output A/B/C row export and exact column mapping, then
evaluates those rows at assignments produced by fresh local Output synthesis.
It does not call ZyCoin's Python QAP implementation to generate the reference
values; no Rust or native code is part of production or runtime code.

The deterministic reference fixture
[`sapling_output_bellman_qap_reference.json`](../tests/fixtures/sapling_output_bellman_qap_reference.json)
has SHA-256
`0d13e5d1e073139fdb6c2e609a77acb6a296ea7582cb0d92337a3f6ec71ed571`,
is 14,821,991 bytes, and records all 8,192 canonical scalar values for each A/B/C domain
evaluation vector and interpolated polynomial, plus all 8,191 H quotient
coefficients for each witness. Its matrix input is the pinned ordered-row
artifact (SHA-256
`c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761`);
the verified variable mapping fingerprint is
`c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc`.
The generator follows Bellman's `EvaluationDomain` IFFT and prover-order
IFFT/coset-FFT, pointwise `A*B-C`, division by `X^n-1` on the coset,
inverse-coset FFT, and final H truncation. It independently checks the
polynomial identity by Bellman FFT convolution.

Three satisfying assignments were compared field-element by field-element:

| Witness | Value | Assignment SHA-256 | Result |
|---|---:|---|---|
| Pinned Zcash note-encryption vector 0 | 100,000,000 | `b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea` | All A/B/C evaluations, coefficients, and H coefficients equal |
| Zero-value boundary | 0 | `3148f6cc60f292a39c747dd9cb3d0b3c5b2e7c4fb6921456578a707cea4adbf3` | All A/B/C evaluations, coefficients, and H coefficients equal |
| Maximum unsigned 64-bit value | `18446744073709551615` | `bead023a3e3130d8851a1bcbdb5da3163148c2c67761f201a1916df0bc1f8095` | All A/B/C evaluations, coefficients, and H coefficients equal |

The Bellman domain has 7,827 circuit rows plus six dummy input rows, 359
zero-padding rows, and size 8,192. The six input values are ONE followed by
the five ordered public inputs; the dummy rows put each value in A and zero
in B/C. All padding evaluations are zero. H contains 8,191 ascending-degree
coefficients with maximum degree 8,190. Each witness satisfies all 7,827
constraints, the final untruncated degree-8,191 quotient coefficient is zero,
and independent coefficient convolution verifies
`A(X)B(X)-C(X)=H(X)(X^8192-1)`.

The fixture also contains a complete Output assignment with a tampered public
input: Bellman identifies failed constraints and emits no quotient, matching
the Python QAP rejection. Rust reference unit tests reject an unsatisfied row
before producing H and reject malformed or noncanonical scalar encodings.
The reference fixture regenerates byte-for-
byte with the pinned Rust toolchain/dependency lock, and the Python parity
tests compare exact arrays rather than only hashes. The focused QAP and
manifest run passed 22 tests; the combined Output, Spend, Bellman, QAP,
Groth16, and compatibility selection passed 301 tests. The Rust reference
runner's two unit tests passed.

This establishes independent Output QAP construction agreement for the
verified pinned matrix and these three assignments. It does **not** bind the
authentic Sapling parameter query values to that matrix, validate the
ceremony transcript, establish proving/verification-key compatibility, or
demonstrate production proof generation. Authentic query-value compatibility
and proof readiness remain **Unverified**; no Spend conclusion is inferred.

## Phase 9.21.21 — Authentic Output query-to-circuit compatibility

The authentic
[`sapling-output.params`](https://download.z.cash/downloads/sapling-output.params)
file is identified by its official name and source-pinned whole-file digests:
3,592,860 bytes, SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4`,
SHA-512
`a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152`,
and published BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
The matching SHA-512 is pinned by
[Z23 `params_init.c`](https://github.com/z23c/z23/blob/7df112acb8584c0a0df4858838b868e0f20e0396/core/modules/sapling/src/params_init.c),
which identifies the canonical file as MPC-ceremony output. The pinned
parameter format is not self-describing and carries no circuit identifier or
matrix fingerprint; the appended 52,836-byte transcript was hashed but not
independently validated. This is strong file identity/designation evidence,
not a validated cryptographic binding from the actual query values to the
pinned Output matrix.

The pinned [Output circuit source](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
has a test-only complete mapping of six input variables and 7,821
auxiliaries, with no identity, assignment, or index mismatches. Its
[ordered row artifact](../tests/fixtures/sapling_output_row_correspondence.json)
matches all 7,827 local A/B/C rows and coefficients at the same row indices.
The [query-index artifact](../tests/fixtures/sapling_output_parameter_query_index_mapping.json)
is deterministically regenerated from that matrix, the variable map, and
authentic sparse A/B counts (mapping fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`):

- IC has 6 entries including ONE: `Input(0)` is ONE, followed by public
  `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`.
- Sparse A has 6,298 points; compact index 0 maps to `Input(0)`/column 0
  and index 6,297 to `Aux(7818)`/column 7,824.
- Sparse B_G1 and B_G2 each have 4,850 points at matching compact positions;
  index 0 maps to `Input(0)`/column 0 and index 4,849 to
  `Aux(7820)`/column 7,826.
- Dense L maps entries 0–7,820 to `Aux(0..7820)` / columns 6–7,826.
- H has 8,191 entries, mapping to quotient-polynomial coefficient degrees
  0–8,190, not circuit rows.

The pinned Bellman generator adds six dummy input constraints (including
ONE), uses the row domain `7,827 + 6 = 7,833`, pads to 8,192, and filters
identity elements from A/B while preserving input-then-aux variable order.
The pinned generator creates H elements for successive `tau^i` powers;
the prover's inverse-coset FFT returns the quotient coefficients in ascending
degree order. The parameter writer serializes H, L, A, B_G1, B_G2 in that
order. These source facts support the position semantics and map.
The map artifact's legacy `upstream_matrix_fingerprint` value
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee` is
actually Bellman's TestConstraintSystem BLAKE2s hash, not a matrix
fingerprint; it was not used as ordered-matrix evidence.

A fresh local Output QAP was compared with a test-only R1CS reconstructed
from the pinned exported rows using the same pinned witness fixture. Both
systems were satisfied and had the same matrix fingerprint
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`.
Their domain metadata, A/B/C evaluations, polynomial coefficients, and
quotient coefficients were equal. The quotient has 8,191 coefficients; its
32-byte little-endian coefficient fingerprint is
`07df9be6c741c02bb72c8ea03e1a8852f4211bfaeed6e734d0813fc4ca3319ca`.
This compares Python QAP runs over an independent pinned *matrix* export;
there is no independently generated full Bellman QAP polynomial fixture.

All 32,010 authentic Output proving-query points remain accounted for in the
subgroup-validation manifest with zero rejections. However, no independent
expected authentic query-value fixture or validated ceremony reproduction
was found. Thus Output's file identity, variable/row correspondence, query
index layout, and local/reference QAP structure are verified; authentic
query-value/proving-key/verification-key compatibility remains
**Unverified**. No Spend conclusion is extrapolated.

## Phase 9.21.20 — Authentic query subgroup validation

The prior query scan had established canonical encodings, curve membership,
section counts, and sparse query-index maps, but had not checked prime-order
subgroup membership. The production bounded parameter parser now uses exact
BLS12-381 endomorphism criteria in `G1Point.is_in_subgroup` and
`G2Point.is_in_subgroup`. The criteria are the ones used by zkcrypto's
[`g1.rs`](https://github.com/zkcrypto/bls12_381/blob/main/src/g1.rs) and
[`g2.rs`](https://github.com/zkcrypto/bls12_381/blob/main/src/g2.rs), with
the proof of correctness referenced there
([ePrint 2021/1130](https://eprint.iacr.org/2021/1130),
[updated proof ePrint 2022/352](https://eprint.iacr.org/2022/352)):

- For G1, verify `phi(P) = -[x^2]P`, where `phi(x,y)=(beta*x,y)`,
  `beta=2^((p-1)/3)` (equal to zkcrypto's BETA), and
  `x=-0xd201000000010000`.
- For G2, verify `psi(P)=[x]P`, where
  `psi(x,y)=(conjugate(x)/(1+i)^((p-1)/3),
  conjugate(y)/(1+i)^((p-1)/2))`, with the same signed `x`.

The points are already curve-checked by the uncompressed decoders. These
per-point tests use projective arithmetic and avoid affine inversions during
the scalar/endomorphism operations. No cross-point aggregate or probabilistic
acceptance is used. The existing affine `multiply_g1`/`multiply_g2` path
remains an independently testable oracle: tests compare each fast criterion
with `[SCALAR_MODULUS]P == O` for the py_ecc reference generators, their
scalar multiples, and deterministic on-curve points outside the subgroup.
Fixtures also check identity behavior, malformed encodings, and rejection of
non-subgroup points by default uncompressed decoding. A streaming helper
validates one point at a time and retains neither source files nor decoded
query arrays.

The authentic files were streamed again and all **469,709** query points
passed individual subgroup checks:

| Circuit | H | L | A | B_G1 | B_G2 | Checked | Rejected | Elapsed | Peak working set |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Spend | 131,071 | 98,638 | 85,390 | 61,300 | 61,300 | 437,699 | 0 | 664.903 s | 30,683,136 B |
| Output | 8,191 | 7,821 | 6,298 | 4,850 | 4,850 | 32,010 | 0 | 49.120 s | 30,711,808 B |

Counts are accounted for once per section by the single-pass parser. Whole
file SHA-256, SHA-512, BLAKE2b-512, section fingerprints, count boundaries,
and zero-identity policy all matched the prior scan. The deterministic
validation artifact is
[`sapling-query-subgroup-validation.json`](sapling-query-subgroup-validation.json)
(SHA-256 `925c7f7b906f1fa8e9338b084d6ec2e852a9d21ab487755a75d977a3a9efa2ea`;
validation fingerprint
`191e50613f303091c5fc4cfc88f45f36f1fe316b6fe12cd4c531671b6b349aa5`).
The Spend and Output query-map artifact hashes and mapping fingerprints
remain unchanged.

Focused BLS12-381, parser, and compatibility-manifest tests passed (**69
tests**); across the targeted BLS12-381, parser, Groth16 (FFT, end-to-end,
proof, QAP, query, and verification), Bellman, Spend, Output, gadget, and
compatibility regressions, **306 tests passed**. Subgroup validity is a
property of the parameter points
only; it does not establish circuit/query-value compatibility, exact Spend
matrix alignment, authentic key compatibility, or proof-generation readiness.

## Phase 9.21.19 — Authentic query points and query-index mapping

The official parameter streams were processed sequentially without retaining
the files. Whole-file byte lengths and SHA-512/BLAKE2b-512 digests matched
their canonical pins. All 437,699 Spend and 32,010 Output A/B_G1/B_G2/H/L
query points were checked for canonical uncompressed encoding, curve
membership, and identity-point rejection with subgroup checks disabled.
Section counts and boundaries matched; zero query identities were found.
Every section was fingerprinted over its count prefix and encoded points.
The existing VK/IC subgroup checks remain verified (14 Spend points and 12
Output points). Query subgroup membership is not established.

The scan took 77.661 seconds for Spend and 6.826 seconds for Output,
including download, with peak process working sets of 30,228,480 and
30,232,576 bytes. Points were streamed and discarded. Based on the measured
pure-Python G1 subgroup-check rate, validating all query points would take
approximately 17.7 hours at minimum, before G2 overhead; that pass was not
attempted.

Deterministic sparse A/B query-index maps use the pinned structural supports
and Bellman's input-then-auxiliary ordering. Output support (A 6,298, B
4,850) matches the authentic compact counts and maps fully to local columns
through its exact ordered matrix and semantic variable mapping. Spend support
(A 85,390, B 61,300) also matches the authentic counts. The Spend map covers
all eight IC inputs, 98,637 of 98,638 L auxiliaries, all 85,390 A upstream
identities (85,389 local columns), and all 61,300 B_G1/B_G2 identities and
local columns. `Aux(76805)` is retained at A query index 63,616 with no
invented local column. H indexes QAP quotient coefficient degrees; it does
not map one-to-one to R1CS rows.

The Output artifact is
[`sapling_output_parameter_query_index_mapping.json`](../tests/fixtures/sapling_output_parameter_query_index_mapping.json)
(SHA-256 `e5ed049ab4cc9571f863f5e20bb49e305d7d655f3f300f22e609792911b5a489`;
mapping fingerprint `bb788970f14269f0257cf23591cbf1a9aeabe5c4b8bfca19420f75d3a630eef2`).
The Spend artifact is
[`sapling_spend_parameter_query_index_mapping.json`](../tests/fixtures/sapling_spend_parameter_query_index_mapping.json)
(SHA-256 `dccf499fcdb7e6dfef6d850d4d60187b515dc32e5c3c8bfa2acb8c51e9a5cf23`;
mapping fingerprint `183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08`).
The Spend artifact references export SHA-256
`b9a1bab4df36059e3c324cd07c0baa96062501bc266cf46005ab0d7c35751046` and
the unchanged v7 variable-mapping fingerprint
`26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656`.

These establish index-to-variable identities where evidence permits, not
point-to-row correspondence or authentic query-value compatibility. Query
subgroup membership, the remaining Spend variable identity, exact ordered
Spend matrix alignment, full parameter-to-circuit binding, key compatibility,
and production proof generation remain **Unverified**. Output's exact matrix
alignment does not by itself establish authentic Groth16 readiness.

### Pinned Spend export and alignment status

A test-only observer executed the pinned `sapling-crypto` 0.9.0 Spend fixture
iteration 0 against Bellman 0.15.0. The export contains all 8 inputs
(including ONE), 98,638 typed auxiliary variables with assignments, and
98,777 ordered A/B/C rows. It is satisfied and reproduces the pinned
`TestConstraintSystem` hash
`d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`;
that hash is not a matrix fingerprint. The export is outside the repository at
`C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-reference.json`
(SHA-256
`b9a1bab4df36059e3c324cd07c0baa96062501bc266cf46005ab0d7c35751046`).
The exporter now records allocation namespace and label separately, in
addition to the original fully qualified annotation.

Local Spend synthesis with the same deterministic witness is satisfied and
has the same aggregate dimensions. Its matrix fingerprint is
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`;
the canonical fingerprint of the pinned export is
`cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`.
All eight input assignments match, and all 98,638 auxiliary assignments are
present in both exports. An ordinal-only comparison finds 43,658 assignment
differences at the same variable indices and 66,135 non-identical A/B/C rows
at the same row indices (32,642 rows are identical under that unproven ordinal
assumption). Equal indices or witness values do not establish semantic
identity. These counts do not establish relation inequivalence or identify
the exact upstream counterpart of any local gadget variable.

**Alignment status:** Spend production synthesis was not changed. Exact
allocation, assignment, and ordered-row alignment remain **Unverified**. The
Output synthesis and its established fingerprint were not changed.

### Exact Spend variable correspondence attempt

### Trace semantic allocation provenance for Spend

The test-only pinned Bellman exporter was extended to record an allocation
event index, variable index, `alloc`/`alloc_input` callback kind, namespace
hierarchy, gadget scope, annotation label, and the available source context.
Bellman's `ConstraintSystem` callbacks expose the annotation and namespace
stack, but not the Rust caller file or line; those source-location fields are
therefore explicitly absent rather than guessed. The upstream trace has 8
inputs including ONE, 98,638 auxiliaries, and 98,777 satisfied rows. Its
98,646 event indices are unique and contiguous. Seven application public
inputs are allocated during later gadget synthesis, at events 1,030, 1,031,
29,078, 29,079, 76,811, 98,644, and 98,645; their variable indices remain
Input(1) through Input(7).

Local provenance was captured by a test-only `R1CS` subclass observing
allocations and Python source frames. Production synthesis and Output were not
modified. The local trace covers all 98,646 variables and is satisfied; it
captures a source context for every auxiliary. The normal local R1CS stores
flattened names rather than namespace objects, so the trace retains empty
namespace hierarchies and records the allocation-site function/file/line as
additional, non-invasive context. Local event indices are contiguous and
match local variable allocation positions; the seven local public inputs are
allocated before private variables.

The upstream export has 57 distinct top-level namespace scopes and every
auxiliary has a unique full namespace/label path. Seven generic bare labels
repeat: `num` (27,793 variables), `squared num` (4), `product num` (1,626),
`ephemeral inverse` (2), `boolean` (41,414), `and result` (7,319), and
`xor result` (20,480). These labels alone are not identities. The local trace
has 15 nearest source-level allocation scopes. The scope/path crosswalk
reliably identifies four groups: `ak/u,v` (2), `ar` bits (252), `nsk` bits
(252), and `rcm` bits (252).

The gadget-level correspondence preserves all 758 previous pairs and adds
27,392 Merkle authentication-path allocations, for 28,150 auxiliary mappings
plus the 8 public/ONE variables. The new mappings cover 856 allocations at
each of the 32 Merkle levels. Each candidate is selected by a unique shared
semantic gadget ID, invocation context, and allocation role; assignments are
checked only after semantic selection. All 28,150 assignments match. There
are zero duplicate semantic IDs among the tagged allocations, zero accepted
ambiguous mappings, zero candidate assignment mismatches, and zero
one-to-many, many-to-one, or many-to-many shared-ID paths. No mapping uses an
ordinal or witness value as identity. The remaining 70,488 auxiliaries on
each side are unresolved and remain unmatched rather than guessed.

Artifacts:

- Pinned allocation-provenance trace with gadget and role metadata:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-provenance-reference.json`;
  SHA-256 `a39e4d2d815dca24eead67996d94732dc9a12b13ac3f1c4881f5e5dadddf8feb`.
- Local test-only provenance trace, enriched from the previously captured
  allocation/source-frame trace without rerunning production synthesis:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-local-gadget-provenance-v2.json`;
  SHA-256 `63b2fb26bfaf02b87c08cb3a3103b294721968c090e266ab9df8a25d860d5c02`.
- Revised correspondence:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-variable-correspondence-gadget-v2.json`;
  SHA-256 `29d5115a32dea0c6a0d985d2897f8676a277c3b8179b900d0363b989464f3f48`;
  mapping fingerprint `b2728d464630bc579659cfd1415f405b8f0fcf0bd4c5d0699f3850de00f8f762`.
- Gadget-level allocation crosswalk:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-gadget-allocation-crosswalk-v2.json`;
  SHA-256 `6e403bf327c9f8abdb682283aa7c110ef95776b7067e682a4ddc26f9bccbdff4`;
  crosswalk fingerprint `7c438b3d6da3b4f4ddef2094ee6edd2611b5dadf54e58b02dc96a40bb47bde8a`.
- Provenance analysis:
  `C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-allocation-provenance-analysis-v2.json`;
  SHA-256 `1ef3daf1d6734129111106093786906389ecaf39254d8144531a5dea8f838b0c`.

The semantic IDs uniquely recover all 856 classified allocations at each
Merkle level, but only 28,150 of 98,638 auxiliary identities overall.
Remaining source metadata is insufficient for the IVK/nullifier BLAKE2s,
pk_d multiplication, point representations, note/value commitments, and
fixed-base multiplication allocations. Complete Spend correspondence is not
established. Exact Spend row alignment, complete Spend recorder synthesis,
Groth16 query compatibility, authentic parameter compatibility, and
production proof generation remain **Unverified**. The earlier
coefficient-independent incidence refinement remains exploratory and does
not add accepted mappings.

### Allocation provenance validation

- Pinned Bellman provenance exporter with Rust 1.97.0: **1 passed**; the
  pinned Spend test-system hash and satisfaction assertions passed.
- Focused provenance/correspondence and compatibility-manifest tests:
  **27 passed, 5 subtests passed**.
- Spend, Output, Bellman synthesis, QAP, Groth16, and compatibility
  regression set: **236 passed, 512 subtests passed**.
- Python compile checks and compatibility-manifest JSON validation passed.
- Spend row alignment, complete Spend recorder synthesis, and Groth16
  compatibility remain **Unverified**.

## Phase 9.21.10 — Exact ordered Sapling Output alignment

The pinned Output synthesis now matches ZyCoin in typed variable positions,
assignments, ordered constraints, and native A/B/C factorization. The
allocation updates place value-randomness bits after value multiplication,
the g_d strict representation before esk, note-randomness bits after the
Pedersen relation, and Jubjub addition/doubling result coordinates after
their intermediates. Strict-representation prefix products are allocated
before the next zero-bound bit. Output-only factorization paths reproduce
Bellman's scalar Boolean, selection, curve, commitment, and public-binding
rows without changing the cryptographic relation or generators.

The variable artifact records all 6 inputs including ONE and all 7,821
auxiliaries: 7,827 unique pairs, identical indices and assignments, and zero
unmatched, ambiguous, or mismatched entries. Mapping fingerprint:
`c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc`;
assignment-pairs fingerprint:
`23a8c322d16b8b717ae877dabe44283973d1b6f36ae10fcaa358dd8d22ed0719`.
Variable artifact SHA-256:
`3c9ce93d3bbaed16488492ea58017846b997378fceed70d7e145a1328430d113`.

The row artifact compares every coefficient and term for all 7,827 rows.
All rows are native A/B/C matches at the same row index; there are zero
factor swaps, normalizations, expanded-only matches, unmatched rows, or
ambiguous rows. The former 260 expanded-relation-only rows now use the
pinned factorization. Row-mapping fingerprint:
`69f6498dbc3d2504bcc7beb6285d3312dd68c790f41dff9b21d3c1e162de8537`;
mapped-coefficients fingerprint:
`272b0d4f3ae3ebc94deca00c0eec981bac75db8c52c43cbc7967d664d6d97b6e`;
row artifact SHA-256:
`c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761`.
Pinned export SHA-256:
`ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe`.

Fresh production and recorder Output synthesis both satisfy the witness and
match dimensions, labels, variable names/positions, assignments, and ordered
matrix serialization: 7,827 rows, 7,827 columns including ONE, and 7,821
auxiliaries. The aligned production matrix fingerprint is
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`.
This intentionally replaces the prior local fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`;
the dimensions and witness semantics are unchanged, but reproducing the
pinned allocation and ordered factorization necessarily changes the local
matrix serialization.

Exact ordered R1CS alignment does not demonstrate compatibility with
authentic Sapling proving or verification parameters. Real proving-key
compatibility, verification-key compatibility, and production proof
generation remain **Unverified** pending authentic parameter/query evidence.

### Phase 9.21.10 validation

- Bellman synthesis, Sapling Output/Spend, QAP, Groth16, and compatibility
  regression suites: **226 passed**.
- Focused variable/row correspondence and manifest tests: **27 passed**.
- Both correspondence artifacts regenerated twice with identical SHA-256.
- `compileall`, Pylance syntax/type diagnostics, and `git diff --check`
  passed. Ruff reports three existing unrelated findings in
  `src/sapling_gadgets.py` and `tests/test_sapling_gadgets.py`; they were left
  unchanged.

## Phase 9.21.12 — Spend gadget-level semantic allocation IDs

The test-only Bellman exporter now records allocation event/index, namespace
hierarchy, gadget ID, invocation context, and allocation role. Bellman's
`ConstraintSystem` API still does not expose Rust caller file or line. The
local trace uses the previously captured allocation events and Python source
frames, enriched with test-only semantic classification; production Spend
and Output synthesis were not rerun or changed.

The prior 758 pairs were retained and cross-checked. Explicit Merkle
authentication-path gadget IDs, level invocations, and roles identify 856
auxiliaries at each of the 32 levels, adding 27,392 mappings. Total coverage
is 8 public/ONE variables and 28,150 auxiliaries; all mapped assignments
agree after semantic selection. There are zero duplicate tagged semantic
IDs, zero accepted ambiguous mappings, and zero candidate assignment
mismatches. The crosswalk contains 36 gadget-invocation groups. The remaining
70,488 auxiliary variables on each side are unresolved. IVK/nullifier
BLAKE2s internals, pk_d multiplication, point representations,
note/value-commitment internals, and fixed-base multiplication do not yet
have sufficient shared semantic allocation IDs.

Artifacts:

- Upstream trace SHA-256:
  `a39e4d2d815dca24eead67996d94732dc9a12b13ac3f1c4881f5e5dadddf8feb`.
- Local enriched trace SHA-256:
  `63b2fb26bfaf02b87c08cb3a3103b294721968c090e266ab9df8a25d860d5c02`.
- Correspondence SHA-256:
  `29d5115a32dea0c6a0d985d2897f8676a277c3b8179b900d0363b989464f3f48`;
  mapping fingerprint
  `b2728d464630bc579659cfd1415f405b8f0fcf0bd4c5d0699f3850de00f8f762`.
- Crosswalk SHA-256:
  `6e403bf327c9f8abdb682283aa7c110ef95776b7067e682a4ddc26f9bccbdff4`;
  mapping fingerprint
  `7c438b3d6da3b4f4ddef2094ee6edd2611b5dadf54e58b02dc96a40bb47bde8a`.
- Analysis SHA-256:
  `1ef3daf1d6734129111106093786906389ecaf39254d8144531a5dea8f838b0c`.

### Phase 9.21.12 validation

- Pinned Bellman Spend exporter (Rust 1.97.0): **1 passed**; the exporter
  checked the pinned TestConstraintSystem hash, 98,777 rows, 8 inputs,
  98,638 auxiliaries, and witness satisfaction.
- Focused provenance, correspondence, and manifest tests:
  **33 passed, 5 subtests passed**.
- Spend, Output, Bellman synthesis, QAP, Groth16, and compatibility suite:
  **244 passed, 538 subtests passed**.
- Compatibility-manifest JSON parsing passed. The optional `cargo fmt
  --check` could not run because rustfmt is not installed for the pinned
  toolchain; exporter compilation and execution passed.

This is a defensible partial correspondence, not complete Spend alignment.
Exact Spend row alignment, complete Spend recorder synthesis, Groth16 query
compatibility, authentic parameter compatibility, and production proof
generation remain **Unverified**.

## Phase 9.20.73 — Output recorder reconstruction boundary

The existing Output composition in
`src/sapling_gadgets.py::constrain_sapling_output` was traced through its
value-commitment, ephemeral-key, and note-commitment stages. The established
local R1CS snapshot has public inputs `(cv.u, cv.v, epk.u, epk.v, cmu.u)`,
7,827 rows, 7,821 auxiliaries, the allocation ranges recorded in the
compatibility manifest, and local matrix fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.

**Reconstruction is blocked before the first Output gadget.** The public
composition rejects any system that is not an instance of `R1CS`; this
check runs before witness validation or allocation. The added regression
passes the existing `R1CSReferenceAdapter` around the Bellman recorder and
confirms the `TypeError` occurs with no recorder variables or rows added.
Thus no recorder Output public layout, allocation trace, ordered A/B/C rows,
or matrix fingerprint was generated or compared.

Removing only that entry-point guard would not make the gadgets recorder
compatible. The first value-commitment helper requires concrete production
`Variable` and `LinearCombination` objects, and the composed gadgets call
R1CS-only `boolean`, `range_check`, `multiply`, `enforce_equal`, and witness
evaluation APIs. Strict variable checks also recur in Jubjub multiplication,
Pedersen, and note commitment. Faithful reconstruction therefore needs a
typed adapter/protocol across the Output gadget stack, preserving each
gadget's true allocation and enforce order; translating rows from the
existing matrix is not acceptable and was not done.

**Status:** recorder-backed Output reconstruction **Blocked at the API
boundary**; existing local Output evidence remains separate. No production
Output assembly, equations, parameters, or spending gates changed. Local
Output counts/fingerprint do not establish equality with an upstream
Bellman matrix; whole-circuit equivalence and parameter compatibility remain
**Unverified / Blocked**. See the Output `recorder_reconstruction` entry in
the [compatibility manifest](sapling-circuit-compatibility-manifest.json).

### Phase 9.20.73 verification

- CPython 3.10.11 full test suite: **246 passed**.
- Focused recorder/manifest tests: **18 passed**; the production Output
  assembly regression: **1 passed**. The full suite includes the no-mutation
  recorder-boundary regression.
- Targeted Ruff, compileall, Pylance diagnostics, manifest parsing, and
  `git diff --check` passed.
- Wheel and sdist builds passed. Clean-target wheel imports and packaged
  resource checks passed; the sdist contains the compatibility manifest and
  report updates.
- The unchanged `src/r1cs.py` Ruff baseline remains **45 findings**:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.
- No production Output code changed; Sapling spending remains gated. No real
  parameters, secrets, credentials, or transactions were used.

## Phase 9.20.74 — Backend-neutral gadget synthesis slice

### Output synthesis coupling audit

The Output call chain begins at `constrain_sapling_output`. That entrypoint
still requires `R1CS`, checks its public/private allocation state and row
count directly, and runs witness validation before allocating public inputs.
It then composes value commitment, ephemeral-key multiplication, and note
commitment.

| Output stage | Concrete dependencies and required semantics |
|---|---|
| Output entrypoint and public input binding | Concrete `R1CS` type/freshness checks; `public_input_count`, `variables`, and `constraint_count`; `alloc_public`/`alloc_private`; ordered public inputs `(cv.u, cv.v, epk.u, epk.v, cmu.u)`. These protect existing entrypoint behavior and remain unchanged. |
| Point allocation and value commitment/fixed-base Jubjub multiplication | `allocate_jubjub_point` now uses backend `alloc_private` for both coordinates; its call sites in the larger composition remain typed to production `R1CS`. Fixed-base helpers and downstream paths still require concrete `Variable`/`LinearCombination` checks, `multiply`, `enforce`, `enforce_equal`, bit allocation, Boolean/range operations, and witness-value reads. |
| Diversifier-base validation and ephemeral key | Concrete Jubjub point ownership; `multiply`/`enforce`; scalar-bit reads and `_point_witness` access to `_witness_value`; allocation order for multiplication accumulators. The on-curve relation and point allocator themselves are backend-neutral, but the wider callers and scalar-multiplication graph are not. |
| Transmission-key representation | Concrete variable bit sequences, ownership checks, bit packing/linear combinations, and witness access. |
| Note commitment and Pedersen | Concrete bit and LC types; Edwards/Montgomery intermediate allocation; direct witness reads; `boolean`, `multiply`, `enforce`, and equality helpers. |
| BLAKE2s | Not in the Output synthesis call chain. Its concrete `Variable`/`LinearCombination` and R1CS witness/Boolean/multiplication dependencies belong to shared-module Spend/nullifier gadgets and are out of scope here. |
| Namespaces and annotations | Production R1CS currently flattens labels into variable/constraint names. The recorder models nested namespace paths separately, and allocation plus A/B/C row order must be preserved during later migrations. |

These are not all merely syntax differences: ownership, witness availability,
public allocation order, and A/B/C relation order are semantic constraints.
Direct state reads in the Output entrypoint are freshness/ordering guards;
host witness reads in arithmetic gadgets compute assignments for intermediate
variables but are not themselves circuit rows.

### Contract and migrated gadget

`src/synthesis.py::SynthesisBackend` is a narrow Protocol for input and
auxiliary allocation, `ONE`, linear combinations, ownership validation,
namespaces, multiplication, generic A/B/C enforcement, and equality
enforcement. Backends retain their own exception types. The interface does not
try to abstract witness validation or every helper used by Output.

Phase 9.20.74 first migrated `constrain_jubjub_point`, which is used in
Output's diversifier-base and ephemeral-key paths. It now obtains an explicit
namespace and uses only the backend operations for three products and the
twisted-Edwards equation. The production `R1CS.namespace` view preserves the
previous flattened production labels and row order. `RecorderSynthesisBackend`
uses the recorder's true variable allocations, namespace API, and A/B/C rows;
it does not import rows from the production matrix.

For the deterministic standalone point fixture, production remains at six
columns including `ONE` and four rows with fingerprint
`2285a26c3911777b051fc133f62d8b2778a01fbe758c4d7bb63d0e5f153869a8`.
The recorder emits five auxiliary variables (two point coordinates and three
products) and four rows. Mapping the recorder's Input/Aux IDs to local
columns produces the same canonical ordered matrix serialization as the
production R1CS. This verifies production-backend matrix stability for the
gadget and cross-implementation agreement for this slice only; it is not an
upstream Bellman matrix export or evidence of complete Output equivalence.
Tests also exercise `ONE`, input/aux allocation, LC construction, namespace
order, and rejection of foreign variables and expressions before synthesis
mutates either backend.

Phase 9.20.75 additionally migrates `allocate_jubjub_point`. That same helper
now allocates `u` then `v` through `SynthesisBackend.alloc_private` on both
backends. A namespaced fixture confirms the identities map as production
private columns 1 and 2 versus recorder `Aux(0)` and `Aux(1)`; the canonical
local-column matrix serializations and assigned witness coordinates match.
The allocation-only production fingerprint is
`880efe8a2dffdedc69b198304e12aa7b2519c661cd0d6541be92ce50cee4d124`.
`None` witness coordinates remain unassigned on both backends, and malformed
point inputs are rejected before allocation.

### Remaining migration boundary

The Output entrypoint's concrete `R1CS` type/freshness guard remains intact.
No complete Output recorder synthesis was performed, and the Output
allocation/constraint sequence was not changed. The value-commitment,
scalar-multiplication, representation, Pedersen, and note-commitment helpers
still use concrete R1CS variable/LC classes or APIs, including range/Boolean
constraints and witness-value access. BLAKE2s is not in the Output synthesis
call graph. Those adapters must be migrated
incrementally and compared against production matrices before a complete
recorder-backed Output path is claimed. Spend synthesis and proving behavior
were not modified. Whole-circuit equivalence and Sapling spending remain
unverified and gated.

### Phase 9.20.74 verification

- CPython 3.10.11 full test suite: **249 passed**.
- Focused recorder/gadget/manifest tests: **53 passed**.
- Targeted Ruff and compileall passed. Pylance diagnostics were empty for
  changed Python modules and tests; all 17 call sites of
  `constrain_jubjub_point` passed signature-compatibility checking.
- Wheel and sdist builds passed; the sdist includes the new synthesis
  interface and final reports. A clean-target wheel install imported the
  recorder, backend, Jubjub, and gadget APIs and accessed the packaged
  BitcoinZ coin resource.
- `git diff --check` and manifest JSON parsing passed.
- The 45 pre-existing Ruff findings in `src/r1cs.py` remain:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.76 — Backend-neutral Jubjub point representation

The Output representation path uses `constrain_jubjub_repr`: it constrains
strict canonical field-bit decompositions of both coordinates, then returns
the 255 little-endian `v` bits followed by the low bit of `u`. The strict
decomposition checks ownership, reads the assigned field value, allocates
high-to-low bits, enforces Boolean and conditional-Boolean constraints,
builds prefix-AND witnesses, reverses to little-endian order, and constrains
the coordinate to equal the reconstructed bits. This is the operation
migrated here; `allocate_unchecked_jubjub_repr`, used for Output `pk_d`, is a
different witness-only API and was not changed.

`constrain_jubjub_repr` now creates a backend namespace and invokes the
shared strict-bit decomposition for `u` and `v`. The helper uses only the
backend contract's ownership check, witness access, auxiliary allocation,
linear-combination construction, multiplication, enforcement, and equality
operations. `R1CS.witness_value` exposes the same owned-variable lookup used
internally by the production gadget; the recorder delegates to its own
witness assignment. Existing R1CS callers retain the same public function
signature and production label flattening.

For `u = 1`, `v = SCALAR_MODULUS - 1`, both backends synthesize 776 ordered
rows and 777 local columns including ONE, returning 256 representation bits.
The production matrix retains the pre-change fingerprint
`32695731f48144ff08bc2b0cce8394f7fe0f160e3cd22d71b84dbe1fdf28dda0`;
recorder local-column serialization exactly equals the production matrix,
and mapped witness assignments match. The existing Spend/Merkle point
representation callers continue using the same API. Tests reject a changed
coordinate, a changed representation bit, and a modulus-alias bit pattern;
they also preserve unassigned coordinate/bit witnesses and reject a
cross-backend coordinate before recorder mutation. This is local cross-
backend synthesis agreement, not Bellman execution or a whole-circuit
equivalence claim.

The Output entrypoint still requires concrete `R1CS`. Point allocation is
backend-neutral, but Output host witness validation, scalar multiplication,
value commitment, the unchecked transmission-key representation allocator,
Pedersen, and note commitment retain concrete R1CS dependencies. Spend,
Merkle behavior, parameter trust, proof generation, and Sapling spending
gates are unchanged.

### Phase 9.20.76 verification

- Focused CPython 3.10.11 representation, recorder, gadget, Spend/Merkle,
  and manifest tests: **62 passed**.
- Targeted Ruff, compileall, JSON validation, and `git diff --check`: passed
  for the changed source/test files. The unchanged `src/r1cs.py` was excluded
  from this targeted Ruff run because of its recorded baseline below.
- Pylance diagnostics: no issues in the changed Python files;
  `constrain_jubjub_repr` signature compatibility: all 15 call sites passed.
- Wheel and sdist builds passed. A clean-target wheel install imported
  `zycoin.sapling_gadgets`, `zycoin.synthesis`, and
  `zycoin.bellman_synthesis`; the packaged coin-resource directory was
  accessible. The sdist contains the updated synthesis modules.
- CPython 3.10.11 full test suite: **252 passed**.
- The 45 pre-existing Ruff findings in `src/r1cs.py` remain:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.77 — Backend-neutral Jubjub conditional selection

The Output dependency graph's variable-base Jubjub scalar multiplication
selects either the current doubled base point or the identity using each
Boolean scalar bit. That coordinate selection was factored into
`constrain_jubjub_select`, which expresses
`selector * (when_true - when_false) = selected - when_false` independently
for `u` and `v`. The caller remains responsible for constraining the selector
as Boolean and for applying point membership/representation constraints
where required. The scalar-multiplication call site retains its existing
Boolean row, allocation sequence, equations, row order, and labels; its
variable-selector branch now calls the shared helper. The preconstrained
negated-bit path retains its existing equations.

For selector values zero and one, the production and recorder fixtures each
have 3 rows and 8 local columns including ONE. They produce identical
local-column matrix serialization and mapped witness assignments. The
production fingerprint is
`ffc4829f0e72c68da37758b7c077b8793a155658b36406ab577e61fd44b9d920`.
Tests show that an invalid selector violates the Boolean row, changing the
selected coordinate violates the mux relation, and changing the unselected
branch coordinate does not alter selection. Foreign point variables are
rejected before either backend mutates. Existing curve-membership and strict
representation regressions continue to reject invalid points and
noncanonical field aliases; the mux itself does not replace those checks.

This is one backend-neutral relation within scalar multiplication, not a
migration of scalar multiplication or point validation. The Output entrypoint
still has its concrete-R1CS guard, and whole-circuit/upstream matrix
equivalence remains unverified.

### Phase 9.20.77 verification

- Focused recorder, selection, gadget, Spend, and manifest suites:
  **64 passed** on CPython 3.10.11.
- Targeted Ruff, compileall, manifest JSON validation, and `git diff --check`
  passed. Pylance diagnostics were empty for changed Python files; signature
  compatibility passed for all 5 `constrain_jubjub_select` call sites.
- Wheel and sdist builds passed. A clean-target wheel install imported the
  selection API, synthesis interface, and recorder and accessed packaged coin
  resources; the sdist contains the updated synthesis modules.
- Full CPython 3.10.11 suite: **254 passed**.

## Phase 9.20.78 — Backend-neutral affine Jubjub doubling

The scalar multiplication call graph repeatedly doubles its current base
point before selecting it for the next scalar bit. Of the remaining concrete
operations, affine doubling is the smallest complete building block: it
consumes two represented points and emits the same three multiplication
intermediates plus two division-relation rows. `constrain_jubjub_double` now
uses the `SynthesisBackend` contract while retaining its R1CS overload and
signature. Its allocations remain caller-owned; the operation preserves
variable order, exact equations, row order, labels, and assigned result
witness semantics. It does not add point-membership checks.

For the spending-key base point and the identity, production and recorder
each synthesize five rows and eight local columns including ONE. The base
fixture fingerprint is
`12ba0c9c8b468d3aab43719068b117d58ebc06777ee7647ae0724378e586c8d6`;
mapped matrix serialization and all auxiliary witness values agree. An
independently computed host point doubling supplies the expected result.
Tampering with either result coordinate or any multiplication intermediate
violates production constraints, and foreign coordinates are rejected before
either backend mutates. The existing scalar-multiplication, Spend, and Merkle
callers retain the same API.

Scalar bit allocation/decomposition, Boolean checks, selector integration,
accumulation, and full scalar multiplication remain concrete-R1CS coupled.
The Output entrypoint still retains its concrete-R1CS guard. This isolated
comparison is not Bellman execution or full Output equivalence.

### Phase 9.20.78 verification

- Focused doubling, recorder, gadget, Spend, and manifest suites:
  **67 passed** on CPython 3.10.11.
- Full CPython 3.10.11 suite, targeted Ruff, compileall, Pylance/signature
  checks, `git diff --check`, wheel/sdist, and isolated wheel checks: passed.
- Full CPython 3.10.11 suite: **257 passed**.
- The 45 existing Ruff findings in unchanged `src/r1cs.py` remain separately
  tracked: 13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.85 — Audit and isolate Boolean handling in Output representation

This phase is audit-only. It leaves the Phase 9.20.84 unchecked allocator,
all synthesis behavior, and the Output entrypoint guard unchanged. The
production Output regression now asserts the exact Boolean row labels and
counts for value bits (64), `rcv` (252), `pk_d` representation (256), and
`rcm` (252), in the source synthesis order.

The unchecked `pk_d` allocator adds no Boolean rows. In Output,
`_constrain_note_commitment` owns its 256 bit constraints, in ascending
representation order (`v[0..254]`, then the `u` sign bit), before the 252
`rcm` Boolean rows. Pedersen is called with
`message_bits_preconstrained=True`, so it adds no second Boolean rows for
message bits. The six personalization bits are literal ones, not allocated
variables. Lookup/AND relations remain distinct equations, not duplicate
Boolean checks.

The separate value-commitment bits are constrained earlier by their
fixed-base multiplications: value bits first, then `rcv` bits, each in
ascending index order before the respective lookup rows. The later
note-commitment value decomposition is marked preconstrained and emits no
duplicate rows. Likewise `rcm` is Boolean-constrained in note commitment;
its fixed-base multiplication is told those bits are preconstrained because
range enforcement is disabled for Output. The direct `R1CS.boolean` calls
remain in note commitment and fixed-base multiplication. The shared
`_constrain_jubjub_scalar_bit` helper expresses the same relation through
`backend.enforce` but is not currently used by these loops and retains an
R1CS-specific ownership branch.

Recommended next isolated migration: route only the 256 `pk_d` Boolean rows
through `_constrain_jubjub_scalar_bit`, using the backend ownership contract.
Test 0/1 assignments, tampering, foreign-variable rejection before mutation,
exact row A/B/C and label order on both backends, plus the full Output
fixture's unchanged matrix and the existing 256-label regression. Do not
migrate fixed-base multiplication, value commitment, note-commitment
orchestration, Pedersen, or the Output guard as part of that next slice.

**Status:** full Output recorder synthesis remains **Blocked**; upstream
Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.85 verification

- CPython 3.10.11 full suite: **275 passed**; focused Output, recorder, and
  compatibility-manifest tests: **13 passed**. Ruff, `compileall`, and
  `git diff --check` passed. Pylance diagnostics were empty for the changed
  Python files; signature compatibility checks found all 5 Output entrypoint
  callers and all 8 unchecked-allocation callers compatible. Wheel and sdist
  builds passed. A clean-target wheel installation imported `zycoin` and
  loaded all 8 packaged coin JSON resources.

## Phase 9.20.86 — Backend-neutral `pk_d` Boolean enforcement

The 256 `pk_d` Boolean checks in `_constrain_note_commitment` now call the
existing `_constrain_jubjub_scalar_bit` helper. The helper validates variable
ownership before emitting the same `bit * (bit - 1) = 0` equation through
`SynthesisBackend.enforce`. No other note-commitment operation changed.

The isolated production/recorder fixture allocates and constrains all 256
bits in a nested namespace. It confirms matching variable mappings, names,
assigned witnesses, 256 ordered rows, the unchanged constraint labels, and
the local matrix fingerprint
`d7ea7fec9edd70b8333431e6cc81379702bc6b7ce37676eac784893493608168`.
Production satisfaction rejects a bit assigned `2`; foreign R1CS and
recorder variables are rejected before mutation. The full Output regression
continues to verify its 7,827-row matrix and that no downstream duplicate
`pk_d` Boolean rows are emitted.

The unchecked representation allocator and Output entrypoint guard are
unchanged. **Full Output recorder synthesis remains Blocked** and upstream
Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.86 verification

- CPython 3.10.11 full suite: **276 passed**; focused `pk_d`, Output, and
  compatibility-manifest tests: **13 passed**. Ruff, `compileall`, and
  `git diff --check` passed. Pylance diagnostics were empty for all changed
  Python files; `_constrain_note_commitment`'s 11 call sites passed signature
  compatibility checks. Wheel and sdist builds passed; the sdist contains
  the implementation, tests, and compatibility manifest. A clean-target
  wheel import loaded all 8 packaged coin JSON resources.

## Phase 9.20.87 — Audit of Output `rcm` Boolean enforcement

The Output entrypoint derives the 252 `rcm` witnesses from the note
commitment randomness in little-endian order and allocates them immediately
after the 256 unchecked `pk_d` representation bits. Their production R1CS
columns are 5063–5314, named `Sapling Output rcm bit[index]`. The focused
Output regression verifies all names, the contiguous identities, and each
assignment against `witness.note_commitment.rcm_bits`.

`_constrain_note_commitment` owns exactly 252 Boolean rows because
`randomness_bits_preconstrained` is false at the Output call site. The current
loop calls concrete `R1CS.boolean`, not `_constrain_jubjub_scalar_bit`.
Rows are contiguous and labeled `Sapling Output note commitment rcm bit[i]`,
immediately after the `pk_d` Boolean rows and before content-hash rows.
Assigned `rcm` bits are read and compared with the witness tuple before
constraint emission; Boolean satisfaction rejects non-binary assignments.

Pedersen does not consume `rcm`; its message is the note value, `g_d`
representation, and `pk_d` representation. The same `rcm` variables feed
fixed-base randomness multiplication after Pedersen. Output disables scalar
range enforcement, making the fixed-base call treat these bits as
preconstrained and add no duplicate Boolean checks. Thus `rcm` enforcement
is **not backend-neutral** and remains concrete-R1CS.

Recommended next isolated migration: route only the 252 `rcm` checks through
`_constrain_jubjub_scalar_bit`, retaining labels, loop/constraint order,
namespace behavior, and the preconstraint branch. This phase made no
synthesis-code or API changes. Full Output recorder synthesis remains
**Blocked**; upstream Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.87 verification

- CPython 3.10.11 full suite: **276 passed**; focused Output and
  compatibility-manifest tests: **12 passed**. Ruff, `compileall`, manifest
  JSON validation, and `git diff --check` passed. Pylance diagnostics were
  empty for the changed Python files; `_constrain_note_commitment`'s 11 call
  sites passed signature compatibility checks. Wheel and sdist builds
  passed; the sdist includes the implementation, tests, and manifest. A
  clean-target wheel import loaded all 8 packaged coin JSON resources.

## Phase 9.20.88 — Backend-neutral `rcm` Boolean enforcement

Only the 252 `rcm` Boolean checks in `_constrain_note_commitment` now use
`_constrain_jubjub_scalar_bit`. Allocation remains unchanged. The branch on
`randomness_bits_preconstrained`, LSB-first loop, labels, namespace behavior,
and placement immediately after `pk_d` rows and before note content-hash
rows are preserved. The helper validates backend ownership before emitting
the same Boolean equation through `SynthesisBackend.enforce`.

The isolated nested-namespace production/recorder fixture verifies 252
ordered rows, matching labels, variable maps, names, and witness assignments.
The local matrix fingerprint is
`2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467`.
Production satisfaction rejects a witness bit assigned `2`, and foreign
variables are rejected before mutation. The full Output regression retains
its 7,827-row matrix and confirms the `rcm` rows remain between `pk_d` and
content-hash constraints. The downstream fixed-base multiplication continues
to treat the bits as preconstrained, adding no duplicate Boolean checks.

The enclosing note-commitment and Output paths remain concrete-R1CS; full
Output recorder synthesis is **Blocked**, and upstream Bellman matrix
equivalence is **Unverified**. The next small candidate is the fixed-base
scalar-bit Boolean enforcement used for Output value and `rcv` inputs.

### Phase 9.20.88 verification

- CPython 3.10.11 full suite: **277 passed**; focused `rcm`, Output, and
  compatibility-manifest tests: **13 passed**. Ruff, `compileall`, manifest
  JSON validation, and `git diff --check` passed. Pylance diagnostics were
  empty for the changed Python files; `_constrain_note_commitment`'s 10 call
  sites passed signature compatibility checks. Wheel and sdist builds
  passed; the sdist includes the implementation, tests, and manifest. A
  clean-target wheel import loaded all 8 packaged coin JSON resources.

## Phase 9.20.89 — Audit of Output value and `rcv` Boolean enforcement

The Output entrypoint allocates the 64 `value_bits` first (production columns
6–69), then the 252 `rcv` bits (columns 70–321), both least-significant bit
first and directly under the supplied Output label. The Output regression
checks the exact names, contiguous identities, and assignments against
`witness.value_commitment.value_bits` and
`witness.value_commitment.randomness_bits`.

`_constrain_sapling_value_commitment` invokes
`_constrain_fixed_base_jubjub_mul` first for the value, then for `rcv`.
Because both calls have scalar-range enforcement disabled and leave
`bits_preconstrained` at its default `False`, the fixed-base helper emits
the Boolean rows directly via `R1CS.boolean`; neither path uses
`_constrain_jubjub_scalar_bit`. The 64 value rows are the first Output
constraints and precede value lookup rows. The 252 `rcv` rows follow all
value-multiplication rows and precede `rcv` lookup rows. Labels are
`Sapling Output value commitment value multiplication scalar bit[i]` and
`Sapling Output value commitment randomness multiplication scalar bit[i]`.
There is no backend namespace scope.

The witness is validated before Output allocation, and the helper stack
compares assigned bits to their witness tuples. The 64 value bits are reused
by note commitment with `value_bits_preconstrained=True`, preventing
duplicate Boolean rows while retaining the value encoding relation. `rcv`
bits have no downstream reuse. The Boolean loops, fixed-base lookup path,
and enclosing value commitment remain concrete-R1CS.

Recommended next isolated migration: route only the shared fixed-base
scalar-bit Boolean loop through `_constrain_jubjub_scalar_bit`, retaining
the current range/preconstrained branches. This would cover both Output bit
groups without migrating lookup, allocation, or accumulation logic. This
phase is audit-only. Full Output recorder synthesis remains **Blocked**;
upstream Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.89 verification

- CPython 3.10.11 full suite: **277 passed**; focused Output and
  compatibility-manifest tests: **12 passed**. Ruff, `compileall`, manifest
  JSON validation, and `git diff --check` passed. Pylance diagnostics were
  empty for changed Python files; signature checks found all 5 fixed-base
  helper call sites and both value-commitment call sites compatible. Wheel
  and sdist builds passed; the sdist includes implementation, tests, and
  reports. A clean-target wheel import loaded all 8 packaged coin JSON
  resources.

## Phase 9.20.90 — Backend-neutral fixed-base Boolean enforcement

Only the Boolean loop in `_constrain_fixed_base_jubjub_mul` changed: it now
calls `_constrain_jubjub_scalar_bit` instead of `R1CS.boolean`. The loop's
location, ordering, labels, and condition are unchanged. Ownership is checked
before the shared `SynthesisBackend.enforce` relation. No allocation,
lookup, multiplication, accumulation, scalar-range, or preconstrained logic
changed.

The Output fixture still verifies 64 value rows and 252 `rcv` rows in their
original positions, as well as the unchanged complete 7,827-row matrix.
Note commitment still reuses value bits as preconstrained; it adds no
duplicate Boolean rows. The preconstrained fixed-base path continues to skip
the loop. Full-width scalar-range enforcement remains on the existing
pack/range path; other cases retain the existing Boolean branch.

Nested-namespace production/recorder parity fixtures verify 64 value-bit
rows and 252 `rcv` rows, labels, variable maps, and witnesses. Their local
matrix fingerprints are respectively
`0647ab54621fcd156c698b16eac2aef84b1529bd5230926f6cf570ff820d7abc` and
`2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467`.
Invalid Boolean assignments fail production satisfaction; foreign
production/recorder variables are rejected before mutation.

This migrates only Boolean enforcement; `_constrain_fixed_base_jubjub_mul`
and Output remain concrete-R1CS around lookup, witness, allocation, and
accumulation operations. Full Output recorder synthesis remains **Blocked**;
upstream Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.90 verification

- CPython 3.10.11: full suite **278 passed**; focused fixed-base/manifest
  tests **12 passed**. Ruff and compileall passed; Pylance reported no
  diagnostics in changed Python files. The unchanged helper signature has
  five compatible call sites. Final wheel/sdist builds and installed-wheel
  import/resource checks passed, including all 8 coin JSON files; `git diff
  --check` passed.

## Phase 9.20.92 — Audit fixed-base 3-bit lookup relation

Audit-only: no circuit implementation, allocation, equation, constraint,
public API, or Output entrypoint guard changed. The lookup table is built per
fixed base from `(0P, 1P, ..., 7P)`; successive window bases are `8P`.
Fixed-base multiplication consumes the little-endian scalar in ascending
three-bit windows. Within each window `a`, `b`, `c` represent bit offsets
`0`, `1`, `2`, selecting index `a + 2b + 4c`. Missing high bits in the last
partial window are literal zeroes.

Output value multiplication has 22 windows: 21 full windows and one final
one-bit window. Its `b AND c` is constant-folded to zero in that partial
window, so that lookup contributes two coordinate rows there instead of
three. The 252-bit `rcv` multiplication has 84 full windows. Thus Output
lookup contributes 65 value rows and 252 `rcv` rows (317 total), following
each scalar's existing Boolean rows. Across both products, 106 selected
points allocate their `u` then `v` coordinates; 105 variable `bc` products
are allocated; and later windows allocate 21 value and 83 `rcv` accumulator
points before the existing affine-addition constraints.

For each coordinate, let `t[i]` be table entry `i`. The gadget computes
`base = t0 + b(t2-t0) + c(t4-t0) + bc(t6-t4-t2+t0)` and
`factor = (t1-t0) + b(t3-t2-t1+t0) + c(t5-t4-t1+t0) +
bc(t7-t6-t5+t4-t3+t2+t1-t0)`. It enforces
`factor * a = selected_coordinate - base`, first for `u`, then `v`.
For variable window bits, rows are appended as `bc multiplication`,
`coordinate[0]`, `coordinate[1]`; the `bc` row is `b * c = bc`.
The Output path passes its concrete `R1CS` directly and composes names into
labels such as `Sapling Output value commitment value multiplication
lookup[0] ...`; it does not enter a namespace scope.

The fixed-base wrapper reads assigned scalar bits and matches them to the
host witness before lookup. For variable `b` and `c`, `R1CS.multiply`
evaluates the `bc` witness. The lookup helper does not read selected-point
coordinates directly: the already allocated witness coordinates are bound by
its A/B/C rows. The preconstrained path still relies on the caller's prior
Boolean checks; 252-bit range enforcement still runs before lookup when its
existing flag selects that branch. Output disables scalar range enforcement
and does not mark its bits preconstrained, so its Boolean rows remain before
lookup with no duplicate checks. Output value and `rcv` share the unsigned
lookup helper. Spend Pedersen uses its own signed three-bit lookup and table,
though it shares the `_constrained_bit_and` helper; it does not call this
unsigned lookup helper.

Remaining concrete dependencies include the `R1CS` and `CircuitPoint`
annotations, the `Variable`-only backing-bit detection, `_read_blake_bit`
for constant/negated aliases, and concrete `multiply`, linear-combination,
and `enforce` calls. The all-variable Output path uses the R1CS `bc`
multiplication followed by the two coordinate relations. No recorder lookup
was synthesized in this audit.

A focused regression exercises all eight patterns and checks exact
Boolean/`bc`/`u`/`v` row labels, A/B/C expressions, selected point assignments,
and satisfaction. The recommended next isolated migration is
`_constrain_lookup3_point` plus only the variable-aware `_constrained_bit_and`
path it needs. Keep signed lookup and its Pedersen table, note commitment,
scalar branches, addition, and Output composition outside that migration.
Because `_constrained_bit_and` is shared with the signed path, retain
Spend/Pedersen regressions. Future parity tests
should cover patterns 0–7, partial-window zero padding, ownership and witness
failures, nested namespaces, ordered rows/mappings/assignments on both
backends, the full 7,827-row Output regression, and fixed-base Spend
regressions.

Full Output recorder synthesis remains **Blocked**. Upstream Bellman matrix
equivalence remains **Unverified**.

### Phase 9.20.92 verification

- CPython 3.10.11 focused lookup, compatibility-manifest, complete Output
  7,827-row, and fixed-base Spend regressions: **14 passed**.
- Ruff, `compileall`, manifest JSON parsing, and Pylance diagnostics for both
  changed Python test files passed. Repository-wide `git diff --check` reports
  unrelated existing trailing whitespace in `src/manager.py:117,119,123`;
  the audit files themselves have none. Package builds were not run. No
  production synthesis code was modified.

## Phase 9.20.93 — Backend-neutral fixed-base 3-bit lookup

`_constrain_lookup3_point` now accepts `SynthesisBackend`, backend-native
`VariableLike` inputs, and selected coordinate pairs. Its equations and
order remain unchanged: allocate selected `u` then `v` at the caller, form
`bc=b*c` for variable operands, then enforce the `u` and `v` coordinate
relations. The variable-aware `_constrained_bit_and` path validates owners
before multiplication and uses backend linear combinations, multiplication,
and witness access. Constant and negated-bit behavior remains supported.
The signed Pedersen lookup algorithm and table are unchanged; it still shares
the AND helper and retains its regressions.

Direct production/recorder parity covers all eight table indices (three
Boolean rows plus `bc`, `u`, and `v`: **6 rows and 7 columns including ONE**)
and the partial one-bit window (one Boolean row plus `u` and `v`: **3 rows
and 4 columns including ONE**, with no `bc` allocation). Tests compare local
matrix rows, label order, variable-index mappings, witness assignments, and
selected coordinates. Foreign variables/coordinates are rejected before
mutation. Invalid and unassigned witnesses preserve the existing behavior:
Boolean and lookup constraints determine validity, and unassigned
multiplication witnesses remain unassigned.

The complete production Output regression still passes with **7,827
constraints and 7,827 columns**. Full Output recorder synthesis remains
**Blocked**: `_constrain_fixed_base_jubjub_mul` and other nested Output
subpaths still use concrete R1CS operations and have not been composed on the
recorder. Upstream Bellman matrix equivalence remains **Unverified**;
production/recorder parity is local evidence only.

### Phase 9.20.93 verification

- CPython 3.10.11 complete Sapling gadget and compatibility-manifest tests:
  **48 passed**, including Output, Spend Pedersen signed-lookup, and shared
  AND-path regressions.
- Targeted Ruff, `compileall`, Pylance diagnostics, and signature
  compatibility checks passed. The repository has unrelated pre-existing
  Ruff findings in `src/r1cs.py`; that file has no net changes from this task.
- Package builds and the full project suite were not run. Repository-wide
  `git diff --check` reports pre-existing trailing whitespace in
  `src/manager.py:117,119,123`; changed audit files are clean.

## Phase 9.20.94 — Backend-neutral fixed-base window orchestration

The fixed-base wrapper still performs scalar admission and witness checks,
then selects optional Boolean/range enforcement before its ordered window
loop. The window loop itself uses only table data, allocation of selected and
accumulator points, unsigned lookup constraints, and affine-addition
constraints. These callees already support `SynthesisBackend`; therefore
only that loop was extracted to `_constrain_fixed_base_windows`. The wrapper
keeps its production-only type checks, witness reads, range/Boolean branch,
and call order unchanged. The extracted helper pre-validates ownership of
every scalar backing variable before allocating the first selected point.

A two-window four-bit fixture exercises a complete first window and a
zero-padded final window. Production and recorder match the ordered local
matrix and common SHA-256 digest
`d0bb18f6a9dbb97594fb879fd6946be554b9f68cb35acefe59f829319e0f8d72`, all labels (accounting for their
namespace separators), every variable mapping/name/witness, and the result
coordinates. Exact totals are **11 constraints and 16 columns including
ONE**: three first-window lookup rows, two final-window coordinate rows,
four affine-addition multiplication rows, and two affine-addition relation
rows. A foreign variable in the later window is rejected with no backend
mutation. The full Output regression remains at **7,827 rows and 7,827
columns**; Spend regressions are retained.

Full Output recorder synthesis remains **Blocked**. Scalar admission and
assigned-witness validation are still concrete R1CS, as are the optional
range/packing branch and other Output subpaths. Upstream Bellman matrix
equivalence remains **Unverified**.

### Phase 9.20.94 verification

- CPython 3.10.11 complete Sapling gadget and compatibility-manifest tests:
  **50 passed**, including the 7,827-row Output regression and Spend
  signed-lookup regressions.
- Targeted Ruff, `compileall`, Pylance diagnostics, and signature checks
  passed. The full project suite and package builds were not run.
- Repository-wide `git diff --check` still reports unrelated existing
  trailing whitespace in `src/manager.py:117,119,123`; changed audit files
  are clean.

## Phase 9.20.95 — Backend-neutral fixed-base scalar validation

`_constrain_fixed_base_scalar` now runs scalar admission, witness-shape and
assigned-bit checks, ownership validation, Boolean enforcement, packing, and
range enforcement through `SynthesisBackend`. `VariableLike` is runtime
checkable for backend-independent variable recognition; ownership and witness
reads remain delegated to the selected backend. The existing
`_constrain_fixed_base_windows` interface and the fixed-base wrapper's
validation-before-window order are unchanged.

The 252-bit range-enforced scalar fixture matches production and recorder at
**876 rows and 875 columns including ONE**. A complete fixed-base call with
84 windows matches at **1,626 rows and 1,625 columns including ONE**, with
common local matrix SHA-256
`aadef2e1b28c133bb86798085aa92f66525af7eac38d46e673f8f003bfb401f0`.
Tests compare ordered matrices, labels, variable mappings, witness
assignments, and output variables. Values 0, 1, and the Jubjub scalar modulus
minus one match; invalid/unassigned, out-of-range, mismatched-witness, and
foreign-variable cases are rejected before constraint mutation. Existing
preconstrained behavior emits no duplicate Boolean checks.

The Output entrypoint guard, production equations, and allocation path remain
unchanged. The full Output production matrix remains **7,827 rows and 7,827
columns**, and the existing Output regression passes. Spend signed-lookup
regressions also pass. This does not resolve other concrete Output synthesis
dependencies: full Output recorder synthesis remains **Blocked**, and
upstream Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.95 verification

- CPython 3.10.11 Sapling gadget suite: **43 passed**, including the complete
  Output regression and Spend signed-lookup regressions.
- Compatibility-manifest suite: **11 passed**.
- Targeted Ruff, `compileall`, Pylance diagnostics, and changed-file
  `git diff --check` passed. No public API signature changed.
- Full project suite, packaging builds, and clean-target wheel checks were
  not run in this phase.

## Phase 9.20.96 — Remove the concrete Output backend guard

The Output entrypoint now accepts the fresh-backend capability protocol
instead of requiring `R1CS`. Freshness is exposed by both production R1CS and
the recorder adapter; public-input position checks are backend operations.
The first newly exposed concrete Output boundary,
`_constrain_sapling_value_commitment`, now validates and synthesizes through
`SynthesisBackend` while preserving the original row order and fixed-base
calls.

The isolated value-commitment relation matches production and recorder at
**1,889 rows and 1,888 columns including ONE**, with identical ordered
matrices, labels, variable order/names, and witness assignments. Its common
local matrix SHA-256 is
`885b7d51797f2d65e89e4ada3e8bdd5ca8fc3187eef421fbe4f7463bbc65d592`.
Foreign backend variables are rejected before this helper emits constraints.
The full production Output regression remains **7,827 rows and 7,827
columns**, with the original matrix regression passing.

The recorder now passes the entrypoint guard and synthesizes the value
commitment, but then fails at `constrain_sapling_ephemeral_key`: that path
still requires concrete `R1CS` scalar bits. This failed attempt leaves a
partial recorder with **1,265 rows, 6 inputs including ONE, and 1,517
auxiliary variables**. Invalid host witnesses and non-fresh backends are
still rejected before mutation. The next isolated migration is the
ephemeral-key operation and its Jubjub scalar-multiplication/point-validation
dependencies. Full Output recorder synthesis remains **Blocked**; upstream
Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.96 verification

- CPython 3.10.11 Sapling gadget/Spend and compatibility-manifest tests:
  **56 passed**.
- The full Output production matrix remains unchanged; no complete recorder
  Output matrix or fingerprint is available.
- Targeted Ruff on the changed gadget, protocol, recorder, and test files,
  `compileall`, Pylance diagnostics, and signature checks passed. Ruff's
  `E,F` check on `r1cs.py` reports five unrelated existing E501 lines (58,
  67, 401-403); they were left untouched. Full-project tests and package
  builds were not run.

## Phase 9.20.97 — Backend-neutral Sapling ephemeral-key constraints

`constrain_sapling_ephemeral_key` now accepts `SynthesisBackend` variables.
It validates owned scalar bits, public coordinate positions, assignments,
scalar/witness consistency, and the `g_d` point witness before adding
constraints. `_point_witness` and `constrain_jubjub_not_small_order` now use
the shared witness and ownership protocol operations. Existing Jubjub
scalar-multiplication, curve, doubling, selection, and accumulation helpers
are reused; no scalar bit order, allocation order, equation, label, or
enforcement order changed.

The ephemeral-key fixture and scalar boundaries 0, 1, and the Jubjub scalar
modulus minus one match across production R1CS and recorder at **3,539 rows
and 3,544 columns including ONE**. Ordered local matrices,
labels, variable names/mappings, witness assignments, and result coordinates
match; common local SHA-256:
`c70a14e6c311b6b029651659ff03a7fec711bd2c4333ccecca138280c65d0a1b`.
Both backends reject non-Boolean and unassigned bits, foreign variables,
out-of-range scalar witnesses/bits, and mismatched witnesses before
constraint mutation.

A fresh full Output recorder attempt now completes the ephemeral-key
operation and exposes the next, separate concrete dependency:
`_constrain_note_commitment` rejects the recorder-backed note-value
expression. The partial recorder has **4,804 rows, 6 inputs including ONE,
and 5,309 auxiliary variables**; this is not complete Output synthesis and
has no complete-output matrix fingerprint. The production Output regression
remains **7,827 rows and 7,827 columns**, with fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No note-commitment, Pedersen, value-commitment, or fixed-base implementation
was changed. Upstream Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.97 verification

- CPython 3.12.10 Sapling gadget/Output, Spend, and compatibility-manifest
  suites: **79 passed**; the manifest suite was rerun against the updated
  manifest: **11 passed**. Final scalar-boundary and mapped-matrix parity
  tests: **2 passed**.
- Ruff, `compileall`, manifest JSON parsing, and task-file whitespace checks
  passed. Repository-wide `git diff --check` reports only three existing
  trailing-whitespace lines in unrelated `src/manager.py` (117, 119, 123);
  they were left unchanged.

## Phase 9.20.99 — Backend-neutral Sapling Pedersen hash

`constrain_pedersen_hash` and its Edwards and Montgomery implementations now
accept the existing `SynthesisBackend`. Pedersen input reads validate variable
ownership and assigned bit values through backend-neutral operations before
emitting constraints. Pedersen intermediate values use
`LinearCombinationLike` and `VariableLike`; allocation, Boolean equations,
and row enforcement use the existing backend interface. The Montgomery
signed-window selection, Edwards additions, generators, personalization,
bit order, labels, and enforcement order are unchanged. The production
`R1CS` overload and its `CircuitPoint` return type remain available.

Isolated Pedersen synthesis used the Output note-hash witness on both
representations. The Montgomery relation matched at **1,558 rows and 1,559
columns**, including the caller's pre-existing message-bit Boolean rows. The
production matrix fingerprint is
`b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76`;
the exact serialized-matrix SHA-256 shared with the recorder is
`fc2a2fd1437f7eeb4e4081a9bf36525ff6adeccb17a644aafdf8d98642700b74`.
The Edwards relation also matched at **2,314 rows and 2,315 columns**.
Both backends agree on ordered matrices, labels, variable mappings,
assignments, and result coordinates. The production R1CS and an independent
evaluation of every recorder row are satisfied.

Malformed constants, a non-Boolean assigned bit, an unassigned bit, and
foreign-backend variables are all rejected before Pedersen mutates the
backend. A fresh complete Output synthesis then completed on both backends.
Production and recorder matched exactly at **7,827 rows and 7,827 columns**,
including ordered matrices, labels, variable mappings, and assignments; both
constraint systems satisfy. The production fingerprint remains
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No subsequent concrete dependency was exposed on the complete Output path.
This recorder agreement does not establish upstream Bellman matrix
equivalence, which remains **Unverified**.

### Phase 9.20.99 verification

- Combined Sapling gadget/Output/Spend and compatibility-manifest suites:
  **63 passed**, including **284 subtests**. The isolated Pedersen input
  rejection/parity checks also pass.
- Ruff `E,F` checks passed with the existing `E501` baseline excluded;
  `compileall`, manifest JSON parsing, and changed-file whitespace checks
  passed. Pylance diagnostics were empty and all nine Pedersen call sites
  passed signature compatibility.

## Phase 9.20.98 — Backend-neutral note-value commitment boundary

The internal `_constrain_note_commitment` now accepts `SynthesisBackend`,
`VariableLike`, and `LinearCombinationLike` note values. The shared protocol
adds owned linear-combination witness evaluation, implemented by production
R1CS, its namespace, and the recorder backend. Note-value range checking,
Boolean constraints, ownership validation, public-coordinate checks, witness
reads, representation constraints, and the post-Pedersen fixed-base/addition
path use the existing backend-neutral helpers. The public
`constrain_note_commitment` signature remains R1CS-specific and unchanged.

The note-commitment relation's Output prefix was compared across production
and recorder from a fresh Output entrypoint through, but not including,
Pedersen synthesis. A test boundary sentinel stopped each run at that call.
Both backends emitted **6,088 rows and 6,089 columns including ONE**, with
matching ordered local matrices, labels, variable mappings, and witness
assignments. Common local SHA-256:
`ee6e68379fb5e5eb144d460fd483acab8b69f68ffdf8e3437a15948502e62c6e`.
The production prefix is satisfied; recorder satisfaction evaluation is
not provided. Invalid types, unassigned/foreign note values, and values
outside the 64-bit range are rejected before note-commitment mutation.

A separate fresh complete Output recorder attempt reaches the next concrete
dependency, `constrain_pedersen_hash`, whose R1CS-specific bit reader rejects
recorder variables. That partial attempt ends at **6,088 rows, 6 inputs
including ONE, and 6,083 auxiliary variables**. It is not complete Output
synthesis. The full production Output regression remains **7,827 rows and
7,827 columns**, fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No Pedersen code or cryptographic equation was changed. Upstream Bellman
matrix equivalence remains **Unverified**.

### Phase 9.20.98 verification

- CPython 3.12.10 Sapling gadget/Output, Spend, and compatibility-manifest
  suites: **82 passed**. Final focused Output, note-commitment, and manifest
  rerun: **16 passed**.
- Ruff `E,F` checks passed with unrelated baseline `E501` findings excluded.
  `compileall`, manifest JSON validation, and task-file whitespace checks
  passed.

## Phase 9.21.00 — Pinned Bellman Output equivalence audit

The comparison target remains Sapling Crypto
`88a7946b4a3066787776e11f0a502654167e022d` and Bellman
`b726862a4ece8a627e7fea486d77b502a6edbb0b` (0.15.0). The pinned Output test
source asserts **7,827 constraints**, six inputs including ONE, and
TestConstraintSystem hash
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`.
That hash is not a matrix fingerprint and contains no exported witness
assignments. Public input order `(cv.u, cv.v, epk.u, epk.v, cmu.u)` agrees
with local `Input(1..5)` after `Input(0)=ONE`. The existing local production
and fresh-recorder matrix remains **7,827 rows × 7,827 columns**, fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
This verifies local backend parity, not upstream equivalence.

The pinned synthesis source and local allocation manifest show three
auxiliary allocation-stage order differences:

1. Local allocates both value and `rcv` bit arrays before value-commitment
   intermediates; upstream computes the value-base product before allocating
   `rcv`.
2. Upstream checks and represents `g_d` before `esk` and `epk`; local creates
   the `g_d` representation after the ephemeral-key relation.
3. Upstream performs note Pedersen before `rcm` allocation; local allocates
   `rcm` before Pedersen.

These are source-order differences, not a demonstrated equation mismatch.
Because a complete typed upstream allocation/assignment trace and ordered
A/B/C export are absent, they prevent claiming positional auxiliary identity
and leave the possibility of a semantic remapping untested. Whole-matrix
equivalence, exact query mapping, witness assignment parity, and upstream
Pedersen-path matrix comparison remain **Unverified**. The pinned source test
was invoked from its cached checkout, but Cargo compilation stopped before
test execution because `link.exe` was unavailable for the installed MSVC
target. No Bellman synthesis or upstream export occurred.

The smallest reproducible next step is to use a temporary checkout at both
pinned revisions, validate the toolchain by running the upstream Output test,
then synthesize the existing
[`sapling_output_reference.json`](../tests/fixtures/sapling_output_reference.json)
witness into a test-only observing `ConstraintSystem` (or add test-only
accessors to Bellman's `TestConstraintSystem`). Export ordered typed input
and auxiliary identities, assignments, and each ordered A/B/C row, then
compare through an explicit local-to-upstream variable map. Keep that
reference harness outside ZyCoin's Python-only runtime and dependencies.
No circuit equations or production code changed. Output proof generation
remains gated on circuit identity and authenticated parameter compatibility.

### Phase 9.21.00 verification

- Pinned upstream test invocation: **Blocked before test execution**;
  `link.exe` was not found. The source assertions above are not represented
  as executed test results.
- CPython 3.10.11: compatibility-manifest tests **12 passed**; Sapling
  gadget/Output tests **52 passed**; Spend circuit/reference/bindings tests
  **18 passed**.
- Targeted Ruff, `compileall`, and manifest JSON parsing passed. No circuit
  implementation or equations changed.

## Phase 9.21.01 — Output allocation-order effects and reference evidence

This follow-up traces the three source/local ordering differences through
their allocations and enforcement calls. The upstream sequence is from pinned
Sapling Crypto `src/circuit.rs` (`expose_value_commitment` and
`Output::synthesize`) and `src/circuit/ecc.rs` (`witness`,
`assert_not_small_order`, `repr`, and `mul`), revisions
`88a7946b4a3066787776e11f0a502654167e022d`. ZyCoin's sequence is from
`constrain_sapling_output`, `_constrain_sapling_value_commitment`,
`constrain_sapling_ephemeral_key`, and `_constrain_note_commitment` in
[`src/sapling_gadgets.py`](../src/sapling_gadgets.py). The manifest records
the per-difference trace and effect analysis.

| Difference | Allocation and enforcement effect | Compatibility interpretation |
|---|---|---|
| `rcv` relative to value-base multiplication | Upstream allocates value bits, emits their Boolean/value-base constraints, then allocates and Boolean-constrains `rcv` before its multiplication. ZyCoin allocates value and `rcv` bit variables before either multiplication, then emits value-base constraints followed by `rcv` constraints. This changes Aux indices and hence positional assignments/query entries. The source relation enforcement order (value multiplication, then `rcv` multiplication) is otherwise preserved; no A/B/C row reordering is implied by these allocations alone. | A column/assignment ordering difference; not evidence by itself of a different relation. Exact typed remapping and query indices remain unavailable. |
| `g_d` representation relative to `esk`/`epk` | Upstream allocates/checks `g_d`, emits non-small-order constraints, allocates and constrains its representation bits, then allocates/constrains `esk` and emits epk multiplication/bindings. ZyCoin allocates `g_d` coordinates and `esk` bits first, emits its curve/small-order and epk relations, then emits `g_d` representation constraints during note commitment. Aux order changes, and the representation constraint rows move across esk/epk rows. | Both column mapping and ordered-row differences. Row and variable permutation might preserve the relation, but must be demonstrated; exact A/B/C terms and a semantic mapping are unavailable. |
| `rcm` relative to Pedersen | Upstream emits note Pedersen rows before allocating and Boolean-constraining `rcm`. ZyCoin allocates `rcm` bits before note-commitment synthesis and emits their Boolean rows before Pedersen. Aux order and enforcement-row order both change; following fixed-base multiplication refers to correspondingly reordered variables. | Both column and row ordering differences. This is not a cryptographic-equation change, but an upstream proving-query mapping cannot be inferred positionally. |

For all three cases, the intended bit values and scalar decompositions are
the same, but the upstream typed assignment for each Aux identity has not
been exported. Bellman setup indexes query entries by input-then-Aux order;
therefore a positional query comparison would be invalid where the Aux order
differs. Conversely, row/column permutations alone do not prove that the
underlying relations differ. The exact ordered upstream rows, assignments,
satisfaction, and query mapping are still needed to determine compatibility
under an explicit mapping.

The existing Python tooling cannot supply this artifact. The
[`sapling_output_reference.json`](../tests/fixtures/sapling_output_reference.json)
fixture provides semantic inputs and expected outputs, and
`src/bellman_synthesis.py` records a bounded Bellman-like subset only when
driven by Python synthesis code. Existing cross-backend tests and isolated
Pedersen transcriptions do not execute the pinned Rust synthesizer and do not
contain a complete Output allocation/assignment trace or ordered A/B/C rows.
Source inspection plus aggregate row counts and the TestConstraintSystem
hash cannot reconstruct those records.

The minimum missing artifact is one deterministic export from the pinned
Sapling/Bellman revisions for this fixture: complete typed Input/Aux
allocation identities and assignments; every ordered constraint's raw A/B/C
terms (typed identities, coefficients, and row annotation); and the
satisfaction result plus upstream test hash as cross-checks. It must permit
an explicit semantic local-to-upstream variable map and query-index mapping.
Generate this in an external, test-only observer `ConstraintSystem`; do not
add Rust, native code, dependencies, or a hybrid path to ZyCoin. The prior
upstream Cargo attempt did not run because `link.exe` was unavailable.

Output/Bellman equivalence remains **Unverified**. ZyCoin production and fresh
recorder still agree at **7,827 rows × 7,827 columns**, with unchanged
production fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`. No
production circuit, cryptographic equation, generator, or runtime dependency
changed.

### Phase 9.21.01 verification

- Compatibility-manifest tests: **12 passed**. Sapling gadget/Output tests:
  **52 passed**. Spend circuit/reference/bindings tests: **18 passed**.
- Targeted Ruff, `compileall`, manifest JSON parsing, and
  `git diff --check` passed.

## Phase 9.21.02 — External Bellman Output reference export

The missing upstream evidence was generated with a test-only observer outside
ZyCoin. The observer ran against Sapling Crypto
`88a7946b4a3066787776e11f0a502654167e022d` and Bellman
`b726862a4ece8a627e7fea486d77b502a6edbb0b` (0.15.0), using the existing
deterministic Output fixture. The cached Sapling checkout is at the pinned
revision, and SHA-256 checks for the copied `src/circuit.rs`,
`src/circuit/ecc.rs`, and `src/circuit/pedersen_hash.rs` match that checkout.
The pinned Output test passed, and the observer test passed, in an isolated
WSL/Cargo 1.88.0 environment. No Rust source, native component, runtime
dependency, or hybrid path was added to ZyCoin; Spend synthesis was not run.

The export contains all six typed inputs including ONE, 7,821 typed auxiliary
allocations with assigned field values, all 7,827 ordered A/B/C rows with
typed terms, coefficients and annotations, and the satisfaction result. All
variables are assigned and the reference circuit is satisfied. Recomputing
Bellman's `TestConstraintSystem::hash` over the exported rows yields
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`,
matching the pinned test assertion. This Bellman test-system hash is not
reported as a matrix fingerprint. The JSON export's separate SHA-256 is
`ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe`.
The export remains outside the repository at
`C:/Users/EzzyG/.copilot/session-state/dedf634b-2027-4458-b86d-28e6f44497f6/files/sapling-output-reference.json`.

The local production circuit was freshly synthesized from the same fixture;
the recorder also completed from a fresh instance. Their ordered local
matrices match at **7,827 rows × 7,827 columns**, retaining production
fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
All six public assignments match the export. Semantic bit-index comparisons
also match all 64 value bits and each of the 252 `rcv`, `esk`, and `rcm` bits,
although their Aux positions differ:

| Variable block | Upstream Aux start | ZyCoin Aux start |
|---|---:|---:|
| Value bits | 0 | 0 |
| `rcv` bits | 255 | 64 |
| `esk` bits | 2,058 | 1,265 |
| `rcm` bits | 6,813 | 5,057 |

The export confirms the enforcement-order changes as well. Upstream's first
`g_d` representation Boolean rows are 1,285 and 1,673; the corresponding
local rows are 5,190 and 5,578. Upstream's first note-Pedersen row is 5,836
and first `rcm` Boolean row is 6,818; locally those begin at 6,088 and 5,836.
The first value-bit Boolean row is at row zero in both circuits, but the
local and upstream A/B factors use opposite signs/order while expressing the
same Boolean equation.

This evidence establishes the complete upstream export and selected
input/witness correspondences, not whole-circuit equivalence. A complete
semantic permutation for all auxiliary variables and a row-reordered A/B/C
comparison have not been established; the exact Groth16 query translation
therefore remains unknown. The evidence does not yet determine whether an
explicit permutation suffices or production allocation/enforcement order
must change. No production circuit change was made. Output/Bellman
equivalence remains **Unverified**, and the Bellman TestConstraintSystem
digest is not treated as an upstream matrix fingerprint.

### Phase 9.21.02 verification

- Pinned Output test and external observer export test: **1 passed each**.
- CPython 3.10.11 focused Output, Spend, and compatibility-manifest suites:
  **85 passed**.
- Fresh local production and recorder syntheses: **7,827 rows × 7,827
  columns**, identical ordered local matrices; production fingerprint
  unchanged.
- Exported assignments: all variables assigned; upstream and local
  satisfaction checks passed; public inputs plus value/`rcv`/`esk`/`rcm`
  bit assignments matched under their semantic identities.
- Exported-row recomputation reproduced the pinned Bellman test hash; it is
  not a matrix fingerprint.
- Manifest JSON and changed-file whitespace validation passed. Exact pinned
  source hashes and compatibility status are recorded in the machine-readable
  manifest.

## Phase 9.21.03 — Semantic Output matrix comparison attempt

This phase compares a fresh ZyCoin production R1CS from the same deterministic
fixture with the external Phase 9.21.02 Bellman export. It changes no
production circuit code, equations, generators, runtime dependencies, or
native components. Both systems have 7,827 rows and 7,827 columns including
ONE and are satisfied. ZyCoin retains production fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
The export SHA-256 remains
`ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe`.

The public inputs, including ONE, and the 64 value bits plus the 252-bit
`rcv`, `esk`, and `rcm` blocks are matched by circuit role and bit index
(820 auxiliaries). Exact normalized annotation matching independently finds
all 252 `esk` and 252 `rcm` identities. The known allocation offsets confirm
the upstream/local reorderings: `rcv` starts at Aux 255/64, `esk` at
2058/1265, and `rcm` at 6813/5057 (upstream/local). The value bits start at
Aux 0 in both. The full `g_d` representation and arithmetic-intermediate
mapping is not complete. After these selected mappings, **7,001 auxiliary
variables remain unaccounted for**. The simpler exact normalized-label pass
alone leaves 7,317 unmatched; those are not asserted to be genuinely
different variables. Assignment values cannot resolve these identities:
each system has 4,610 variables in repeated-value classes, with the largest
class containing 2,148 variables.

Both native row sets have 7,827 unique exact rows (no duplicate row kinds).
Their sorted native-namespace row-multiset SHA-256 values are
`217f883eb571ae9a7208a401359b6cc7070b3d60ab72f69006f18ae94b01adbd`
(ZyCoin) and
`e162369b83fdc7eddf4883a030ee86c1ac97f4544dba76ab5cba955cb83fd8b9`
(upstream). The canonicalizer sorts terms Input-before-Aux then by index,
preserves A/B/C side order and coefficients, and sorts the row multiset.
Since unresolved typed auxiliary identities differ, these native-index
hashes are not direct cross-system comparisons.

One strict mismatch is established under the known identity of value bit 0.
At row 0, ZyCoin has `A=Aux(0)`, `B=Input(0)*(p-1)+Aux(0)`, `C=0`; upstream
has `A=Input(0)+Aux(0)*(p-1)`, `B=Aux(0)`, `C=0`, where `p` is the scalar
field modulus. The upstream export contains no exact counterpart to the
local row under that typed-variable identity. These factors encode the same
Boolean zero set (`x*(x-1)=0` versus `(1-x)*x=0`), so this is not evidence of
a changed satisfying relation. The exact ordered A/B/C rows still differ;
this phase did not yet apply relation-aware R1CS factor transformations.

No complete variable permutation, cross-system constraint multiset, row
permutation, or equation-equivalence proof was established. Therefore the
investigation cannot determine whether ZyCoin can remain unchanged with
explicit mappings or whether further row/QAP transformations are required.
Even semantic equation correspondence would not by itself establish
Groth16 query/proving-key compatibility: no full variable-query permutation
or row-domain transformation was derived. **Bellman matrix equivalence and
exact query mapping were Unverified at this phase.

### Phase 9.21.03 verification

- Fresh local production R1CS: **7,827 × 7,827**, satisfied; fingerprint
  unchanged. Pinned upstream export: **7,827 × 7,827**, satisfied; export
  SHA and Bellman test-hash cross-check unchanged.
- Canonicalized each side's A/B/C rows without dropping coefficients or
  terms; exact local/upstream duplicate-row counts are zero. The first
  mapped Boolean row mismatch and its exact coefficients are recorded in the
  compatibility manifest.
- CPython 3.10.11 focused Output, Spend, and compatibility-manifest suites:
  **86 passed**. Ruff passed for the changed test; manifest JSON and
  reference-export SHA-256 checks passed; `git diff --check` passed.
- Incomplete variable/row accounting is explicitly retained as Unverified
  rather than inferred from matching dimensions or assignments.

## Phase 9.21.04 — Relation-aware Output comparison status

The value-bit-0 Boolean row is not a genuine relation mismatch. ZyCoin emits
`(A, B, C) = (x, x - 1, 0)` and Bellman emits
`(1 - x, x, 0)`. Swapping A and B, then multiplying the new A factor by
`-1`, transforms the ZyCoin row into Bellman's row. This is a valid R1CS
factor transformation: the corresponding C scaling is the product of the
factor scales, and remains zero. Both rows therefore constrain the same
Boolean witness values. Their exact ordered matrices still differ.

An order-independent, relation-aware multiset comparison was also performed
for rows whose variables are all covered by the established public-input and
named-bit correspondence. All **820 of 820** rows in that mapped subrelation
match after allowing A/B factor swaps and nonzero factor scaling, with C
scaled by the product of the factor scales; there are no unmatched rows in
that subset. This result is limited to the mapped subrelation and does not
establish a row permutation or ordering correspondence.
The canonical relation-row multiset fingerprint is
`8c522a3c1ca0ab07d759af11050ac12e6503ff20305bb85beca271dde829087d`;
it is a fingerprint of this mapped subrelation, not an upstream matrix
fingerprint. The mapped subrelation has no duplicate relation-row kinds.

Constraint-incidence and neighborhood signatures were investigated for the
remaining auxiliaries, using mapped neighbors, A/B/C roles, coefficients,
and allocation context. No additional mapping is accepted: unique structural
signatures are candidate evidence, not proof of variable identity, and a
complete cross-system relation validation was not achieved. The remaining
**7,001 auxiliaries** are unaccounted for. Witness equality is supporting
evidence only and remains ambiguous because of repeated assignments.

The complete circuits remain 7,827 rows × 7,827 columns and satisfied on the
deterministic fixture; ZyCoin's production fingerprint remains
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No production circuit code or equations changed. Complete relation
equivalence, exact variable/row mappings, and Groth16 query or proving-key
translation remain **Unverified**. The external Bellman test hash remains a
test-system hash, not a matrix fingerprint.

### Phase 9.21.04 verification

- The relation-aware comparison covered 820 local and 820 upstream rows;
  all 820 mapped rows matched, with no unmatched rows in this subrelation.
- The value-bit-0 transformation is the exact A/B swap and `-1` factor
  scaling described above; the ordered matrix row remains different.
- No complete auxiliary mapping was produced. The remaining 7,001
  auxiliaries, complete relation, row order, and query mapping remain
  **Unverified**.
- Production dimensions and fingerprint were not changed.

## Phase 9.21.05 — Complete semantic Output relation comparison

The pinned Bellman export and the unchanged ZyCoin production Output circuit
were compared using a complete semantic variable correspondence. The mapping
covers all six typed inputs, including `ONE`, and all 7,821 auxiliaries.
Auxiliary identities were matched by gadget boundary, allocation role,
coordinate/bit index, and pinned source annotation; all mapped incidences and
witness assignments were checked. The mapping has no duplicate semantic keys,
unmatched variables, or assignment mismatches. Repeated witness values were
not used as identity evidence.

The newly mapped 7,001 auxiliaries partition as follows: 947 value-commitment
internals, 21 `g_d` coordinates and validation intermediates, 774 strict
`g_d` representation variables, 3,265 `epk` scalar-multiplication variables,
256 `pk_d` representation bits, 982 note-hash variables, and 756 `rcm`
multiplication/final-addition variables. These add to the previously
established 820 named scalar bits, accounting for all 7,821 auxiliaries.
Public-input positions and all assignments match; both fixture systems are
satisfied.

The ordered local and upstream A/B/C matrices are not identical: 1,722 rows
are exact at the same row index, and 5,973 rows match as an exact mapped
A/B/C multiset. A further 1,594 rows match after valid A/B factor swaps and
nonzero factor scaling, for 7,567 factor-normalized row matches in total.
The remaining 260 rows were compared by expanding `A*B-C` over the scalar
field. Their polynomials match as a multiset: 257 are identical after
expansion and three are nonzero scalar multiples. The 260 comprise 252 `epk`
selection-v factorization rows, two value-commitment public equalities, one
`g_d` curve check, two `g_d` representation reconstruction rows, two `epk`
public equalities, and one note-commitment public equality. No row or variable
remains unmatched. The comparison preserves row multiplicities; it does not
force identities between duplicate normalized rows.

This establishes semantic constraint-relation equivalence for the deterministic
Output fixture, including the Pedersen note-hash and Edwards/Montgomery paths.
It does not establish exact ordered-matrix equality: allocation and row
ordering differ, and the per-region native-index fingerprints recorded in the
compatibility manifest are intentionally not cross-system comparable. The
external Bellman test-system hash remains distinct from a matrix fingerprint.
Exact Groth16 query/proving-key translation and authentic parameter
compatibility remain **Unverified**; relation equivalence alone is not query
compatibility.

The production Output matrix remains **7,827 rows × 7,827 columns** with
fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No production circuit equations or allocation order were changed.

### Phase 9.21.05 verification

- Complete semantic mapping: six inputs and 7,821 auxiliaries; zero
  unaccounted variables, duplicate semantic keys, or assignment mismatches.
- Constraint accounting: 7,827 local and 7,827 upstream rows; all rows
  accounted for by the factor-normalized or expanded-polynomial multiset
  comparison.
- Regional native row fingerprints and matched-row counts are recorded in
  `sapling-circuit-compatibility-manifest.json`; their native variable
  namespaces differ and their hashes must not be interpreted as cross-system
  matrix fingerprints.
- Exact matrix equality and exact Groth16 query mapping remain **Unverified**.
- The production dimensions and fingerprint remain unchanged.

## Phase 9.21.06 — Output Groth16 query compatibility analysis

The complete semantic variable correspondence gives an exact input-index
translation: Bellman `Input(0)=ONE` and the five application public inputs
remain in the same positions, while the 7,821 auxiliary identities translate
through the established local-to-upstream permutation. This is sufficient to
translate an assignment vector, but not the QAP or its query points.

The pinned Bellman `create_proof` and parameter generator were inspected at
revision `b726862a4ece8a627e7fea486d77b502a6edbb0b`, together with its
`EvaluationDomain` and verifier. Bellman appends one `x * 0 = 0` row for each
input, including ONE, after circuit constraints. Output therefore has 7,833
QAP rows before zero padding and an 8,192-point domain (359 padding rows).
Both Bellman and ZyCoin use natural root-of-unity evaluation order,
inverse-FFT interpolation, the BLS12-381 scalar field, and coset generator 7.
Both form `H=(A*B-C)/(X^8192-1)` and use the 8,191 ascending-degree H
coefficients.

The Output query layout follows the input/variable identities but its points
are QAP- and toxic-waste-dependent:

| Query | Entries | Meaning/order |
|---|---:|---|
| A in G1 | 7,827 | All variables: ONE, five public inputs, then auxiliaries |
| B in G1 and G2 | 7,827 each | Same variable order as A |
| L in G1 | 7,821 | Auxiliary variables only |
| H in G1 | 8,191 | Quotient coefficients in ascending degree |
| IC in G1 | 6 | ONE followed by five public-input positions |

Parameter serialization sections are H, L, A, B_G1, B_G2. The verification
key also includes alpha, beta, gamma, and delta group elements; the proving
key includes the corresponding A/B/L/H query points. Bellman's verifier
accumulates IC[0] plus public input `i` times IC[i+1], so public-input order
must remain exact.

A variable permutation alone can reorder A/B/L/IC query entries only when the
underlying ordered QAP row polynomials and factorization are otherwise the
same. Output does not meet that condition: its row order differs, many rows
use A/B swaps or nonzero factor scaling, and 260 rows match only after
expanding `A*B-C`. Row ordering and factorization determine the interpolated
per-variable A/B/C polynomials evaluated at secret `tau`; a relation-multiset
match and variable permutation do not determine their values. H's shape and
degree indexing agree, but its query points also depend on `tau` and `delta`.
No explicit transformation of the actual Bellman query points into local
query points has been established.

A deterministic test-only synthetic setup used `tau=11`, `alpha=5`, `beta=7`,
`gamma=13`, `delta=17`, and proof randomizers `(19, 23)` on two equivalent
two-row R1CS fixtures. The second fixture reverses rows and swaps/scales the
A/B factors. Each fixture's own QAP-derived queries produce a proof accepted
by its own synthetic verification key. Their A/B/C evaluations, quotient
coefficients, A/B query points, and IC points differ; their H query points
agree because they share the same domain, `tau`, and `delta`. The first
fixture's proof is rejected by the second verification key. Regression tests
pin both evaluation vectors, polynomial/quotient coefficient fingerprints,
and query lengths/order. This bounded example
demonstrates why relation equivalence does not imply reusable Groth16 query
points; it is not an Output-size test or evidence about real Sapling
parameters.

The local parameter reader verifies a bounded Bellman-format stream, but no
authenticated Output parameter file was loaded or used here, no trusted
query-value export for the pinned Output fixture exists, and no real Output
proof/public-input fixture was independently verified. Therefore real
proving-key compatibility, verification-key compatibility, and production
Output proof generation remain **Unverified**. No production circuit,
allocation order, query implementation, or parameter material was changed.

### Phase 9.21.06 verification

- The controlled synthetic row-order/factor-swap/scaling QAP test passed,
  including exact per-variable QAP evaluations, quotient coefficients,
  query-vector lengths and order, own-key proof verification, and cross-key
  rejection.
- The QAP/query/proof/verification suite passed (**88 tests**); the updated
  focused synthetic QAP transformation test passed again, and the final
  compatibility-manifest suite passed (**14 tests**).
- Output and Spend regression suites passed (**87 tests**), preserving the
  production Output dimensions and fingerprint.
- The additional standalone Bellman synthesis suite reported two failures in
  untouched scalar-bit ownership/type-boundary assertions; this task did not
  modify those source paths.
- The test uses deliberately disclosed synthetic toxic-waste values and does
  not use or authenticate Sapling parameters.
- Output remains 7,827 rows × 7,827 columns with the unchanged production
  fingerprint `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.

## Phase 9.21.07 — Exact Output synthesis alignment audit

The pinned Bellman export and the complete semantic relation comparison
confirm that the existing Output relation matches, but do not yet justify a
production rewrite that reproduces Bellman's ordered R1CS. This phase records
the precise known ordering and equation-form differences and leaves the
production circuit unchanged.

The verified allocation-order differences are:

| Region | Pinned Bellman | ZyCoin | Consequence |
|---|---|---|---|
| Value and `rcv` | Value bits, then value-multiplication auxiliaries; `rcv` starts at Aux(255). | Value bits are immediately followed by `rcv`, starting at Aux(64). | Auxiliary and dependent row positions differ. |
| `g_d` representation and `esk` | `g_d` checks and strict representation precede `esk` bits. | `esk` bits precede strict `g_d` representation. | Auxiliary and row positions differ. |
| `rcm` and Pedersen | Pedersen rows precede `rcm`; `rcm` starts at Aux(6813). | `rcm` is allocated before Pedersen; it starts at Aux(5057). | Auxiliary positions and Boolean/Pedersen row order differ. |

The first Boolean row also has different native factorization:
ZyCoin uses `bit * (bit - ONE) = 0`, while Bellman uses
`(ONE - bit) * bit = 0`. The complete relation comparison reports 7,567
rows matched through factor swap/nonzero scaling and another 260 only after
expanding `A * B - C` as a polynomial. Those 260 comprise 2 value-commitment
public equalities, 252 `epk` selection-v factorization rows, 1 `g_d` curve
check, 2 `g_d` representation reconstruction rows, 2 `epk` public
equalities, and 1 note-commitment public equality.

The durable comparison evidence contains complete aggregate variable/row
accounting and per-region fingerprints, but no reproducible per-index
correspondence assigning every local auxiliary and each local constraint row
to one exact upstream identity. Therefore it is not sufficient to specify and
verify all allocation moves, row ordering, and factorization changes needed
for an exact Bellman matrix. No production circuit equations, allocation
order, public interfaces, or QAP code were changed. The minimal next step is
to emit the deterministic 7,821-variable and 7,827-row correspondence from
the pinned export and a fresh local synthesis, including exact mapped A/B/C
terms and transformation classes, before implementing an alignment.

Output/Bellman exact ordered-matrix equivalence and exact query mapping remain
**Unverified**. The production Output remains **7,827 rows × 7,827 columns**
with unchanged fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
Real proving-key compatibility, verification-key compatibility, and
production Output proof generation also remain **Unverified**.

### Phase 9.21.07 verification

- Corrected two stale Bellman-synthesis test expectations without weakening
  their ownership/type-boundary or pre-mutation checks; both focused tests
  pass. The complete Bellman synthesis suite passed (**39 tests**).
- Sapling gadget/Output and Spend regression modules passed (**73 tests**).
  QAP, Groth16, and compatibility-manifest suites passed (**102 tests**).
- No production synthesis code changed in this audit. The complete Output
  recorder behavior established in prior phases remains unchanged; upstream
  exact ordered-matrix equivalence is still **Unverified**.
- A repository-wide `git diff --check` reports trailing whitespace in
  pre-existing, unrelated `src/manager.py` edits. No such file was changed
  for this phase.

## Phase 9.21.08 — Materialized Output variable correspondence

The previously reported semantic variable correspondence is now persisted as
a machine-readable test fixture at
[`tests/fixtures/sapling_output_variable_correspondence.json`](../tests/fixtures/sapling_output_variable_correspondence.json).
It pairs all six upstream inputs (including ONE) and all 7,821 auxiliaries
with local Output columns, preserving each side's identity, source
annotation/name, and 32-byte little-endian witness assignment.

The generator is
[`tests/sapling_output_correspondence.py`](../tests/sapling_output_correspondence.py).
It verifies the pinned export SHA-256, independently translates each upstream
annotation and local variable name into a unique semantic role key, and
rejects duplicate or unmatched keys before checking assignments. Witness
values do not select pairings. A second generation from the same pinned
export produced byte-identical canonical content.

| Validation | Result |
|---|---:|
| Input pairs, including ONE | 6 |
| Auxiliary pairs | 7,821 |
| One-to-one total pairs | 7,827 |
| Unmatched upstream / local | 0 / 0 |
| Ambiguous upstream / local semantic keys | 0 / 0 |
| Assignment mismatches | 0 |
| Mapping fingerprint | `9df59fefa7c21df06f07049b97776b17251a4f01566d0da0c3ca9756b5351812` |
| Assignment-pairs fingerprint | `57e33a5911cba3b585b550fa24f4dcbecb099da11bcf86bc0b4053709003cbc1` |
| Artifact SHA-256 | `98d8161f6934d8730b908874a348cdf676816cee71edec583cf031f2e18ef76a` |

Fresh local Output synthesis satisfied at **7,827 rows × 7,827 columns** and
retained the production matrix fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No production circuit code changed. This artifact establishes variable
identity and assignment correspondence only; it does not contain a complete
row correspondence and does not establish exact ordered-matrix alignment,
Groth16 query compatibility, real proving-key compatibility, or production
proof generation. Those claims remain **Unverified**.

### Phase 9.21.08 verification

- Correspondence, QAP/Groth16, and compatibility tests: **105 passed**.
- Bellman synthesis tests: **39 passed**.
- Output and Spend tests: **73 passed**.
- Targeted Ruff checks and changed-file `git diff --check` passed.
- Regenerating the correspondence twice from the pinned export produced
  identical canonical content.
- Exact real Bellman query translation and all real parameter/proof
  compatibility claims remain **Unverified**.

## Phase 9.21.09 — Exact Output row correspondence

The Python-only generator
[`tests/sapling_output_row_correspondence.py`](../tests/sapling_output_row_correspondence.py)
now pairs every row from the pinned Bellman export with fresh local Output
synthesis using the verified 7,827-entry variable correspondence. The
machine-readable artifact is
[`tests/fixtures/sapling_output_row_correspondence.json`](../tests/fixtures/sapling_output_row_correspondence.json).
It records upstream and local row indices and labels, all upstream/local
A/B/C linear-combination terms and exact 32-byte coefficients, mapped
variable identities, factor orientation/scales, and the complete expanded
polynomial for each expanded-only row.

| Result | Verified value |
|---|---:|
| Upstream / local rows | 7,827 / 7,827 |
| One-to-one row pairs | 7,827 |
| Native A/B/C matches | 5,973 |
| A/B factor swaps | 252 |
| Valid nonzero factor normalizations | 1,342 |
| Expanded `A*B-C`-only matches | 260 |
| Unmatched / ambiguous upstream rows | 0 / 0 |
| Unmatched / ambiguous local rows | 0 / 0 |
| Same-index / moved row pairs | 2,298 / 5,529 |
| Row-map fingerprint | `c87e79dd0c55c61c46e5ff8cea9fbec1c84801db7298a5eb73aece26b0f070a9` |
| Mapped-coefficient fingerprint | `c42f36a3b4197daf9bf10340ffb9081066431baede06d75a0f0fe04c42cdd215` |
| Canonical artifact-content fingerprint | `a71db480bca3081f76c3c688c8db141f94ab61b4b3fdcad8ce58372fb88fe9f5` |
| Artifact SHA-256 | `893441e69dae735dffb4e0a4b22c0a88bae8bf44857327d09668a424b2b9d971` |

The 260 expanded-only rows are individually resolved in the artifact:
252 epk-selection rows, two value-commitment public equalities, two g_d
representation-reconstruction rows, two epk public equalities, one g_d
curve-check row, and one note-commitment public equality. They are not
represented as native factorization matches. The 1,594 factor-swapped or
normalized rows are likewise classified separately from the 5,973 native
A/B/C matches.

The row-index map confirms 5,529 rows move relative to their upstream row
indices. All 64 value-bit rows and 252 rcv-bit rows retain their indices;
variable allocation differs, but those Boolean row positions do not. All
776 g_d representation rows, 252 esk-bit rows, 3,265 epk-computation rows,
252 rcm-bit rows, 982 note-content-hash rows, and two epk rows move. These
observed row pairs are recorded exactly. The source-traced g_d/esk and
rcm/Pedersen stage differences are consistent with their changed regions,
but row-index counts alone do not prove that those differences caused every
movement. They do not explain the factorization differences. Exact ordered
Bellman A/B/C matrix alignment is therefore **not established**; row
correspondence and relation-aware equivalence are not byte-identical
synthesis. The production Output circuit was not changed and remains
7,827 × 7,827 with fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
Fresh production synthesis is satisfied; its ordered matrix serialization
matches the fresh recorder serialization. The recorder's separate matrix
fingerprint uses a distinct serialization and is recorded as such in the
artifact.

The pinned export SHA-256 is
`ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe`; the
input variable-map fingerprint is
`9df59fefa7c21df06f07049b97776b17251a4f01566d0da0c3ca9756b5351812`.
The generator verifies both before matching, rejects duplicate/ambiguous
signatures, and checks complete one-to-one coverage. Exact ordered matrix
alignment, Groth16 query compatibility, real proving-key or verification-key
compatibility, and production proof generation remain **Unverified**.

### Phase 9.21.09 validation

- Focused row-correspondence tests: **9 passed**.
- Combined Bellman synthesis, Sapling Output/Spend, QAP, Groth16, and
  compatibility regressions: **226 passed**.
- Two complete regenerations from the pinned export produced the same
  artifact SHA-256:
  `893441e69dae735dffb4e0a4b22c0a88bae8bf44857327d09668a424b2b9d971`.
- Targeted Ruff and changed-report whitespace checks passed.
- No production circuit code changed; exact ordered Bellman matrix alignment
  and real Groth16 parameter compatibility remain **Unverified**.

## Phase 9.20.84 — Backend-neutral unchecked Jubjub representation allocation

`allocate_unchecked_jubjub_repr` now uses `SynthesisBackend.alloc_private`
for the same 256 representation bits. Its R1CS overload still returns the
production `Variable` tuple; a backend overload returns `VariableLike`
values. Allocation order and labels remain `point.v` bits `[0..254]`
little-endian followed by the parity bit of `point.u`, named
`{name}.v bit[index]`. It emits no constraints and retains its prior
unchecked behavior—no bit Boolean constraints, curve check, canonicality
check, or range enforcement.

Production/recorder tests match all 256 mapped identities, names, and
assignments for identity, the spending-key generator, its negative, an
off-curve zero-coordinate point, and a field-boundary off-curve point.
Invalid `None`, arbitrary objects, and foreign-backend variable objects are
rejected before either target backend changes. The API accepts only concrete
`Point` witnesses, so it cannot produce an unassigned representation; the
`None` case verifies rejection without mutation. Off-curve fixtures confirm
that allocation remains deliberately unchecked.

The Output entrypoint's concrete R1CS/freshness guard is unchanged. This
helper is now backend-neutral, but note commitment and full Output synthesis
remain blocked by the remaining concrete dependencies mapped in Phase
9.20.83. This local allocation parity is not upstream Bellman equivalence.

### Phase 9.20.84 verification

- CPython 3.10.11 full suite: **275 passed**; focused allocator, namespace,
  invalid-input, note-commitment, and manifest suite: **15 passed**.
- Ruff, compileall, Pylance diagnostics (no diagnostics in changed Python
  files), all eight signature call sites, and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install imported
  `zycoin.sapling_gadgets` and read all eight packaged coin JSON resources.

## Phase 9.20.83 — Output synthesis dependency audit

This phase is audit-only. It changes no circuit equations, allocation behavior,
public API, or Output entrypoint guard. The complete production call graph is
captured in `circuits.sapling-output.recorder_reconstruction
.output_synthesis_dependency_audit` in the compatibility manifest.

The entrypoint first enforces its concrete `R1CS` type, witness type, label,
and freshness checks, then validates the complete witness before allocating
anything. It allocates public inputs in `cv.u`, `cv.v`, `epk.u`, `epk.v`,
`cmu.u` order. The private stages then execute in this exact order:

1. 64 little-endian value bits, 252 `rcv` bits, value fixed-base
   multiplication, `rcv` fixed-base multiplication, their affine addition,
   and `cv.u` then `cv.v` equality rows.
2. The value linear combination; private `g_d.u/v`; 252 `esk` bits; then
   `g_d` on-curve, its three-doubling non-small-order relation and inverse
   row, 252-bit scalar multiplication, and `epk.u/v` equalities.
3. 256 unchecked `pk_d` representation bits (`v[0..254]`, then `u` parity),
   followed by 252 `rcm` bits.
4. Note-commitment synthesis: strict `g_d` representation; Boolean rows for
   `pk_d` and `rcm`; Montgomery Pedersen lookup/addition/segment conversion
   in segment and window order; fixed-base `rcm` multiplication; randomized
   commitment allocation and affine addition; and `cmu.u` equality.

The Output note-hash input is six personalization bits plus 576 message
bits: 64 value bits, 256 `g_d` representation bits, and 256 `pk_d`
representation bits. Montgomery Pedersen consumes 194 three-bit chunks in
four segments of 63, 63, 63, and 5 chunks. In this Output path, fixed-base
scalar-range enforcement is disabled for value, `rcv`, and `rcm`; the
optional `pack_bits`/`range_check` branch is therefore not executed. The note
function also receives the already-constrained value bits, so its optional
value `range_check` branch is not executed. Boolean enforcement, ownership,
assignment reads, point lookups, and allocations remain concrete.

The production allocation manifest records public identities and contiguous
auxiliary ranges: value `[6,69]`, `rcv` `[70,321]`, value commitment
`[322,1268]`, `g_d` `[1269,1270]`, `esk` `[1271,1522]`, `g_d` checks and
ephemeral multiplication `[1523,4806]`, `pk_d` `[4807,5062]`, `rcm`
`[5063,5314]`, and note commitment `[5315,7826]`. These are production
identities only; they do not imply recorder allocation equivalence. The
Output composition uses prefixed labels rather than an enclosing backend
namespace. The shared on-curve and strict-representation helpers open their
existing label namespaces; nested equations append in call/loop order.

Already backend-neutral operations include point allocation/on-curve
validation/strict representation, scalar-bit allocation, point selection,
affine doubling/addition, and complete variable-base scalar multiplication.
Remaining concrete dependencies are the Output guard/freshness properties;
value commitment and fixed-base multiplication (including lookup, range,
packing, Boolean, and assignment APIs; in this Output path the optional range
and packing branches are not selected; ephemeral-key composition and
non-small-order witness extraction; note-commitment value/LC ownership and
evaluation; and Montgomery Pedersen's concrete `_PedersenNum`,
`Variable`/`LinearCombination`, direct witness reads, allocations, and
enforcement. Their detailed paths and shared dependency groups are in the
manifest. Value/fixed-base, note/Pedersen, and ephemeral/non-small-order
layers must migrate with their listed nested helpers rather than replacing
or bypassing the entrypoint guard.

Recommended next isolated migration: `allocate_unchecked_jubjub_repr`.
It is the Output `pk_d` allocator and only maps its point witness to 255
little-endian `v` bits followed by the `u` parity bit, allocating each via
the already shared private-allocation operation. It can be independently
tested for allocation order, values, names/identities, and zero emitted rows
on both backends. It intentionally performs no curve validation; this small
slice does not by itself enable note commitment or Output recorder synthesis.

**Status:** full Output recorder synthesis remains **Blocked** at the
unchanged concrete entrypoint guard. Upstream Bellman matrix equivalence
remains **Unverified**; existing local cross-backend parity is not upstream
evidence.

### Phase 9.20.83 verification

- The compatibility manifest dependency-audit assertions and focused
  synthesis/compatibility tests passed on CPython 3.10.11.
- Full suite: **272 passed**. Ruff, compileall, Pylance diagnostics and
  signature checks, `git diff --check`, wheel/sdist builds, and clean-target
  wheel import/resource checks passed.
- No production synthesis code was modified.

## Phase 9.20.82 — Backend-neutral scalar multiplication orchestration

`constrain_jubjub_scalar_mul` now accepts the shared `SynthesisBackend`.
Production R1CS callers retain their overload and behavior; recorder-backed
callers execute the same complete orchestration rather than a parallel
recorder transcription. It validates the supplied witness type, bit length,
`bits_preconstrained` flag, backend-specific bit ownership/assignment,
matching `witness.bit_values`, and trace lengths before adding rows.

The existing 252-bit little-endian order is unchanged. For each bit, the
routine Boolean-constrains it unless preconstrained, doubles the current base
for indices greater than zero, allocates the selected point, applies the
existing selector, then initializes the accumulator from selected point zero
or adds later selected points through the existing accumulation helper.
Allocated `base[i]`, `selected[i]`, and `accumulator[i]` points, annotations,
equations, and row order remain in the same positions. No scalar
reconstruction or modulus comparator was added. The Output entrypoint's
concrete R1CS guard is unchanged.

End-to-end production-versus-recorder tests cover zero, one, `0x1234`, and
`SCALAR_MODULUS - 1` for the spending-key base, plus zero and one for the
identity base. All 252 bit indices and the LSB-first witness trace are
checked; independent host multiplication matches the final coordinates.
All rows and mapped witnesses agree for a 3,521-row, 3,523-column matrix
including ONE, with fingerprint
`1e53bdeacde8d6565d678691dc5a47723f9bcdf781aced9a50cf8dee94c8216f`.
Scalar-bit, accumulator, and final-coordinate tampering is rejected for
nonidentity bases. Unassigned bits and foreign variables/linear combinations
are rejected before synthesis mutation.

The remaining concrete surfaces are `constrain_sapling_ephemeral_key` and
the Output entrypoint/witness assembly; value commitment and fixed-base
multiplication; non-small-order composition; note commitment; and Pedersen
synthesis. Consequently, this does not establish full Output recorder
synthesis or upstream Bellman matrix equivalence. Spend synthesis, proving
behavior, parameter trust, and Sapling spending gates are unchanged.

### Phase 9.20.82 verification

- CPython 3.10.11 full suite: 272 passed; focused scalar, recorder, Sapling
  gadget, and manifest suite: 76 passed.
- Ruff, compileall, Pylance diagnostics (no diagnostics in changed Python
  files), all 11 signature call sites, and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install imported
  `zycoin.sapling_gadgets` and read all eight packaged coin JSON resources.

## Phase 9.20.81 — Backend-neutral scalar multiplication accumulation

The scalar multiplication loop visits witness bits least-significant first.
For each bit it retains the existing order: Boolean constraint when needed,
base doubling at indices greater than zero, selected-point allocation and
selection, then accumulation. The host witness starts with the identity and
adds each selected point. Circuit synthesis does not allocate that initial
identity: the first selected point itself becomes the accumulator. For each
later bit, synthesis allocates `accumulator[index]` immediately after the
selected point and invokes the existing affine addition relation; its four
products and two coordinate rows remain ordered as before. Zero bits select
the identity but still pass through addition at later indices.

The new `_constrain_jubjub_scalar_mul_accumulation` helper contains exactly
this first-selected-then-add behavior. The production loop calls it at its
original location, preserving interleaved allocations and constraint order.
The helper validates ownership of accumulator and selected coordinates
before allocation, allocates the next point from the existing witness, and
uses the shared affine-addition gadget. The complete loop's bit and base
handling and witness validation remain concrete-R1CS coupled; no parallel
recorder-only implementation was added.

For four-bit decompositions of zero, one, and `0xB`, using both the
spending-key base and identity base, the accumulation-only fixtures agree
across production R1CS and recorder. The independently summed selected
points match `base.multiply(scalar)`. Each fixture has 18 rows, 27 columns
including ONE, and fingerprint
`2a095999443d2a45416b2e06c6003fcb83f736d1401f38e3dd1334867cda33a0`.
Witness-to-column mappings and all assigned values match. Tampering with any
addition intermediate or accumulator coordinate fails; unassigned witnesses
remain unassigned, and malformed or foreign inputs fail before mutation.

This is local cross-backend agreement, not authoritative Bellman matrix
evidence or complete Output equivalence. No strict point-representation
constraint was added; the existing selection, doubling, addition, and
scalar-bit helpers remain unchanged. Proving behavior, parameter trust, and
Sapling spending gates are unchanged.

### Phase 9.20.81 verification

- Focused recorder, scalar multiplication, Sapling gadget, and manifest
  suites: **73 passed** on CPython 3.10.11.
- Targeted Ruff, compileall, manifest JSON validation, Pylance diagnostics,
  signature compatibility for all 13 scalar-multiplication call sites, and
  `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install exercised the
  recorder accumulation and loaded all 8 packaged coin configurations.
- Full CPython 3.10.11 suite: **269 passed**.

## Phase 9.20.80 — Backend-neutral scalar bit decomposition

The Output ephemeral-key witness stores `esk` as an integer in
`[0, Jubjub SCALAR_MODULUS)`. Its host bit sequence is generated as 252
little-endian bits, with bit `i` equal to `(esk >> i) & 1`. Output allocates
those bits as private variables in ascending index order, then scalar
multiplication Boolean-constrains each bit at its existing per-bit position.
The R1CS relation for each bit is `b * (b - 1) = 0`.

The shared helpers `_allocate_jubjub_scalar_bits` and
`_constrain_jubjub_scalar_bit` now perform those same allocation and Boolean
operations for production R1CS and the recorder. Output uses the allocation
helper while keeping all 252 allocations before multiplication. The Boolean
helper is called from the existing scalar multiplication loop, preserving
row interleaving with its selection/doubling/addition relations.

There is **no reconstruction equation in this R1CS path**: no scalar
variable is allocated, and the sum of weighted bits is checked only by host
witness validation (`esk == sum(bit << index)`). There is also no circuit
less-than-`Jubjub SCALAR_MODULUS` comparator. Host witness construction
accepts only canonical scalar values, but the isolated 252 Boolean relations
alone admit any 252-bit assignment. No stronger constraint was added.

For zero, one, an intermediate value, and `SCALAR_MODULUS - 1`, production
and recorder allocate the same 252 bit identities/values and emit 252
identical ordered Boolean rows. The local matrix fingerprint is
`2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467`
(253 columns including ONE). Every non-Boolean bit tamper fails; a valid
Boolean bit flip remains accepted by this isolated slice, as expected without
a reconstruction row. Unassigned bit values remain unassigned, and foreign
variables or linear combinations are rejected before mutation.

Scalar multiplication, its witness trace, and the Output entrypoint remain
concrete-R1CS coupled. This local recorder agreement is not upstream Bellman
matrix evidence. Proving behavior, parameter trust, and Sapling spending
gates are unchanged.

### Phase 9.20.80 verification

- Focused recorder, Sapling gadget, and compatibility-manifest suites:
  **70 passed** on CPython 3.10.11, including scalar boundary, tampering,
  ownership, unassigned-witness, and existing Output regressions.
- Targeted Ruff, compileall, manifest JSON validation, Pylance diagnostics,
  signature compatibility for scalar multiplication callers, and
  `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install exercised the
  252-bit recorder synthesis and loaded all 8 packaged coin configurations.
- Full CPython 3.10.11 suite: **266 passed**.

## Phase 9.20.79 — Backend-neutral affine Jubjub addition

`constrain_jubjub_add` now accepts the shared `SynthesisBackend` contract
while retaining its production R1CS call signature and the existing formula.
It allocates no points itself: its caller-owned point coordinates are checked
for backend ownership before synthesis. The operation retains the four
products (`U`, `A`, `B`, and `C`) followed by the `u` and `v` division
relations, in that exact order. Input curve-membership constraints remain
the caller's responsibility, as before. This is the existing incomplete
affine formula: it is intended for subgroup points and does not handle
denominator poles for arbitrary curve points. The helper does not establish
subgroup membership.

The production R1CS and recorder run this same helper for a representative
point pair, identity on either side, equal points, and inverse points. Each
fixture emits six ordered rows; the representative fixture has eleven local
columns including ONE and fingerprint
`b9c3cfc17d0b5201e6f4c69a10138911190b747f9c09ffcc6ee56a0fbadce39c`.
Mapped matrix serialization and witness values match. The expected result
was independently computed with host Jubjub addition. Tampering with any
addition intermediate or result coordinate violates production constraints.
Unassigned witnesses remain unassigned, and foreign variables or linear
combinations are rejected before either backend mutates.

The identity, equal-point, and inverse-point fixtures in the intended
subgroup domain exercise the existing affine formula without replacing it.
They do not establish completeness for arbitrary curve points. This is local
cross-backend agreement, not authoritative Bellman matrix evidence. Scalar
bit allocation, selection composition, accumulation, and complete scalar
multiplication remain concrete-R1CS coupled; the Output entrypoint guard and
all proving/spending gates remain unchanged.

### Phase 9.20.79 verification

- Focused recorder, Sapling gadget, and compatibility-manifest suites:
  **65 passed** on CPython 3.10.11. The focused affine-addition and manifest
  evidence checks also pass after the allocation-mapping assertion was added.
- Full CPython 3.10.11 suite: **261 passed**.
- Targeted Ruff, compileall, manifest JSON validation, and `git diff --check`
  passed. Pylance diagnostics are empty for changed Python files; signature
  compatibility passes for all 19 `constrain_jubjub_add` call sites.
- Wheel and sdist builds passed. A clean-target wheel install imported the
  changed gadget, synthesis interface, and recorder and read all 8 packaged
  coin configurations.
- The 45 existing Ruff findings in unchanged `src/r1cs.py` remain separate:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.75 — Backend-neutral point allocation

The Output graph's `allocate_jubjub_point` helper was migrated from a
concrete `R1CS` parameter to the existing `SynthesisBackend` contract. It
still validates `Point | None` before allocating and then allocates the
coordinates in the same `u`, `v` order using `alloc_private`. No constraint
rows are added by this helper.

Tests execute that same helper against production R1CS and recorder
backends. For a namespaced fixture, production assigns private columns 1 and
2, while the recorder assigns `Aux(0)` and `Aux(1)`; after mapping through
implicit ONE, the identities and order match. Both have three total local
columns, zero rows, identical canonical local-column matrix serialization,
and fingerprint
`880efe8a2dffdedc69b198304e12aa7b2519c661cd0d6541be92ce50cee4d124`.
The pinned Jubjub point witness coordinates match, `None` stays unassigned
on both backends, and invalid host point input is rejected without changing
allocation state. This is local cross-backend agreement, not an upstream
matrix export.

`constrain_sapling_output` still retains its concrete R1CS/freshness checks.
The host witness validator, value-commitment and fixed-base paths, ephemeral
scalar multiplication, point representations, note commitment, and Pedersen
still depend on concrete R1CS variable/LC APIs. No full Output recorder
synthesis was attempted; Spend, parameter trust, proof generation, and
spending gates are unchanged.

### Phase 9.20.75 verification

- CPython 3.10.11 full test suite: **250 passed**.
- Focused recorder/gadget/manifest tests: **54 passed**.
- Targeted Ruff and compileall passed. Pylance diagnostics were empty for
  changed Python modules and tests; all 49 call sites of
  `allocate_jubjub_point` passed signature-compatibility checking.
- `git diff --check` and manifest JSON parsing passed. The existing
  45-finding Ruff baseline in `src/r1cs.py` is unchanged:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.
- Wheel and sdist builds passed. The sdist includes the new synthesis
  interface and Phase 9.20.75 reports. Clean-target wheel imports exercised
  the recorder-backed allocator and gadget and read the packaged BitcoinZ
  coin configuration.

## Phase 9.20.72 — Bellman recorder semantic conformance

The recorder was checked against Bellman 0.15.0's pinned `ConstraintSystem`,
`LinearCombination`, `TestConstraintSystem`, and Groth16 setup paths. A
concrete discrepancy was fixed: namespace scope creation extends the path but
does not itself register a named object; only variable allocations and
constraints occupy unique complete annotation paths. Repeated scope objects
with distinct children are therefore accepted, matching the test-system
behavior.

Recorder tests now cover interleaved Input/Aux allocation, stable implicit
ONE/input indices, nested and repeated namespaces, duplicate/zero/reordered
LC terms, malformed and foreign references, canonical equivalence, and exact
post-synthesis setup dummy rows and query indexing. A two-row hand-calculated
fixture exercises top-level and namespaced allocation/enforce APIs, three
input dummy rows, IC/L query partitioning, domain padding, and a pinned
canonical matrix fingerprint. Raw operation order and annotations remain in
`serialize()`; matrix serialization combines duplicate terms modulo the
scalar field, removes zero terms, and sorts by typed variable index so
equivalent LCs have stable matrix hashes.

The existing test-only BLAKE2s source transcription was run against both local
R1CS and the recorder for a one-byte Sapling nullifier-hash input. The mapped
matrices match (20,094 rows and 20,051 total columns), and the digest matches
Python `hashlib`. This is a second isolated cross-implementation check, not
Bellman execution or an authoritative matrix export. The adapter
deterministically suffixes repeated flattened reference labels; this affects
only labels, not allocation indices or matrix rows. Complete Spend/Output
synthesis was not integrated.

**Status:** tested recorder subset **Partially Verified** against source and
hand fixtures; Pedersen and BLAKE2s comparisons are **Partially Verified**
cross-implementation agreements. Rust closure/error semantics, Rust
namespace push/pop lifetime behavior, alternate ConstraintSystem backends,
the exact TestConstraintSystem hash implementation, and full circuit
synthesis remain outside the modeled subset. Whole-circuit equivalence and
parameter compatibility remain **Unverified / Blocked**; Sapling spending
remains gated. See the [compatibility manifest](sapling-circuit-compatibility-manifest.json)
for exact semantics and fingerprints.

### Phase 9.20.72 verification

- CPython 3.10.11 full suite: **245 passed**; focused recorder and
  compatibility-manifest tests: **17 passed**.
- `compileall`, targeted Ruff, and `git diff --check` passed. Pylance
  diagnostics were empty for the changed Python files; all 7
  `constrain_bellman_blake2s_reference` call sites passed signature checks.
- Wheel and sdist builds passed. A clean-target wheel install imported the
  recorder and read all 8 packaged coin configurations; the sdist contains
  the recorder/fixture tests and updated reports.
- The unchanged `src/r1cs.py` Ruff baseline remains **45 findings**:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.71 — Pure-Python Bellman synthesis recorder

Added `src/bellman_synthesis.py`, a bounded recorder for the pinned Bellman
0.15.0 synthesis operations reviewed in this phase: separately indexed
`Input`/`Aux` allocations, implicit `Input(0)=ONE`, nested namespace names,
ordered linear-combination terms, ordered A/B/C constraint insertion,
post-synthesis setup dummy-input rows, and input-then-aux query indexing.
The recorder also reports the derived domain size and H-query length. It
retains Bellman's append-order LC semantics; the separate local-R1CS mapping
combines duplicate terms and maps typed Bellman indices explicitly to local
columns.

Small tests pin the typed variables, A/B/C row, dummy-row placement, query
layout, and deterministic serialization. A corrected recorder matrix
fingerprint covers dimensions and ordered terms, not annotation names; its
format and domain separator are ZyCoin-specific and cannot be interpreted as
a Bellman `TestConstraintSystem::hash` or an upstream matrix hash.

The test-only Pedersen transcription runs against both the existing local
R1CS and recorder through a narrow adapter. Their local-matrix serializations
and output witnesses agree for the bounded fixture (9 input-boolean rows,
22 Pedersen rows, 31 total rows, 32 columns including ONE). This is
cross-implementation agreement with a Python transcription, not execution of
Bellman and not an upstream matrix export. Spend/Output circuits were not
migrated to the recorder.

**Status:** recorder semantics and hand fixtures are **Verified** within the
modeled subset; the Pedersen comparison is **Partially Verified**; complete
Spend/Output compatibility and parameter mapping remain **Unverified /
Blocked**. Unsupported APIs and the exact boundary are listed in the
`synthesis_recorder` section of the [compatibility manifest](sapling-circuit-compatibility-manifest.json).

### Phase 9.20.71 verification

- CPython 3.10.11 full test suite: **239 passed**; final focused recorder and
  compatibility-manifest tests passed (**11 passed**).
- `compileall`, targeted Ruff, and `git diff --check` passed. Pylance
  diagnostics were empty for the changed Python files; all 9
  `synthesize_pedersen_hash` call sites passed signature-compatibility checks.
- Wheel and sdist builds passed. A clean-target wheel install imported the
  recorder and read all 8 packaged coin configurations. The sdist contains
  the recorder tests and updated reports.
- The unchanged `src/r1cs.py` Ruff baseline remains **45 findings**:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

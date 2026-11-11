# Sapling Groth16 proof-generation readiness

## Purpose and scope

This report records the Phase 9.18 readiness audit for protocol-compatible
Sapling spend and output Groth16 proofs in pure Python. Phase 9.21.37 adds
full-size test-only synthetic Spend setup and proof-pipeline evidence, and
Phase 9.21.38 records complete official Spend query accumulations; neither
adds secure parameters or enables Spend proving. A subsequent phase
implemented and independently vector-checked BLS12-381 field, curve, encoding,
and pairing primitives. Phase 9.21.29 records the test-only deterministic
interoperability run; Phase 9.21.30 adds the restricted production-facing API
and OS-backed randomness; Phase 9.21.31 audits API misuse and fixes parameter
object reconfiguration; Phase 9.21.32 distinguishes file integrity, parser
compatibility, circuit binding, and ceremony validity. The latter two remain
unverified.

## Findings

Sapling proofs use Groth16 over BLS12-381. The circuit constraint field is
the BLS12-381 scalar field; Sapling's Jubjub operations are defined over that
field, while Groth16 proof elements use the BLS12-381 G1 and G2 groups and
verification uses their pairing. Upstream serializes a proof as G1/G2/G1
elements (48 + 96 + 48 bytes). Phase 9.21.30 adds a restricted
production-facing pure-Python Output API; it does not close the ceremony,
circuit-binding, or full production-readiness gaps.

**Current Output proof status (Phase 9.21.32):** the production API loaded
only the hash-pinned official Output parameters and generated two distinct
proofs for the pinned witness using Python's OS-backed `secrets` source.
ZyCoin and independent Bellman 0.15 verification accepted both proofs.
The security audit also fixed parameter-object reconfiguration through
`dataclasses.replace`. This verifies the API behavior for that test witness
and tested misuse cases only, not ceremony validity, general
parameter-to-circuit binding, Spend circuit/key compatibility, or full production
readiness.

**Spend parameter and QAP status (Phases 9.21.33–35, 38):** Bellman 0.15 and
ZyCoin's Python parser match all 437,707 canonical IC/query point encodings
from the pinned official Spend file in exact section order. A deterministic
satisfying assignment was then independently synthesized by pinned Bellman
0.15 and evaluated through complete Bellman and local QAPs. Both matrices
were satisfied; 8 public/ONE assignments and 98,637 mapped auxiliaries
matched, with `Aux(76805)` and local packed position helper handled
explicitly. All eight complete canonical QAP vector fingerprints differ:
A/B/C evaluations, A/B/C coefficients, quotient coefficients, and H
evaluations. Independent quotient divisibility checks passed on both sides.
Thus exact canonical QAP equivalence is **Unverified**, not established by
the satisfying assignments or parameter serialization match. Phase 9.21.35
traces the differences to 48,546 moved rows, 251 A/B swaps, 28,351
nonuniform factor normalizations, 333 expanded-relation-only matches, and
the explicit helper projection. Semantic relation equivalence is
evidence-supported for the pinned exports under the accepted mapping and
projection, but is not a formal source-level proof. No transformation of
the complete variable-indexed QAP polynomials and the resulting A/B/IC/L
proving queries has been demonstrated. The observed differences alone do
not prove semantic incompatibility or rule out accidental equality at the
hidden setup point. Spend parameter-to-circuit binding and ceremony validity
remain **Unverified**; `phase1radix2m17` and the exact ceremony-era Spend
circuit/setup source are unavailable. No Spend proof was generated and Spend
proving remains gated.

The Phase 9.21.38 full-vector check independently accumulated every official
IC/H/L/A/B_G1/B_G2 section using ZyCoin's complete MSM and a separate Bellman
0.15 loader. IC, L, A, B_G1, and B_G2 matched; H differed for the deterministic
satisfying witness, consistent with the differing local and upstream quotient
coefficient fingerprints. The official key therefore does not establish
support for the local Spend QAP. No proof was generated; parameter-to-circuit
binding and ceremony validity remain **Unverified**.

The Bellman trace SHA-256 is
`a39e4d2d815dca24eead67996d94732dc9a12b13ac3f1c4881f5e5dadddf8feb`;
the Bellman and local assignment hashes are
`429887b2897ce1ee6f4bf9707c7e28158ce66dc9ba9789dff708ce02a0fc3e57` and
`4ca277581c10a4e20d576a787b771a9c36bbf9b0e26d3b920ef3ea66fd2b45a3`.
Both systems have 98,777 constraints; the Bellman QAP domain is 131,072.
The eight Bellman/local QAP vector hashes and detailed dimensions,
fingerprints, and validation are recorded in
[Phase 9.21.34](sapling-circuit-implementation.md#phase-92134--independent-sapling-spend-qap-compatibility).
The final complete Sapling test discovery run passed **201 tests** with
**1 skipped** in **1,314.384 seconds**, including the Spend/Output,
parameter-parser, and compatibility-manifest regressions.

## Phase 9.21.38 — Official Spend full-vector query accumulation

ZyCoin's streaming parameter parser validated every point in the official
47,958,396-byte Spend file, including canonical encodings, curve/subgroup
membership, section boundaries, and pinned SHA-256
`8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13`.
Pinned Bellman 0.15 independently loaded the same source and produced an
exact ordered-point-byte match across all 437,707 points: IC 8, H 131,071,
L 98,638, A 85,390, B_G1 61,300, and B_G2 61,300.

The pinned deterministic satisfying Spend witness and its Bellman QAP
quotient were used for the Bellman result. ZyCoin synthesized the same
semantic witness, confirmed the existing 98,637-auxiliary correspondence
(with upstream `Aux(76805)` explicitly projected to the anchor), and
accumulated every full official vector with its production G1/G2 MSM
primitive. A distinct Bellman 0.15 test runner independently loaded the
official parameters and accumulated every full vector. Exact accumulated
results match for IC, L, A, B_G1, and B_G2, but not H. The Bellman and local
uncompressed H result hashes are
`a95259f4792a7727f33efa3eb466b5a1481f06c494182ffd091e46ef39bfd7fe` and
`1336802122c751934174ee3689fc8b140240b85e1ab4142a019ed611461742c7`.
The H mismatch aligns with the independently reported difference in quotient
coefficient vectors. Other matching accumulations are only witness-specific
linear combinations and do not establish query-to-circuit compatibility.

The dedicated test passed in 1,152.794 seconds; Bellman's six full-vector
accumulations took 155.485 seconds. The result establishes parser/serialization
compatibility and a concrete H-accumulation mismatch under the direct local
mapping, not a proof or ceremony claim. The official parameters do not
establish support for ZyCoin's local Spend circuit; Spend proving stays
disabled and parameter-to-circuit binding and ceremony validity remain
**Unverified**. No Spend proof was generated.
The complete Sapling regression suite passed **206 tests** with **1
skipped** in **2,844.775 seconds**, including Output interoperability,
Spend, parser, and compatibility-manifest regressions.

## Phase 9.21.37 — Memory-bounded full-size synthetic Spend setup

Test-only setup tooling generated and reloaded a synthetic key for the exact
local Spend matrix: 98,777 rows, 98,646 columns, fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`,
domain size 131,072, and 131,071 H-query entries. It wrote the complete
IC/H/L/A/B_G1/B_G2 and verification-key sections in a private format that
the production Bellman parameter parser rejects. The QAP setup scalars were
checked against column-major accumulation and selected inverse-FFT
calculations; sampled fixed-base generated points matched the independent
production scalar-multiplication implementation.

All toxic-waste scalars `(3, 5, 7, 11, 2)` are public test values. The test
exercises the production proof assembler with full-size vectors and the
production verifier, but replaces full-vector group MSM with a test-only
scalar-exponent oracle. Production G1/G2 MSM was independently checked only
on 64-point A, B_G1, B_G2, L, and H subsets. It therefore demonstrates
full-size synthetic query construction and proof/verifier algebra, not
full-vector production MSM performance, secure setup, official parameter
compatibility, or ceremony validity.

The four dedicated tests passed in 431.399 seconds. Measured elapsed time was
428.363 seconds, peak working set 611,672,064 bytes, and fixture size
59,934,611 bytes with SHA-256
`579199bf8c8bf3c703dfca6160a967e619b250b907907af104e4f9050281aba0`.
Setup calculation/write/reload took 366.642 seconds; proof assembly,
independent reference checks, and verification took 15.868, 14.242, and
1.365 seconds respectively. Negative tests reject wrong circuit metadata,
malformed files, production-loader use, invalid witnesses, altered public
inputs, and corrupted proofs. The material is insecure because the setup
toxic waste is known. No Spend proof was generated with official parameters;
Spend proving remains gated and ceremony validity remains **Unverified**.

The full Sapling regression command
`python -m unittest discover -s tests -p 'test_sapling*.py'` passed **205
tests** with **1 skipped** in **1,776.259 seconds**, including official Spend
parameter compatibility, Output interoperability, and compatibility-manifest
regressions. The process-wide peak working set was **1,154,809,856 bytes**;
this is cumulative across the suite, not an isolated setup measurement.

## Phase 9.21.36 — Spend circuit-specific setup requirements

The local Spend matrix requires a new circuit-specific key: 8 IC entries,
98,646 dense A/B variable positions, 98,638 L auxiliaries, and 131,071 H
points for a 131,072-row QAP domain after setup dummy rows and padding.
The domain uses `omega = 7^((SCALAR_MODULUS-1)/131072)` and coset generator 7;
the ordered matrix and its canonical coefficients are part of the circuit
identity. Setup also requires fresh, ceremony-generated Groth16 toxic-waste
scalars (`alpha`, `beta`, `gamma`, `delta`, and `tau`), which must not be
retained.
Existing QAP, FFT, query/MSM, proof assembly, and verification code can be
reused once authentic queries for that exact matrix exist. The production
parameter parser is read-only and has no circuit identifier or sparse A/B
position metadata; no production setup generator or parameter writer exists.
Its Bellman 0.15 encoding uses uncompressed 96-byte G1 and 192-byte G2 points
and validates curve and subgroup membership.
The full-size test-only synthetic run is recorded in Phase 9.21.37; it does
not supply secure parameters. `phase2` 0.2.2 is the identified
transcript-format reference, but the required `phase1radix2m17` input and
exact ceremony-era upstream Spend setup source required to check its
existing transcript are missing. A new local-matrix ceremony would require a pinned compatible
implementation, a circuit-specific contribution chain with at least one
honest contributor, and independent verification of the full chain and final
key. Parameter-to-circuit binding, ceremony validity, and Spend proving
remain **Unverified**.

Validation for this audit: the full Sapling regression suite passed 201
tests with 1 skipped in 1,269.139 seconds; the focused Groth16 end-to-end and
parameter-parser suite passed 46 tests. Manifest JSON and setup dimensions
were checked successfully.

## Phase 9.21.35 — Spend QAP transformations and proving-query semantics

The test-only row audit confirms 69,840 identical factor rows, 251 A/B
swaps, 28,351 nonzero factor normalizations, 333 expanded-equation-only rows,
48,546 moved row pairs, and two unmatched rows on each side. The 333 expanded
matches consist of 251 `pk_d` selection rows, 64 Merkle left/right rows, and
18 other rows; their expanded `A*B-C` polynomials match with unit scale, but
the factor polynomials are not identical. Upstream `Aux(76805)` is the
conditional anchor bound by a separate public-anchor row; local column
32,621 is the packed Merkle position derived from direction bits. They are
not interchangeable query variables.

For the deterministic witness, the same-index A/B/C evaluation differences
are 45,434 / 47,272 / 29,010 entries, and all A/B/C interpolant coefficients
(131,072 each), quotient coefficients (131,071), and H evaluations (131,072)
differ. The independently reconstructed upstream hashes match Bellman's
Phase 9.21.34 reference. Both circuits remain satisfied and both quotient
divisibility checks pass.

Row permutations, A/B swaps, and nonzero row-wise factor scaling preserve
the relation under the stated mapping, but alter the Lagrange-basis factor
vectors. Expanded relation equality verifies the row zero set, not the
individual factor queries. Equal domain size provides the same generic H
query basis shape only; it does not establish circuit-specific A/B/IC/L
query compatibility. The precise blocker is the missing complete
variable-space and row-domain transformation that derives the local query
basis from the pinned setup. The serialized parameter points do not expose
the polynomials or secret evaluation point needed to infer such a transform.
Parameter-to-circuit binding and ceremony validity remain Unverified.

Test-only toy-domain regressions show row permutation, A/B swap, nonuniform
normalization, and expanded-relation rewrites can preserve row satisfaction
while changing QAP polynomials and H. Negative cases reject malformed row
maps and invalid coefficient scaling; the existing correspondence test
rejects mismatched variable assignments. No proof was generated.

**Prior synthetic proving-cost profile (Phase 9.21.28):** projective scalar
multiplication and windowed MSM reduced full-shape Output proof-element
assembly to 14.76 seconds on Python 3.12.10 / i5-9400F, with about 50.6 MiB
peak working set. That benchmark used synthetic query points and did not
generate an authentic proof. The old affine query path was estimated at
48.7 minutes from the real witness scalar lengths and measured operation
costs.

## Phase 9.21.32 — Output parameter-to-circuit trust audit

The loader accepts the exact compiled SHA-256 and BLAKE2b-512 pins, full
length, Bellman 0.15 serialization, section counts, and trailer length. This
is **file integrity relative to the pins**. The official download URL and
upstream parameter-source digest support the file's Output designation; the
hashes themselves do not establish its source or what circuit generated it.

The parameter format carries no circuit ID, circuit/setup hash, matrix
fingerprint, or variable labels for query entries. ZyCoin's parser and
Bellman 0.15 agree exactly on all decoded ordered points, which establishes
**parser compatibility**, not **circuit binding**. The local matrix
fingerprint is checked during synthesis, but this binds the witness/QAP path
to the local Output matrix; it does not prove that the loaded key/query
points were generated from that matrix. A proof interoperability result for
one witness is not a general key-to-circuit binding proof. Circuit binding
therefore remains **Unverified**.

The 52,836-byte transcript is included in the pinned whole-file hashes, and
its `phase2` 0.2.2 record envelope has been identified. It is not
cryptographically validated. Verification requires the missing
`phase1radix2m13` initial Powers-of-Tau artifact and the exact
ceremony-era Output circuit/setup implementation to reproduce the transcript
circuit hash. The pinned Phase-2 verifier must then validate the contribution
chain and final parameter scaling, and its resulting final parameters must
be compared point-by-point with the pinned file. Ceremony validity remains
**Unverified** until this evidence is available.

Negative coverage rejects a same-length modified copy of the official
parameter file, rejects an altered digest even when the expected format and
section counts are supplied, and rejects loader-issued object reconfiguration
or query/key substitution. No independent alternate-circuit ceremony fixture
was available; such a fixture cannot be replaced by synthetic matching
counts, because counts do not identify a circuit.

**Trust policy:** treat the compiled hashes as integrity pins for the
designated official Output artifact, and the Bellman comparison as
parser-compatibility evidence only. Do not treat either as circuit binding or
ceremony validation. Keep production proof use gated until the missing
ceremony-era inputs allow independent transcript verification and exact
final-parameter comparison to the pinned matrix. No circuit equations,
query mappings, fingerprints, or proof-generation behavior changed.

Validation: the focused Output API, compatibility-manifest, parser, and
authentic proof-interoperability suite passed **72 tests** with **1 skipped**
in 206.629 seconds. The API's Python-generated proof and independent Bellman
verification regression passed; altered same-length parameter bytes and a
wrong digest with matching layout metadata were rejected. The pinned matrix
fingerprint remains
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`, and
the query-map fingerprint remains
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.

## Phase 9.21.31 — Production Output API security audit

The focused audit found one API-misuse defect: `SaplingOutputParameters` was a
normal frozen dataclass whose issuance token was preserved by
`dataclasses.replace`. A caller could therefore replace the pinned digest,
proving queries, or verification key while retaining an apparently loader-
issued object. The class is now non-publicly-constructible, the loader binds
the exact query/key objects and pinned digest in an internal seal, and both
proving and verification validate that sealed state before proceeding.
Uninitialized instances are also rejected. Tests cover altered digest, query,
and verification-key replacements, plus uninitialized and wrong-type objects.

Other reviewed behavior remains as previously verified: parameter-file hashes
and section layout are checked before proving-query use; witness synthesis and
full constraint satisfaction precede random draws; the public API has no RNG
argument; verification enforces the five named canonical scalar inputs and
canonical group encodings; failures do not print secret values. The
`secrets.randbelow` source provides bounded OS-backed draws, and the proof
assembly validates field ranges. Python cannot provide constant-time
arithmetic or guaranteed zeroization.

Classification:

| Finding | Status | Evidence / limitation |
|---|---|---|
| Parameter object could be reconfigured with `dataclasses.replace` | **Fixed** | Loader-issued object now binds exact query/key object identity and pinned digest; altered and uninitialized objects are rejected. |
| Ceremony transcript validity and general setup-to-circuit binding | **Accepted limitation** | Hash pins authenticate exact file bytes only; transcript verification and general circuit binding remain **Unverified**. |
| Constant-time execution and reliable secret-memory zeroization | **Accepted limitation** | Pure-Python big integers and immutable objects provide no such guarantees. |
| Other exploitable finding in the reviewed API scope | **None found** | Focused negative tests and independent Bellman regression passed. |

Validation after the fix: the focused API, BLS12-381, parameter-parser,
Groth16, Output query/QAP, and compatibility-manifest suites passed **165
tests** with **1 skipped** in 202.524 seconds; the manifest module also passed
separately (19 tests). Ruff passed for the production API and its API tests;
the manifest test retains its unrelated pre-existing I001 import-order
finding. Python compilation, Pylance syntax checks, and setuptools `build_py`
passed; the package build included `sapling_output_proof.py` and emitted
existing setuptools license-classifier and package-discovery warnings. These
results do not establish ceremony validity, arbitrary-witness security,
Spend compatibility, constant-time behavior, memory zeroization, or full
production readiness.

## Phase 9.21.30 — Production-safe Sapling Output proving API

The production-facing API in
[`sapling_output_proof.py`](../src/sapling_output_proof.py) accepts a validated
`SaplingOutputWitness` and an opaque parameter object returned by
`load_sapling_output_parameters`. The parameter loader accepts only the
external official Output file with SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` and
BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
It checks Bellman 0.15 format, exact query counts, transcript boundary, and
curve/subgroup validity for all parsed parameter points. Dense query vectors
are reconstructed from compact A/B supports embedded as compressed bitmaps;
tests compare these bitmaps against the verified mapping
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.

The prover synthesizes a fresh Output circuit and checks its matrix
fingerprint, dimensions, public-input ordering and values, QAP domain, and
full witness satisfaction before drawing randomness. It calls
`secrets.randbelow` twice with no deterministic or caller-injected RNG path.
Canonical proof output is compressed G1/G2/G1. Verification accepts a
name-keyed mapping containing exactly the five public inputs, each encoded as
a canonical 32-byte little-endian scalar; malformed point/scalar encodings
raise an API error, while a well-formed invalid proof returns false.

The test generated two non-identical proofs for the same pinned witness using
the production randomizer path. ZyCoin accepted both, and test-only Bellman
0.15 independently accepted both after checking all 7,827 witness
constraints. Both verifiers rejected altered proof points, changed or
reordered inputs, and malformed proof encodings. Tests also confirm an
inconsistent or unsatisfied witness is rejected before randomizer calls and
malformed parameter sources are rejected. The complete API test passed
**5 tests** (157.85 s); the focused witness/map/input subset passed **4 tests**
with the integrated proof test deselected. The broader BLS, Groth16, Output
query/QAP, compatibility, and authentic-parameter set passed **144 tests and
141 subtests**. Python compilation, targeted Ruff, and Pylance diagnostics
passed. An isolated setuptools `build_py` check confirmed the API module is
included in the `zycoin` distribution.

The module does not cache witnesses, assignments, quotient values, or
randomizers and releases local references after each proof call. Python does
not guarantee zeroization or constant-time execution. Exact file hashes pin
the parameter bytes but do not validate the appended ceremony transcript or
prove general parameter-to-circuit binding. The production API is Output
only. Ceremony validity, general setup binding, side-channel properties,
Spend, and full production readiness remain **Unverified**. See the
[API security and usage documentation](../docs/sapling-output-proving.md).

## Phase 9.21.29 — Test-only authentic Output proof interoperability

The test-only driver
[`generate_verify_sapling_output_python_proof.py`](../tests/generate_verify_sapling_output_python_proof.py)
uses the production Python parameter parser, QAP, optimized MSMs,
`assemble_proof_elements`, canonical proof encoding, and verifier. It checks
the external official Output file against SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` and
the pinned BLAKE2b-512 digest before use. The deterministic satisfying
assignment is
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`;
the 7,827-row/7,827-column matrix fingerprint and query-map fingerprint are
unchanged at
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368` and
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.

The canonical public-input encoding is five little-endian 32-byte scalars in
the order `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`. The generated
Bellman-compressed G1/G2/G1 proof is 192 bytes with SHA-256
`22b06dcd01c54e8329cc04ac4270a72de0919642452c478a64c783c4780bb6ef`.
ZyCoin's verifier accepted the proof. A separate Bellman 0.15 test runner
independently checked the witness against all 7,827 pinned constraints,
reconstructed public inputs from that assignment, and accepted the same
proof. The prover consumed IC 6 (including ONE), H 8,191, L 7,821, A 6,298,
B_G1 4,850, and B_G2 4,850 query entries.

Both implementations rejected altered proof points, changed or reordered
public inputs, truncated encodings, and malformed proof-point encodings.
Randomizers are fixed SHA-256-derived test-only values, not secure production
randomness. The parameter file, generated proof, and exchange files were
temporary and not retained.

Python measured 0.700 s for the QAP quotient, 14.998 s for separately
measured query accumulations, 16.038 s for proof assembly (including its own
QAP/MSM work), and 1.484 s for verification. Parsing and subgroup validation
took 51.799 s; the full driver took 164.769 s and peaked at 61,693,952 bytes
working set. Bellman verification of all cases, including parameter loading
and runner startup, took 18.259 s and peaked at 197,558,272 bytes RSS. These
overlapping timing buckets are not additive.

Python proof/query/verifier regressions passed 26 tests and 6 subtests.
Validation recorded for this phase also includes the focused Groth16, Output
QAP/query, and manifest set (130 tests and 135 subtests) and the pre-existing
authentic-parameter
interoperability regression passed 1 test in 78.91 s. Python compilation
passed. Ruff passed for the proof driver and its changed production module;
the manifest test retains an unrelated pre-existing I001 import-order finding.
This evidence establishes one deterministic proof interoperability result,
not ceremony validity or general parameter-to-circuit binding. A production
prover interface, secure production randomness, Spend compatibility, and
production proof readiness remain **Unverified**.

Phase 9.21.27 ran the optimized accumulations against every authentic Output
H/L/A/B_G1/B_G2 point. They took 13.771 s total and matched independently
partitioned optimized runs; affine-oracle comparisons matched first/last
12-term subsets. Parsing and subgroup validation took 47.333 s, with a
54.7 MiB process peak. This is authentic-query MSM validation only: no
authentic proof was generated, and full-section affine equivalence, proof
correctness, ceremony validity, and production readiness remain **Unverified**.

Phase 9.21.28 independently compared all five full authentic proving-query
accumulations and IC against a test-only Bellman 0.15 runner. All six
canonical group encodings matched exactly. Bellman computed its own QAP
quotient and witness scalar vectors from the pinned matrix, assignment, and
sparse query map; it received no Python-generated scalar vectors. No proof
was generated. This establishes accumulation equivalence only; proof
correctness, parameter-to-circuit binding, ceremony validity, and production
readiness remain **Unverified**.

**Output parser-to-Bellman query decoding evidence (Phase 9.21.24):** the
official Output parameter file's 32,016 IC and proving-query points were
decoded by ZyCoin's production
Python parser and independently loaded by Bellman 0.15; all canonical
uncompressed encodings matched byte-for-byte in section/index order. A
test-only Bellman 0.15 prover also used the authentic parameters and exact
pinned 7,827-row matrix to create and verify one proof, which ZyCoin's
pure-Python verifier accepted. At that phase, parser-to-Bellman serialization
compatibility and Bellman-to-Python interoperability were established. Phase
9.21.29 separately demonstrates Python-to-Bellman interoperability. General
parameter-to-circuit/ceremony binding and production readiness remain
**Unverified**.

**Current Spend status (Phase 9.21.17):** the v7 test-only semantic mapping
covers all 8 public/ONE variables and 98,637 of 98,638 auxiliaries. The
test-only row correspondence pairs 98,775 of 98,777 rows (69,840 native,
251 A/B swaps, 28,351 valid factor normalizations, 333 expanded-relation
matches), with zero ambiguities and two unmatched rows per side. Inspection
shows upstream rows 76893–76894 (`(root - rt) * note_value = 0` and
`rt = public_anchor`) reduce to the local conditional-anchor row 76894 by
substitution; the local packed-position reconstruction is a redundant
auxiliary relation because the upstream circuit uses the same Boolean path
directions directly in little-endian order. Thus the audit supports semantic
equivalence of the pinned exported R1CS relations under role mapping and
auxiliary projection, but is not a formal source-level proof or verification
of arbitrary production synthesis paths. The v7 mapping and row artifact
remain unchanged. Exact ordered matrix alignment, formal/complete circuit
equivalence, QAP/query compatibility, authentic proving-key/verification-key
compatibility, and production proof generation remain **Unverified**.

**Current parameter status (Phase 9.21.24):** every authentic Spend and
Output query point passed canonical decoding, curve validation, and an exact
per-point prime-order subgroup test. Sparse query-index maps remain unchanged;
Spend `Aux(76805)` still has no supported local column. These point checks do
not establish circuit or ceremony binding. For Output, exact byte equality
between all 32,016 Python-decoded and Bellman-loaded points is now verified;
this is not an independent derivation of those points from the pinned Output
matrix. The test-only interoperability proof also demonstrates one
operational proving/verification path. Spend compatibility and production
proof generation remain **Unverified**.
The parameter files contain no raw scalar-field values; verifier public inputs
are separately range-checked as canonical BLS12-381 scalars, with synthetic
boundary tests. No pre-existing official proof vector is included; the
test-only interoperability harness generates one deterministic Output proof
when supplied the externally stored official Output parameters. The complete
query-value and ceremony binding remain **Unverified**.

**Current ceremony status (Phase 9.21.25):** both official parameter suffixes
have the expected `phase2` 0.2.2 envelope length for 97 contributions, and
their boundaries are separated from the Bellman parameter prefix. This is
not transcript verification. The phase2 verifier requires the matching
Phase-1 Powers-of-Tau input and exact ceremony circuit/setup; neither the
Spend `phase1radix2m17` nor Output `phase1radix2m13` file is available, and
the exact ceremony-era circuit implementations are not established. The
official files' measured hashes and transcript digests are recorded in the
[implementation report](sapling-circuit-implementation.md#phase-92125--authentic-sapling-parameter-ceremony-transcript-audit).
Ceremony validity and Python proving readiness remain **Unverified**.

The v7 correspondence artifact is
`C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-variable-correspondence-gadget-v7.json`
(SHA-256 `efa67820fdbaf0410cc1fad7380f2468173fedc5fa25ae8366ed0e067124046f`;
mapping fingerprint `26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656`).
The crosswalk SHA-256 is
`0b2b37a5ada665f4d1a640618275c02cea320555b5d58e0a8580b87f25573356`
(mapping fingerprint
`a54e423b92a0fc7649b7d4ad75e369fe957069c151c229b26f0075bb60f38a5b`);
the provenance analysis SHA-256 is
`4fea9950d68756db8bf4a0137df6bc9a1319234eae70c2bb87c14997c9ad14f8`.
The row correspondence artifact is
`C:\Users\EzzyG\.copilot\session-state\dedf634b-2027-4458-b86d-28e6f44497f6\files\sapling-spend-row-correspondence-v1.json`
(SHA-256 `44a14939955a9a82a24f4013bb0b9144a1810b648d6e4d9d3643117330b58ecc`;
row-mapping fingerprint
`f502b0f22dece3829d6e2e1e198ca8d98d82e233e9eb1a4dcded3a399f6ae17d`;
coefficient fingerprint
`883e9561c0f159bafc17f65977d1311f30f8f6e39bf66569fde51c85a24c3a32`).
Deterministic regeneration reproduced it byte-for-byte, and the v7 variable
mapping SHA-256 remains
`efa67820fdbaf0410cc1fad7380f2468173fedc5fa25ae8366ed0e067124046f`.
Focused anchor/position semantic tests passed (8 tests, 17 subtests), with
deterministic boundary-probe SHA-256
`94d29c70b4f5ce62e37ffa0083300fa7025699b90fbc81c7c16a6b1e278964cd`.
The updated row/variable/manifest focused set passed (50 tests, 28 subtests);
the targeted Spend, Output, Bellman, QAP, Groth16, and compatibility
regressions passed (276 tests, 570 subtests). The algebraic audit supports
semantic equivalence of the pinned exported R1CS relations under the accepted
mapping and auxiliary projection, but does not constitute a formal
source-level proof. Exact ordered Spend matrix alignment and authentic
parameter and proof compatibility remain unverified.

The pinned upstream Sapling implementation contains separate `Spend` and
`Output` circuits and separate spend/output parameter types. The spend
witness includes the value-commitment opening, proof-generation key, payment
address, note-commitment randomness, spend randomizer, note authentication
path, and anchor. The output witness includes the value-commitment opening,
payment address, note-commitment randomness, and ephemeral secret. Their
circuits constrain Sapling note commitments and expose the relevant
transaction public inputs; implementing the generic Groth16 algorithm alone
would not implement either circuit.

## Reusable ZyCoin functionality

- `jubjub.py` provides pure-Python Jubjub field/point arithmetic and Sapling
  group hashing.
- `sapling_tree.py` provides Pedersen Merkle hashing, commitment trees,
  authentication paths, and witnesses.
- `derivation.py`, `note_decryption.py`, and `nullifiers.py` provide
  ZIP32-derived key components, validated decrypted-note data, and nullifier
  derivation.
- The transparent ZIP-243 implementation is a separate transaction-signing
  path and is not a Sapling proof backend.

The [pure-Python BLS12-381 implementation](bls12-381-arithmetic-and-pairing.md)
now supplies field arithmetic, G1/G2 operations, point encodings, subgroup
checks, an optimal-Ate Miller loop, and final exponentiation. Phase 9.20 added
a generic scalar-field [R1CS foundation](sapling-circuit-implementation.md)
and ZyCoin Spend/Output assemblies. Spend now has the same row count as
pinned Bellman, but its complete ordered matrix is not established as
equivalent. Phase 9.20.67 corrected two source-backed Output shape differences.
Phase 9.20.68 uses the Bellman-shaped Montgomery Pedersen route for Output;
its local count now matches the pinned 7,827 rows, and its isolated note-hash
matrix matches an independent transcription. The complete Output recorder
matches local production R1CS. Phase 9.21.02 adds a complete external
upstream typed-allocation/assignment and ordered-row export, confirms source
integrity and the pinned test hash, and maps selected public and scalar-bit
assignments. Phase 9.21.05 establishes a complete semantic variable mapping
for all 7,821 auxiliaries and relation equivalence across all 7,827 Output
constraints. Exact ordered-matrix equality, Groth16 query translation, and
parameter compatibility remain unverified.
Phase 9.21.06 confirms that the identity/public/auxiliary mapping translates
assignment indices but not Output's QAP-dependent query points: row order,
factorization, and query values differ in a bounded synthetic setup.
Neither circuit is established as compatible with
authentic parameters. The repository has a synthetic
Groth16 QAP/query/proof/verification path, but no authenticated Sapling
parameter loader or real Sapling witness-to-proof pipeline. A bounded
structural Bellman parameter-stream parser was added in Phase 9.20.57; no
production parameter files are bundled or retained.
`src/coins/*.json` filename declarations are not evidence that a network's
files are authentic or circuit-compatible.

The current Spend allocation-provenance crosswalk establishes 8 public/ONE
identities and 28,150 auxiliary identities: the 758 previously mapped
allocations plus 27,392 Merkle-path allocations, uniquely distinguished by
their 32 level contexts. Another 70,488 auxiliaries per side remain
unresolved, so this partial mapping is not enough to translate the complete
Spend QAP or Groth16 queries. Exact Spend row alignment, complete Spend
recorder synthesis, Groth16 query compatibility, authentic parameter
compatibility, and production proof generation remain **Unverified**.

## Required pipeline and blockers

1. **Circuit witness construction:** validate note/value/keys, a verified note
   position and authentication path, anchor, ZIP-212 note rules, and all
   circuit-specific relations.
2. **Circuit identity:** establish exact equivalence between the ZyCoin
   Spend/Output matrices and the pinned Bellman circuits. The Spend row count
   now matches (98,777), but whole-matrix and exact auxiliary-allocation
   equivalence are not established. Output has a complete external,
   test-only pinned upstream export for 7,827 rows and 7,827 columns. All six
   typed inputs and 7,821 auxiliaries have a one-to-one semantic mapping with
   matching assignments. All 7,827 constraints match as a relation multiset
   after valid factor transformations and expanded-polynomial normalization.
   Exact ordered matrices, Groth16 query translation, and parameter
   compatibility remain unverified. Matching dimensions and relation
   equivalence do not establish parameter compatibility.
3. **Proving parameters:** the official Zcash endpoints serve distinct
   [`sapling-spend.params`](https://download.z.cash/downloads/sapling-spend.params)
   and
   [`sapling-output.params`](https://download.z.cash/downloads/sapling-output.params)
   artifacts. Phase 9.20.41 streamed and SHA-512 hashed each file, cross-
   checked the values against an independent source pin, and recorded the
   observed byte lengths and hashes in the [circuit report](sapling-circuit-implementation.md#phase-92041--groth16-parameter-compatibility).
   No files were retained. Phase 9.21.18 updates the bounded parser for
   Bellman's independently sparse A/B query sections, BLAKE2b-512 digest
   checking, and Zcash's trailing transcript (when explicitly enabled).
   Current `librustzcash` source declares BLAKE2b-512 pins, which were matched
   by streaming the authentic files in this phase. They differ from the
   Phase 9.20.41 SHA-512 values because the algorithms differ. No
   authenticated loader, sparse-query index reconstruction, or
   circuit-specific eligibility check exists. Parsing and digest checks
   alone do not establish compatibility with ZyCoin's matrices.
4. **Parameter-bound Groth16 proving:** the pure-Python FFT, QAP,
   query-evaluation, proof-assembly, and verification modules have synthetic
   regression coverage. They have not been bound to authentic Sapling
   parameters or established as equivalent to Bellman's full circuit
   matrices. The implementations are not constant-time or production-ready;
   real proving would also require trusted parameters and secure randomization.
5. **Independent Sapling validation:** expand beyond the test-only Output
   interoperability proof to additional witnesses and authoritative Sapling
   proof vectors, and independently establish complete parameter/query
   binding. Spend remains unverified. ZIP32, note-decryption, nullifier,
   ZIP-243, and Merkle fixtures are not Groth16 proof vectors.

The pinned upstream reference uses `bellman`/`groth16` and `bls12_381` Rust
crates; those are useful protocol references but cannot be brought in under
the project's Python-only and no-native-dependency constraints. Completing
the authenticated, circuit-compatible Sapling proving pipeline remains a
substantial cryptographic project; the synthetic APIs do not claim a
production or real-chain proof.

## Capability status

| Capability | Status | Evidence / limitation |
|---|---|---|
| Jubjub and Sapling Merkle primitives | **Implemented, Verified** | Existing reference tests cover ZIP32/key components, nullifiers, MerkleCRH, and tree/witness outputs. These do not establish BLS12-381 or Groth16 support. |
| BLS12-381 G1/G2, extension fields, pairing | **Implemented, independently vector-checked** | See [the implementation report](bls12-381-arithmetic-and-pairing.md); not formally verified, constant-time, or production-ready. |
| Generic R1CS foundation | **Implemented, locally tested** | ZyCoin-only builder and shape serializer; not compatible with Bellman serialization. |
| Spend and Output circuit synthesis | **Implemented locally; Output semantic relation verified** | Spend has 98,777 rows and no complete upstream export. Output has 7,827 rows × 7,827 columns with local production/recorder parity and a complete external pinned export. All six typed inputs and 7,821 auxiliaries map one-to-one with matching assignments; all 7,827 relation rows match after documented normalization. Exact ordered matrices and query translation remain unverified. See Phases 9.21.00–06 in the [circuit status report](sapling-circuit-implementation.md). |
| Official Spend/output parameter artifacts | **SHA-512 and BLAKE2b-512 verified against streamed bytes** | Both official files were streamed without retention; exact lengths and both digest algorithms matched. Bellman section counts and transcript lengths are recorded in the [circuit report](sapling-circuit-implementation.md#phase-92118--authentic-sapling-parameter-format-audit). Every query point was checked; one Output proof interoperated, while complete query-value compatibility remains unverified. |
| Bellman parameter-stream validation | **Implemented, synthetic-fixture tested** | Bounded streaming validation checks uncompressed points, subgroup membership, Bellman section structure, compact sparse A/B counts, and strict EOF by default. Explicit transcript mode hashes bounded trailing bytes. Manifests include SHA-256 and BLAKE2b-512. Digest trust still requires an independently trusted expected value. |
| Parameter-to-circuit compatibility gate | **Partial Output interoperability demonstrated** | A Bellman proof from the authentic Output parameters and pinned matrix was accepted by the Python verifier for one witness. Per-query value equivalence, ceremony binding, and Spend compatibility remain unverified. |
| Radix-2 FFT and QAP | **Implemented, synthetic/reference-tested** | Pure-Python scalar-field FFT/IFFT, coset transforms, R1CS-to-QAP construction, and quotient evaluation are implemented. They do not prove Sapling circuit compatibility. |
| ZyCoin parameter authenticity/eligibility | **Partial, test-only Output evidence** | Published digests and the parameter stream were checked; sparse positions map to the pinned matrix, and one authentic-parameter proof verified. No production parameter eligibility API or complete pointwise query/circuit binding is established. |
| Synthetic Groth16 assembly and verification | **Implemented, synthetic-only** | Deterministic fixtures exercise query evaluation, proof assembly, and pairing verification; this is not a real Sapling proof or trusted setup. |
| Spend proof generation | **Unsupported for Sapling** | Local circuit/query/proof components are not mapped to authenticated, circuit-compatible Spend parameters. |
| Output QAP/query compatibility | **One-way operational interoperability verified for one witness** | Bellman created and verified a proof using the authentic parameter stream and exact pinned Output matrix; the Python verifier accepted it. This does not establish full per-query value equivalence or ceremony binding. |
| Real Output proving-key compatibility | **Partially Verified for one proof** | Bellman used the authentic proving-query sections with the pinned matrix to create one proof; complete query-value compatibility and Python proving remain unverified. |
| Real Output verification-key compatibility | **Partially Verified for one proof** | The Python verifier accepted the Bellman-generated proof with the authentic VK and five ordered public inputs. |
| Output proof generation | **Test-only Bellman generation verified; production Python generation unverified** | A pinned Output witness generated a proof in the test-only Bellman runner. The existing Python prover was not run; its measured scalar-multiplication cost projects to more than 76 minutes before validation/QAP overhead. |
| Real Sapling Groth16 verification | **Partially Verified for Output only** | The Python verifier accepted one test-only Output proof and rejected proof/input mutations. Spend has no authentic proof verification result. |
| Sapling spending | **Unsupported; gated** | Proofs, authorization and binding signatures, transaction assembly, and independent verification are incomplete. BitcoinZ ZIP32 account-path verification also remains gated. |

Synthetic performance and behavior results are scoped in Phases 9.20.62–65;
they are not production benchmarks. No production proof, key, witness,
transaction, or parameter material was stored or used. The Phase 9.20.41
audit streamed public parameter bytes only to calculate hashes; it did not
retain or use them.

## Phase 9.20.42 circuit-shape update

The checked strict coordinate decomposition was safely reduced to the pinned
Bellman-style prefix-AND relation. The current local Spend assembly is
127,823 rows over 127,144 columns; Output is 9,654 rows over 9,400 columns.
Their versioned local fingerprints are respectively
`8fbe0deea3c3386e28cdf582a98658a9c37c49ca1d353c77050d9643fef482f8` and
`8078509dd71169f7931212dc38b0809e68d389e729853c8301d84b9f35a02cac`.
These replace the earlier local measurements in this report for current
status. Upstream remains at 98,777 Spend rows and 7,827 Output rows. The
remaining gaps are 29,046 and 1,827 rows; count agreement is not the basis
for an equivalence claim.

The Spend gap is accounted for by the measured/source-derived semantic
grouping: differing Pedersen structure (27,990), BLAKE2s structure (1,054),
and two explicit local bindings. Output's remaining component differences
include Pedersen/allocation, affine addition, scalar decomposition, and
variable-base structure; a reliable upstream per-relation breakdown is not
available. Because neither ordered upstream matrix is available, both
circuits remain **blocked / not eligible** for authentic Sapling proving
parameters. The reduction does not change public inputs or host admission
semantics, does not implement proving, and does not enable spending. See the
[Phase 9.20.42 circuit-shape reconciliation](sapling-circuit-implementation.md#phase-92042--spendoutput-upstream-shape-reconciliation)
for methodology and regression evidence.

## Phase 9.20.43 Pedersen shape update

The Pedersen signed-lookup conditional-negation relation now combines its
product and equality into one algebraically equivalent R1CS row. After this
change the local Spend assembly is 122,125 rows over 121,446 columns and the
Output assembly is 9,460 rows over 9,206 columns. Their current local
fingerprints are `5a30865162cc958176e1be6efbc2a72486fa3cabbb41a1ff339bbf7860bd6b2a`
and `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739`.
Upstream remains at 98,777 and 7,827 rows; the local matrices remain
ineligible for authentic Sapling proving parameters.

Pinned boundary vectors and per-segment counts confirm the expected
personalization, bit order, signed-digit encoding, and resulting points. The
remaining Pedersen overhead comes from ZyCoin's Edwards-coordinate lookup
and affine additions compared with Bellman's Montgomery lookup/addition and
segment conversion. No BLAKE2s or explicit binding relation was changed.
Neither matrix equivalence nor Groth16 readiness is claimed; spending remains
gated. See the [Pedersen reconciliation](sapling-circuit-implementation.md#phase-92043--pedersen-hash-bellman-reconciliation).

## Phase 9.20.44 BLAKE2s shape update

The shared BLAKE2s gadget now packs its 320 bounded modular-addition
equalities into Bellman's 46 scalar-capacity-bounded rows and represents
constant-one XORs as zero-cost Boolean negation aliases. The one-block,
512-variable-bit BLAKE2s profile is **21,518 rows**, matching the pinned
Bellman 0.15.0 test count. This count match does not establish ordered matrix
equivalence: ZyCoin's XOR polynomial uses different coefficients, and no
complete ordered upstream A/B/C export is available.

The current Spend assembly is **121,071 rows over 120,940 columns**, with
fingerprint
`9cf4d3458d4bd02acfbdc179b031d9cdc7314d927f9310c4f118bb338f9add6f`.
Output is unchanged at 9,460 rows over 9,206 columns and retains fingerprint
`885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739`.
Spend remains 22,294 rows above Bellman's 98,777, entirely accounted for by
the documented 22,292-row Pedersen shape difference and two explicit local
bindings. Both circuits remain **blocked / not eligible** for authentic
Sapling proving parameters; proving is not implemented and spending remains
gated. See the [Phase 9.20.44 BLAKE2s reconciliation](sapling-circuit-implementation.md#phase-92044--blake2s-gadget-bellman-reconciliation).

## Phase 9.20.45 BLAKE2s XOR update

ZyCoin's variable-variable XOR now emits Bellman 0.15.0's exact row
`(2a) * b = a + b - x`, with the same raw output allocation order.
Exhaustive truth-table and polarity tests inspect the canonical A/B/C terms;
the one-block compression remains 21,518 rows. Boolean negations now
propagate as aliases through compression. The local Sapling IVK and nullifier
wrappers still materialize 130 and 136 complemented digest bits respectively
because their scalar-multiplication/multipacking APIs require variable bits.
Those **266 adapter rows/columns** are outside the XOR relations and account
for the remaining BLAKE2s structural difference.

The current Spend assembly is **121,337 rows over 121,206 columns**, with
fingerprint
`1f586c7fb91c078feed5a8cadc00350665a4b2a0e6627dd8e402811e0a0e4d91`.
Its 22,560-row gap to Bellman's 98,777 consists of 22,292 Pedersen rows,
266 BLAKE2s interface adapters, and two explicit local bindings. Output
remains unchanged at 9,460 rows over 9,206 columns. Matching XOR equations
and constraint counts do not establish full matrix equivalence; no
authoritative ordered upstream Spend/Output matrices are available. Both
circuits remain blocked for authentic proving parameters, and spending stays
gated. See the [Phase 9.20.45 XOR reconciliation](sapling-circuit-implementation.md#phase-92045--blake2s-xor-gadget-bellman-equivalence).

## Phase 9.20.46 BLAKE2s compression matrix update

A full one-block, 512-variable-bit compression matrix is now compared against
a Python transcription of pinned Bellman 0.15.0 synthesis. The complete
canonical ordered A/B/C matrix matches: 21,518 rows, 21,473 columns, and
fingerprint
`fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785`.
This comparison exposed and corrected the local Boolean-row placement and
the 46 packed-addition row placements. It does not derive an upstream-exported
matrix file; the evidence is source-derived and the test checks complete
matrix bytes against the auditable Python transcription.

The 266 wrapper adapters are explicitly outside compression: 130 IVK bits
and 136 nullifier bits are materialized as ordinary variables for local
consumer interfaces. Spend remains 121,337 rows over 121,206 columns, but
its corrected matrix fingerprint is now
`72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6`.
The 22,560-row gap to Bellman's Spend circuit remains 22,292 Pedersen rows,
266 adapters, and two local bindings. No full Spend matrix equivalence,
Groth16 readiness, or spending support is claimed; both Sapling circuits
remain blocked for authentic proving parameters.

## Phase 9.20.47 complete BLAKE2s hash update

The test-only Bellman 0.15.0 transcription now includes message block
construction, padding, byte counters, final-block flags, chaining-state
updates, and little-endian digest extraction. Complete hash matrices compare
byte-for-byte for the pinned Sapling IVK and nullifier configurations, with
fingerprints
`1ec15b1eb11bc673d71aa761acb8e396a4bb74a5945940d302cfbfa6a429cc0d`
(`Zcashivk`) and
`701c5a72f19a024a3f7b436f5364820efa4a824364b00753c9a06ef04d2ef569`
(`Zcash_nf`). Boundary matrices match at 0, 1, 63, 64, 65, 127, 128, and
129-byte inputs. These are source-derived Python reference comparisons, not matrices
exported by Bellman's Rust test runner.

The one-block compression fingerprint remains
`fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785`.
Spend remains 121,337 rows over 121,206 columns with fingerprint
`72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6`.
Hash-level matrix agreement does not imply whole Spend matrix equivalence;
Sapling proving remains blocked and spending remains gated. See the
[complete hash reconciliation](sapling-circuit-implementation.md#phase-92047--complete-sapling-blake2s-hash-gadget-reconciliation).
The CPython 3.10.11 full suite passes (**132 tests**); focused BLAKE2s, Spend,
and R1CS suites pass (**19**, **4**, and **13 tests**, respectively). Final
wheel/sdist and clean-target matrix replay evidence is recorded in the
complete hash reconciliation report.

## Phase 9.20.48 Spend Pedersen matrix update

The test-only Python transcription now follows the pinned Sapling/Bellman
Pedersen composition for the 576-bit NoteCommitment message and all 32
510-bit MerkleTree(depth) messages. It compares each complete canonical
ordered A/B/C matrix against ZyCoin's isolated hash matrix, with caller-side
message Boolean admission included in both. The matrices are intentionally
not identical: the note hash differs by 756 internal rows, each Merkle hash
by 673, for 22,292 Pedersen rows across Spend. The ledger traces those rows
to the Edwards versus Montgomery lookup/addition forms, segment conversion,
allocation order, and row order. Note commitment randomization is separate;
the nullifier path uses rho construction and BLAKE2s, not Pedersen.

The Spend fingerprint is unchanged at
`72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6`
(121,337 rows / 121,206 columns). The one-block BLAKE2s and complete IVK
and nullifier wrapper fingerprints also remain unchanged. The Python
transcription is not an exported Bellman matrix and does not establish
whole-circuit equivalence; Groth16 parameter eligibility remains blocked and
Sapling spending remains gated. See the [Phase 9.20.48 Pedersen
reconciliation](sapling-circuit-implementation.md#phase-92048--sapling-spend-pedersen-composition-reconciliation)
for source provenance, dimensions, fingerprints, and the complete ledger.

## Phase 9.20.49 Spend binding update

The Spend assembler no longer allocates separate `ar` or note-value scalar
variables. It passes the Boolean `ar` decomposition directly to fixed-base
multiplication and reuses the 64-bit note-value linear combination in the
conditional-anchor relation. These changes follow the pinned upstream
`field_into_boolean_vec_le` and `Num::add_bool_with_coeff` composition; the
R1CS Boolean, multiplication, value-opening, and anchor relations remain
enforced. Isolated substitution tests show that the former note-value binding
was necessary only because a separate scalar could otherwise be set to zero.

Spend is now **121,335 rows / 121,204 columns**, fingerprint
`73160f3bdcaff7a2a98fd62eab5cabc856224203239d4e757bf666dee3bc8733`.
The 22,558-row difference from Bellman's 98,777 rows consists of 22,292
Pedersen structural rows and 266 BLAKE2s interface adapters; no explicit
local binding rows remain. This is not a full ordered-matrix comparison:
both local Bellman references are source-derived Python transcriptions, not
upstream matrix exports. Spend remains **blocked** for authentic Sapling
parameters and spending stays gated. See the [Phase 9.20.49 composition
audit](sapling-circuit-implementation.md#phase-92049--spend-explicit-bindings-and-composition-audit).
The CPython 3.10.11 full suite passes (**135 tests**); detailed lint,
diagnostic, and package validation evidence is in the circuit report.

## Phase 9.20.50 Spend Pedersen/BLAKE2s composition update

The Spend-only BLAKE2s wrappers now preserve complemented-bit aliases across
the IVK fixed-base/variable-base consumers and nullifier multipacking. The
previous 130 IVK and 136 nullifier materialization rows and columns are gone;
the isolated comparison verifies each removed boundary has identical digest,
Jubjub result, or packed public chunks and rejects mutated aliases. The full
Spend now has **121,069 rows / 120,938 columns** and fingerprint
`bf491500c18a6c2fbe1605f4921c0163a44c24d5b07a2271fad851cd00d493a2`.
Its exact **22,292-row** difference from the pinned Bellman count is the
NoteCommitment Pedersen delta of 756 plus 32 Merkle Pedersen deltas of 673.
The composed IVK and nullifier hash bodies match the source-derived Bellman
reference row counts with shared input admissions; all other current Spend
relation groups also match the pinned row ledger.

The IVK-to-scalar and nullifier-to-multipacking consumer matrices also match
the source-derived Python Bellman transcriptions byte-for-byte in isolated
tests. This is not an authoritative upstream matrix export and does not
establish whole-circuit equivalence. Final Phase 9.20.50 validation used
CPython 3.10.11: **137 pytest tests passed**, changed-file Ruff and Pylance
checks passed, compileall and wheel/sdist builds passed, and the wheel
installed and exposed its coin-configuration and wordlist resources from a
clean target. Sapling Spend remains blocked for authentic-parameter use and
spending remains gated.

These are component-level row and source-transcription results, not a whole
Spend ordered-matrix comparison or authentic-parameter compatibility proof.
Spend remains blocked for Groth16 eligibility and Sapling spending remains
gated. See the [Phase 9.20.50 composition ledger](sapling-circuit-implementation.md#phase-92050--spend-pedersen-and-blake2s-composition-reconciliation).

## Phase 9.20.51 Pedersen discrepancy review

The remaining 22,292 Spend rows are accounted for by the Pedersen
representation structure: `4N - 5S` rows and auxiliary columns for `N`
three-bit windows across `S` 63-window segments. This yields 756 for the
576-bit NoteCommitment message (`N=194`, `S=4`) and 673 for every
510-bit Merkle message (`N=172`, `S=3`), or 21,536 across 32 depth-personalized
Merkle instances. The source-derived Python transcription's lookup,
Montgomery addition/conversion, and Edwards segment-combination relations
were checked against the pinned Bellman/Sapling source and count assertions.
Phase 9.20.51 validation passed on CPython 3.10.11: **137 full-suite tests**,
8 focused Pedersen tests, and 17 Spend/R1CS tests passed. Ruff, compileall,
Pylance diagnostics/signature compatibility, wheel/sdist builds, and
clean-target wheel import/resource checks also passed.

No constraint was removed. Local Edwards intermediate representation differs
from Bellman's Montgomery segment representation, so the count match alone
cannot establish matrix identity or parameter compatibility. The current
At Phase 9.20.51, Spend remained at 121,069 rows. Phase 9.20.52 adds a
Spend-only Montgomery Pedersen path whose isolated ordered matrices match
the existing source-derived Python transcription for NoteCommitment and all
32 Merkle depths. Spend now has 98,777 rows / 98,646 columns and fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
This equality of row counts and component transcription matrices is not an
authoritative whole-circuit matrix comparison; authentic parameter use
remains blocked and spending remains gated. See the
[Phase 9.20.52 Montgomery alignment](sapling-circuit-implementation.md#phase-92052--montgomery-representation-pedersen-alignment).

## Phase 9.20.53 complete Spend composition update

A new full-assembly regression substitutes source-derived Python
transcriptions for all 33 Spend Pedersen calls and both BLAKE2s configurations.
The composed and local ZyCoin assemblies have identical ordered canonical
matrices, relation-group counts, local variable allocation, seven public
inputs, and deterministic witness satisfaction: 98,777 rows, 98,646 columns,
fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
This verifies the composition boundaries and shared wiring for those
transcribed components. Other Spend gadgets are not independently
transcribed, and the local public-first input allocation differs from
Bellman's interleaved allocation. No authoritative whole-circuit Bellman
matrix export is available, so exact Bellman row/column identity and Groth16
parameter compatibility remain unverified. Spending remains gated. See the
[Phase 9.20.53 composition reconciliation](sapling-circuit-implementation.md#phase-92053--complete-spend-composition-reconciliation).

## Phase 9.20.54 variable allocation update

The allocation audit corrects the interpretation of interleaved
`inputize` calls: Bellman 0.15.0's test constraint system maintains separate
`Input` and `Aux` namespaces, with `ONE` at `Input(0)`. ZyCoin's local
columns 0–7 therefore map exactly to Bellman's `Input(0..7)` identities,
including the seven ordered application inputs. Local auxiliary allocation
order is deterministic and pinned, but exact Bellman `Aux(n)` identity is
unverified; source-order differences include `pk_d` representation,
`rcm` allocation, and per-level path-position bits. The local position
scalar/reconstruction row and Bellman's anchor alias/equality row are a
source-backed one-row/one-auxiliary cancellation, not identical witnesses or
matrix rows. No allocation mode or circuit change was made. Whole-circuit
Bellman matrix equivalence and Groth16 eligibility remain unverified. See the
[Phase 9.20.54 allocation audit](sapling-circuit-implementation.md#phase-92054--bellman-spend-variable-allocation-and-synthesis-order).

## Phase 9.20.55 remaining Spend gadget update

The remaining local Spend relations were traced to pinned `sapling-crypto`
and Bellman source. Jubjub membership, non-small-order, addition/doubling,
fixed- and variable-base multiplication, value commitment, nullifier
multipacking, randomized authorization-key, and Merkle equations match the
source-level formulas, encodings, and vector-tested behavior described in the
[Phase 9.20.55 audit](sapling-circuit-implementation.md#phase-92055--remaining-spend-gadget-equivalence-audit).
Point arithmetic identity/inverse cases now have isolated R1CS satisfaction
and output-tampering regressions. Value commitments, packing, path bits,
public bindings, and adversarial mutations retain their existing focused
tests.

This is not an ordered matrix comparison. Apart from the already-tested
Pedersen and BLAKE2s source-derived Python transcriptions, no independent
Bellman matrix transcript is available for the remaining gadgets. Their
source-equation and vector evidence does not establish exact row order,
coefficients, or auxiliary-variable identity. The path-position/anchor
allocation difference remains documented; the local host admission rule for
`ak` also checks subgroup membership beyond Bellman's circuit-level
non-small-order relation. That check does not add a circuit constraint.
No Spend semantics, Output semantics, or circuit rows were changed.

Spend remains 98,777 rows / 98,646 columns with local fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
Whole-circuit Bellman matrix equivalence, authentic parameter eligibility,
proof generation, and Sapling spending remain unverified or unsupported;
spending remains gated.

## Phase 9.20.56 — Groth16 parameter and proving-pipeline readiness audit

This is a source and implementation audit only. No parameter files were
downloaded or opened, and no proving key, witness, secret, proof, or private
material was retained. The source basis is Sapling commit
[`88a7946b4a3066787776e11f0a502654167e022d`](https://github.com/zcash/sapling-crypto/tree/88a7946b4a3066787776e11f0a502654167e022d),
Bellman/Groth16 0.15.0 release commit
[`b726862a4ece8a627e7fea486d77b502a6edbb0b`](https://github.com/zkcrypto/bellman/tree/b726862a4ece8a627e7fea486d77b502a6edbb0b),
and the BLS12-381 0.9.0 serialization and group APIs.

### Parameter format and circuit binding

Sapling's `SpendParameters::read` and `OutputParameters::read` wrap the same
`groth16::Parameters<Bls12>::read(reader, verify_point_encodings)` parser.
The wrapper types describe which prover/verifying-key API will consume the
result; they do not change the wire format. The stream is an ordered,
uncompressed Bellman serialization, not a self-describing container:

| Stream order | Contents | Encoding |
|---|---|---|
| VK | `alpha_g1`, `beta_g1`, `beta_g2`, `gamma_g2`, `delta_g1`, `delta_g2` | G1 96 bytes each; G2 192 bytes each |
| VK input query | `ic_len`, then `ic[]` | 4-byte unsigned big-endian count; G1 entries |
| Proving query H | `h_len`, then `h[]` | 4-byte unsigned big-endian count; G1 entries |
| Proving query L | `l_len`, then `l[]` | 4-byte unsigned big-endian count; G1 entries |
| Proving query A | `a_len`, then `a[]` | 4-byte unsigned big-endian count; G1 entries |
| Proving query B in G1 | `b_g1_len`, then `b_g1[]` | 4-byte unsigned big-endian count; G1 entries |
| Proving query B in G2 | `b_g2_len`, then `b_g2[]` | 4-byte unsigned big-endian count; G2 entries |

Each G1 uncompressed point is `x || y`, two 48-byte big-endian Fp values.
Each G2 point is `x || y`, where each Fp2 coordinate is serialized as
`c1 || c0`, and each coefficient is 48-byte big-endian Fp. The uncompressed
point format uses the BLS12-381 flag bits in the high bits of the first byte;
the compression flag is clear. The six fixed VK points occupy 864 bytes and
the six count prefixes occupy 24 bytes, before the variable-length arrays.
The `bls12_381` point encoding specification defines the field order and
flags. **No Fr scalar values are serialized in this parameter stream.**
Scalars are used internally by the QAP/prover; parameter queries are group
points. This uncompressed parameter encoding is distinct from compressed
proof encoding: a proof is A(G1) || B(G2) || C(G1), 48 + 96 + 48 = 192 bytes.

The serializer writes the VK first and then H, L, A, B_G1, B_G2. There is no
magic prefix, explicit version, curve tag, checksum, or circuit identifier
in this serialization. A parser consumes the counts and points in this
order. Consequently, the filename or wrapper type alone cannot establish
which circuit or trusted ceremony produced an arbitrary byte stream.

Bellman's setup source determines the expected query cardinalities:

- `ic_len` is the number of input variables, including implicit `ONE`;
  Sapling Spend has 8 entries (7 application inputs plus ONE), and Output
  has 6 (5 plus ONE).
- `l_len` equals the number of auxiliary variables.
- `a_len`, `b_g1_len`, and `b_g2_len` each equal inputs plus auxiliaries.
- H has `domain_size - 1` points. The radix-2 domain is the next power of
  two covering the synthesized constraints plus the dummy input constraints
  that Bellman adds for density. Domain limits are bounded by the Fr
  two-adicity.

The generic reader reads each count as an untrusted u32 and iterates that
many points. It does not derive these circuit-specific length relationships,
cap allocations against synthesized dimensions, or perform a final
trailing-byte check. Bellman's `checked` argument selects checked versus
unchecked uncompressed decoding for the five proving-query vectors. Checked
decoding validates canonical coordinates, curve membership, and subgroup
membership; unchecked decoding is unsafe for untrusted point bytes. The VK
is decoded through the checked path. The reader rejects identities in `ic`
and the proving-query vectors, but the VK's six fixed elements are not all
explicitly subjected to that same identity rule by the generic reader.
Strict application validation must therefore enforce the intended
non-identity and query-length conditions as well as point decoding.

The official file names, byte lengths, and SHA-512 pins were recorded by the
earlier Phase 9.20.41 streamed-hash audit; they are not re-downloaded here.
Those digests establish identity against the pinned public artifacts when
checked against a trusted expected digest. They do not prove that the local
Spend or Output matrices match the parameter-generating circuits. Spend's
row count now matches Bellman's 98,777, but exact ordered matrix and
auxiliary-allocation equivalence remain unverified. Output remains at
10,170 local rows versus 7,827 upstream rows. Neither current circuit is
eligible for these parameters.

### Operation-by-operation coverage

| Required operation | Existing ZyCoin surface | Audit status and gap |
|---|---|---|
| Fr and Fp arithmetic | `Fp`, `Scalar`, `Fp2`, `Fp6`, `Fp12` in `src/bls12_381.py` | Implemented with Python integer arithmetic and representative independent vectors. Not constant-time, formally verified, or comprehensively audited. `Scalar` reduces integer inputs modulo Fr; it is not a canonical scalar-byte parser. |
| G1/G2 arithmetic and subgroup checks | Affine add, double, signed double-and-add multiplication, `is_on_curve`, `is_in_subgroup` | Implemented and exercised by generator, group-law, subgroup-rejection, and pairing tests. No multi-scalar multiplication/query-evaluation engine exists; affine inversions and scalar-bit branches are variable-time. |
| Pairing and final exponentiation | `miller_loop`, `final_exponentiate`, `pairing` | One reduced pairing has an independent generator vector and bilinearity coverage. There is no Groth16 multi-pairing/prepared verifying-key API or proof-equation implementation; a single pairing vector is not a production audit. |
| Compressed point encoding | `encode_g1/g2`, `decode_g1/g2` | Compressed canonical point encoding/decoding and default subgroup checks exist. Decoders allow identity and expose `check_subgroup=False`; proof-level parsing must reject identity and require subgroup checks. |
| Parameter uncompressed point encoding | None | Missing. The current point APIs do not parse the uncompressed 96-byte G1 / 192-byte G2 query representation used by parameters. |
| Bounded parameter parser and validation | None | Missing. No read limits, strict EOF check, circuit/query dimension checks, VK/parameter representation, authenticated resource loader, or malformed-file test suite exists. |
| R1CS construction and matrix serialization | `R1CS` in `src/r1cs.py`, local Spend/Output builders, `groth16_qap.py` | Local constraint construction, witness checks, and canonical matrix encoding exist; Phase 9.20.61 adds assignment-specific R1CS-to-QAP conversion. Circuit identity checks and parameter-backed proving remain unsupported. |
| QAP and polynomial domain | `groth16_fft.py`, `groth16_qap.py` | Implemented: Bellman-shaped constraint domain, assignment-specific A/B/C evaluations and interpolation, and coset-based quotient construction with assignment/divisibility checks. Full per-variable setup polynomials, QAP-to-key evaluation, and proving remain missing. |
| Proving-key query evaluation | `groth16_queries.py` | Implemented: checked G1/G2 variable-base MSMs for witness A/B, auxiliary-only L, and QAP H coefficients. No real query artifacts are loaded; the affine Python MSM is variable-time and not suitable for production secret handling. |
| Groth16 proving/verification key structures | Partial | Typed immutable point-query vectors exist in `groth16_queries.py`; bounded parser output is not yet assembled into authenticated circuit-specific proving-key objects. |
| Proof construction and verification | None | Missing: witness-to-QAP evaluation, query MSMs, randomized A/B/C construction, proof parser/serializer object, prepared VK, and Groth16 pairing equation. |
| Proof randomness and secret handling | No integrated Groth16 RNG path | Missing. Fresh independent uniformly sampled Fr values are required per proof. Existing cryptographic primitives use variable-time Python and cannot safely hide witness-dependent operations from timing observation. Python also cannot reliably guarantee zeroization of immutable integer/object copies. |

The Groth16 verifier requires the public input vector length to match the
verification key's `ic` query (with the implicit constant handled separately),
forms the public-input linear combination of IC points, and checks the
pairing-product equation. Bellman's verifier uses prepared verification-key
pairing data and a multi-Miller-loop/final-exponentiation path. ZyCoin's
single-pairing API and local public-input matrix convention are not that
verifier.

### Security and validation requirements

Any future parser/prover work must, at minimum:

1. Authenticate the exact source artifact using a trusted, circuit-specific
   digest before treating it as the intended Sapling CRS. Then still validate
   the full stream: truncation, invalid flags, non-canonical Fp values,
   off-curve/non-subgroup points, illegal identities, unexpected counts,
   trailing bytes, and resource exhaustion must fail closed.
2. Derive and cap all section counts from the exact pinned circuit synthesis
   and expected dimensions before allocation. u32 length prefixes must never
   drive attacker-controlled unbounded memory or CPU work.
3. Keep the untrusted-data path on checked subgroup decoding. Do not expose a
   generic `verify_point_encodings=False`/unchecked route as a routine option;
   the upstream API documents it only when another integrity mechanism is
   being used.
4. Treat point validity as structural, not proof of a correct trusted setup.
   An accepted byte stream does not by itself prove circuit identity,
   parameter-query consistency, ceremony provenance, or that toxic waste was
   destroyed.
5. Sample fresh, unbiased, cryptographically secure proof randomizers for
   every proof, reject invalid randomness sources, and avoid logging,
   serializing, or retaining secret witnesses and proving intermediates.
6. Require subgroup checks and canonical proof decoding, reject malformed or
   identity proof components where the Sapling wire contract requires it,
   and test tampered proof/public-input rejection. Python's variable-time
   arithmetic, memory behavior, and lack of reliable secret zeroization
   remain a production blocker under the current pure-Python restriction.

### Dependency-ordered implementation roadmap

Each item is a future independently testable milestone; none is implemented
in Phase 9.20.56.

| Order | Milestone and prerequisite | Independent acceptance evidence |
|---:|---|---|
| 1 | Close circuit identity for Spend and Output against the exact parameter-generating Bellman synthesis; do not use a parameter set with a circuit whose ordered matrices are not established. | Pinned source and reproducible full ordered A/B/C, variable allocation, public-input mapping, and independent witness comparisons; resolve Spend allocation and Output row differences without changing semantics. |
| 2 | Specify and implement a bounded, streaming Bellman parameter reader using the wire layout above; establish trusted artifact provenance and exact circuit-specific expected lengths first. | Small non-secret synthetic parameter streams, round-trip fixtures, independent offset/cardinality checks, and rejection tests for truncation, trailing bytes, bad counts, noncanonical/off-curve/non-subgroup/identity points, and resource limits. Do not bundle the Sapling CRS. |
| 3 | Harden the arithmetic substrate and add Fr radix-2 domains and FFT/IFFT. | Independent field and root-of-unity vectors; FFT/IFFT round trips, domain-size boundaries, and polynomial operation tests; no secret inputs in tests. |
| 4 | Convert the verified R1CS to a QAP and compute/evaluate the quotient polynomial. | Tiny independently hand-checked R1CS-to-QAP fixtures and adversarial unsatisfied-witness rejection; confirm exact input/auxiliary mapping and domain conventions. |
| 5 | Add validated VK/PK/query representations and G1/G2 multi-scalar multiplication. | Query cardinality and point checks, independent MSM vectors, allocation/resource limits, and parameter-hash binding to the selected circuit. |
| 6 | Implement research-only proof construction with a reviewed CSPRNG and no persistent secret material. | Independent known-answer Groth16 vectors, fresh-randomizer checks, proof encode/decode and tamper tests; keep disabled because pure-Python operations are variable-time. |
| 7 | Implement prepared-key verification and multi-pairing, then independent end-to-end positive/negative verification. | Independent Sapling Spend and Output proof vectors, wrong-key/input/proof rejection, malformed point rejection, and pairing-equation tests; no release readiness claim without external audit. |
| 8 | Reassess deployment and secret handling. | Independent cryptographic audit, threat model, timing analysis, and a defensible constant-time/secret-isolation strategy. Under the current pure-Python-only requirement, this gate is not met; do not enable spending. |

**Phase 9.20.56 conclusion:** BLS12-381 and local R1CS primitives are
research-level building blocks only. Parameter parsing, validation,
QAP/FFT, query evaluation, Groth16 proof construction, and Groth16
verification are absent. Parameter format is now source-documented, but
neither the local circuits nor the arithmetic implementation are ready for
Sapling Groth16 use. Proof generation, parameter use, and Sapling spending
remain unsupported and gated.

### Phase 9.20.56 sources

- [Pinned Sapling `circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs) —
  Spend/Output parameter wrappers and their `read` methods.
- [Bellman 0.15.0 Groth16 serialization and parameter reader](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/lib.rs) —
  `VerifyingKey`, `Parameters`, and `Proof` layouts and validation branches.
- [Bellman 0.15.0 parameter generation](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/generator.rs) —
  QAP query vector cardinalities and circuit setup.
- [Bellman 0.15.0 QAP evaluation domain](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/src/domain.rs) —
  radix-2 domain sizing and FFT/IFFT operations.
- [Bellman 0.15.0 prover](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/prover.rs) —
  witness query evaluation and proof construction.
- [Bellman 0.15.0 verifier](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/verifier.rs) —
  prepared verification key and pairing-product equation.
- [BLS12-381 0.9.0 serialization rules](https://docs.rs/crate/bls12_381/0.9.0/source/src/notes/serialization.rs) —
  Fp/Fp2 byte order, point sizes, and flag bits.
- [BLS12-381 0.9.0 checked G1 decoding](https://docs.rs/bls12_381/0.9.0/bls12_381/struct.G1Affine.html#method.from_uncompressed)
  and [G2 decoding](https://docs.rs/bls12_381/0.9.0/bls12_381/struct.G2Affine.html#method.from_uncompressed) —
  checked versus unchecked decode guarantees.

## Verification performed

- At the Phase 9.18 audit, no BLS12-381, pairing, Groth16, circuit, or proof
  fixture was present. A subsequent Phase 9.19 implementation added the
  BLS12-381 arithmetic and pairing module and pinned independent vectors.
- Confirmed that configured `sapling-spend.params` and
  `sapling-output.params` values are filename declarations only; no matching
  resource exists in the repository.
- CPython 3.10.11 full regression suite: **47 passed**.
- `py -3.10 -m compileall -q src tests`: passed.
- `py -3.10 setup.py bdist_wheel sdist`: passed. The sdist contains this
  report and `docs/USER_GUIDE.md`.
- Installed the wheel with `--no-deps` into a clean target; `import zycoin`
  and access to the packaged `coins/btcz.json` resource passed.
- Local Markdown file links and heading anchors in the root, `docs/`, and
  `reports/` passed validation.
- `git diff --check` reports trailing whitespace at
  `src/crypto.py:104`; that unrelated pre-existing line was not changed.

## References and provenance

- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf) —
  Sapling circuits, cryptographic groups, proof statements, and transaction
  descriptions.
- [Pinned `sapling-crypto` circuit source](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs) —
  Spend/Output circuit witnesses, constraints, and parameter readers.
- [Pinned `sapling-crypto` prover source](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/prover.rs) —
  circuit preparation, randomized Groth16 proof generation, and proof
  serialization.
- [Zcash Sapling MPC tooling](https://github.com/zcash/sapling-mpc/tree/7934d34502745f3a8c03a7f98355a990d42930b7) —
  multiparty computation and separate Sapling Spend/Output parameter
  extraction sources; this repository is tooling, not a full ceremony
  transcript.
- [Independent Z23 SHA-512 parameter pins](https://github.com/z23c/z23/blob/7df112acb8584c0a0df4858838b868e0f20e0396/core/modules/sapling/src/params_init.c) —
  cross-check for the hashes streamed from the official Zcash endpoints.
- [Pinned `sapling-crypto` constants](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/constants.rs) —
  Sapling generators and 192-byte Groth16 proof encoding.
- [Pinned `sapling-crypto` dependency/features](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/Cargo.toml) —
  `bls12_381`, `bellman`, and `groth16` circuit dependencies.
- [Pinned Bellman 0.15.0 source](https://github.com/zkcrypto/bellman/tree/b726862a4ece8a627e7fea486d77b502a6edbb0b) —
  parameter, QAP, prover, and verifier implementation at the 0.15.0 release
  commit.
- [Pinned Bellman Groth16 parameter reader](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/lib.rs) —
  uncompressed parameter point reads, infinity checks, and section order.
- [BLS12-381 0.9.0 serialization](https://docs.rs/crate/bls12_381/0.9.0/source/src/notes/serialization.rs) —
  field and compressed/uncompressed point encoding rules.
- [ZIP-212](https://zips.z.cash/zip-0212) — note plaintext version rules
  relevant to valid output creation.
- [ZIP-243](https://zips.z.cash/zip-0243) — Sapling transaction signature
  digest rules; not a Groth16 proof specification.

The local [Sapling spending status guide](../docs/USER_GUIDE.md#sapling-spending-status)
and [historical compatibility record](coin-registry-compatibility-audit.md)
retain the ZIP32 gate, witness status, and other remaining spending blockers.

### Phase 9.20.56 verification

- CPython 3.10.11 focused BLS12-381, R1CS, Sapling gadget, and Spend circuit
  tests: **57 passed**.
- Full CPython 3.10.11 suite: **138 passed**.
- `py -3.10 -m compileall -q src tests` and `git diff --check`: passed.
- Pylance diagnostics for `src/bls12_381.py`, `src/r1cs.py`, and
  `tests/test_bls12_381.py`: no diagnostics. Signature compatibility checks
  found all call sites compatible for `pairing` (6), `decode_g1` (5), and
  `R1CS.serialize_matrix` (49); no Python signatures changed.
- `ruff check src/bls12_381.py src/r1cs.py tests/test_bls12_381.py
  tests/test_r1cs.py`: blocked by **147 lint findings** in the existing,
  unmodified Python files, primarily legacy typing and import conventions.
  No unrelated source cleanup was made.
- Python 3.10.11 wheel and sdist builds passed. A `--no-deps` clean-target
  wheel install imports `zycoin`, `zycoin.bls12_381`, and `zycoin.r1cs`;
  all eight packaged coin JSON resources are available. The final sdist
  contains this report and the report index; reports are not wheel package
  resources.
- No parameter file, proving key, witness, proof, or secret material was
  downloaded, stored, or used.

## Phase 9.20.57 — Bounded Bellman parameter-stream parser

`src/groth16_parameters.py` now reads the common Bellman 0.15.0 format from a
binary stream. It validates the six fixed verification-key points and the
count-prefixed IC, then yields the five query sections in H, L, A, B_G1, B_G2
order. It retains the verification key and validates query points as callers
consume each single-pass section; consuming all sections checks cross-section
dimensions and exact EOF before `validated` becomes true.

The parser bounds per-section counts (1,000,000 by default), total points
(2,000,000), and bytes read (256 MiB). It checks counts before reading or
allocating query point data; the IC is retained as a bounded tuple. It rejects
truncation, oversized sections, malformed or noncanonical points, points
outside the correct subgroup, query/IC infinity, bad H/A/B dimensions, and
trailing data. The IC count includes Bellman's implicit ONE. The six fixed VK
points may be infinity, matching the pinned Bellman reader; Bellman rejects
infinity in IC and query elements. This distinction is covered by synthetic
tests. These defaults are resource safeguards, not limits validated against
production Sapling parameter sizes; a caller would need to choose larger
bounds deliberately for larger inputs.

`src/bls12_381.py` now provides uncompressed 96-byte G1 and 192-byte G2
encoders/decoders. Decoding validates coordinate range, flags, curve
membership, canonical infinity representation, and subgroup membership by
default; the generic codecs support infinity round trips where the parser
format permits them. The parser is format-level only: successful parsing does
not authenticate a file, identify its circuit, establish its provenance, or
show compatibility with ZyCoin's circuit matrices. Subgroup checking can
also be prohibitively slow for production-sized streams in pure Python, and
the single-pass API cannot seek or replay sections.

Synthetic fixtures cover valid typed sections, chunked reads, zero-length
sections where structurally permitted, malformed encodings, subgroup errors,
truncation, count and byte limits, infinity policy, dimension mismatches, and
trailing bytes. No production parameter files or cryptographic secret
material were used. Parameter authentication, QAP/FFT, proving and
verification remain unsupported; Sapling spending remains gated.

### Phase 9.20.57 verification

- CPython 3.10.11 full regression suite: **156 passed**. The final focused
  parser suite, including the added IC and G2 malformed-point cases: **20
  passed**; the focused parser/BLS run also passed **27** before those last
  two parser cases were added.
- `py -3.10 -m compileall -q src tests`: passed.
- Pylance diagnostics for `src/bls12_381.py`,
  `src/groth16_parameters.py`, and
  `tests/test_groth16_parameter_parser.py`: no diagnostics. Signature
  compatibility checks passed for all call sites of both encoders, both
  decoders, and `read_parameter_stream` (9, 6, 7, 7, and 17 call sites).
- Ruff passes for `src/groth16_parameters.py` and
  `tests/test_groth16_parameter_parser.py`. Running Ruff on the complete
  `src/bls12_381.py` reports 100 findings in existing code; none are in the
  newly added uncompressed codec functions. No unrelated lint cleanup was
  made.
- Wheel and sdist builds passed. A `--no-deps` clean-target wheel install
  successfully imported the installed point codec and parser, parsed and
  exhausted a synthetic stream, and accessed the packaged
  `coins/btcz.json` resource. The sdist contains the parser and this report
  plus the report index.
- `git diff --check`: passed. No production parameter files, proving keys,
  witnesses, proofs, or secret material were downloaded, stored, or used.

## Phase 9.20.58 — Parameter validation and raw-stream manifest

The Phase 9.20.57 parser was audited against the pinned Bellman 0.15.0
`VerifyingKey::read` and `Parameters::read` implementations. The stream order
remains the six fixed VK points, the IC count and G1 points, then H, L, A,
B_G1, and B_G2 count-prefixed query sections. Decoding always uses checked
uncompressed point validation, including curve and subgroup checks. The six
fixed VK elements are allowed to be infinity because Bellman does not reject
identity there; IC and all query elements reject infinity, matching the
upstream reader. The IC must contain at least the implicit ONE element.

`validate_parameter_stream()` is the whole-stream validation entry point. It
consumes and discards query points as they are checked, does not retain full
query sections, requires all sections and exact EOF, and returns only a
`ParameterManifest` after successful completion. It verifies the IC, H, L,
A, B_G1, and B_G2 counts and their relationships: nonzero IC; H count of
`2^k - 1`; A count equal to IC plus L; and each B query count equal to A.
These are structural relations of the Groth16 queries; Bellman's low-level
reader itself reads count prefixes and points but does not check all these
cross-section dimensions. The parser cannot infer a circuit's constraint
domain, public inputs, or identity from the file, so these checks do not
establish that a parameter set matches a particular circuit.

The manifest includes the parser's format label `bellman-0.15.0` (the stream
does not contain a version field), ordered section counts, and a SHA-256
digest. The digest is updated from bytes actually read
from the original stream, including count prefixes and point encodings; no
point reserialization participates. `canonical_json()` serializes the
manifest deterministically. The optional `expected_sha256` argument requires
a 64-hex-character value and compares it after successful full validation.
Only pass a hash obtained independently through a trusted channel: an
attacker-controlled hash proves no provenance. To rely on a signature, a
caller must verify the signed trusted hash/manifest with its separately
managed trusted key before supplying that expected hash. Signature
verification and trust-store management are not implemented here. No
trusted parameter hash is embedded or claimed, and a valid manifest does not
identify the circuit or establish circuit compatibility.

Adversarial synthetic coverage checks digest mismatch and canonical manifest
output, hashes of exact encoded bytes, subgroup-invalid points across VK, IC,
G1 and G2 queries, forbidden infinity, inconsistent counts, truncated and
trailing data, and manifest access before full validation. Validation
continues to use bounded reads and the existing parser limits; it does not
retain query points. No real parameter files, trusted hashes, signatures, or
secret material were used.

### Phase 9.20.58 verification

- CPython 3.10.11 focused parameter-parser and BLS12-381 tests: **38 passed**.
  The CPython 3.10.11 full regression suite: **167 passed**.
- `py -3.10 -m compileall -q src tests`: passed.
- Ruff passes for `src/groth16_parameters.py` and
  `tests/test_groth16_parameter_parser.py`. The unchanged
  `src/bls12_381.py` reports 100 Ruff findings; it was not modified in this
  phase, and these pre-existing findings are reported separately.
- Pylance diagnostics for the parser and parser tests: no diagnostics.
  Signature compatibility checks pass for `read_parameter_stream` (19 call
  sites) and `validate_parameter_stream` (10 call sites).
- Python 3.10.11 wheel and sdist builds passed. A `--no-deps` clean-target
  wheel install imported the validation API, validated a synthetic stream
  against its exact raw-byte SHA-256, and accessed `coins/btcz.json`. The
  sdist includes the parser and updated report/index.
- `git diff --check` and changed-file trailing-whitespace checks passed. No
  parameter files, trusted hashes, signatures, or secret material were
  downloaded, stored, or used.

## Phase 9.20.59 — Parameter metadata and circuit compatibility gate

`src/groth16_compatibility.py` records explicit local Spend and Output
metadata: application public-input order/count, local constraint count, total
columns, auxiliary columns, the separate implicit ONE column, and the local
canonical matrix fingerprint and serialization version. Spend is recorded as
7 application inputs, 98,777 local rows, 98,646 total columns (98,638
auxiliary), and fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
Output is recorded as 5 application inputs, 9,460 local rows, 9,206 total
columns (9,200 auxiliary), and fingerprint
`885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739`.
Both local fingerprints use `zycoin-r1cs-matrix-v1`; these are local matrix
fingerprints, not Bellman fingerprints. The upstream row-count references are
98,777 for Spend and 7,827 for Output. Spend's matching count does not prove
matrix equivalence. No authoritative matching upstream matrix fingerprint or
auxiliary-column count is available for either circuit. The explicit local
public orders and separate ONE handling do not imply that a parameter file
names or authenticates those slots.

The validated manifest now exposes only stream-recoverable data: IC length
(including ONE), application input count (`IC - 1`), L auxiliary-query
length, total variable count (`IC + L`), all five query lengths, and the
padded H-domain size (`H + 1`). H does **not** encode the exact constraint
count. The stream also contains no input names/order, matrix fingerprint, or
circuit ID. The Bellman format label is parser metadata, not a version field
in the stream.

`assess_parameter_compatibility()` reports each property as **Verified**,
**Mismatched**, or **Unverified**. It compares available input/auxiliary/
total-column dimensions, checks the implicit-ONE convention, and flags an
impossible row count if the candidate circuit has more rows than the H-domain
size. Otherwise exact rows remain Unverified. It separately compares local
counts/orders and fingerprints with upstream metadata when those references
exist, and records whether the caller attests that the expected digest came
from an independently trusted source. The library does not verify that
attestation or a circuit description signature.

The gate always leaves `parameter_circuit_binding` **Unverified**: the
parameter serialization has no circuit identity or matrix fingerprint, and
there is no independently trusted external record binding a parameter digest
to a complete authoritative circuit description. Consequently `compatible`
cannot become true from the available metadata, even if public-input, row,
auxiliary, and total-column counts match. A matching Spend row count is
necessary evidence only. A matching matrix fingerprint also requires the
same canonical serialization contract and a trusted upstream reference; no
such reference is bundled. Callers must not treat a digest match as
authenticity unless its expected digest was independently trusted, and a
trusted parameter hash alone still does not establish circuit compatibility.

Synthetic tests cover matching counts with differing fingerprints, wrong
public-input and auxiliary counts, missing metadata, untrusted manifests,
unvalidated manifests, exact recovered metadata, and the fact that input
order/constraint count/binding remain unverified where the wire format omits
them. No trusted digests, signatures, real parameter data, or secret
material were used. Neither circuit is eligible for parameters; Sapling
spending remains gated.

### Phase 9.20.59 verification

- CPython 3.10.11 focused Groth16 parser/metadata/compatibility, BLS12-381,
  R1CS, Spend, and Sapling gadget tests: **93 passed**. The final full suite:
  **174 passed**.
- `py -3.10 -m compileall -q src tests`: passed.
- Ruff passes for `src/groth16_parameters.py`,
  `src/groth16_compatibility.py`, `tests/test_groth16_parameter_parser.py`,
  and `tests/test_sapling_gadgets.py`.
- Pylance diagnostics for both Groth16 modules and the compatibility/parser
  and Output-shape tests: no diagnostics. Signature compatibility checks
  passed for `validate_parameter_stream` (14 call sites) and
  `assess_parameter_compatibility` (7 call sites).
- Python 3.10.11 wheel and sdist builds passed. A `--no-deps` clean-target
  wheel install imported the compatibility gate, validated a synthetic
  stream, confirmed the gate remained closed, and accessed
  `coins/btcz.json`. The sdist contains the new compatibility module and
  updated reports.
- `git diff --check` and changed-file trailing-whitespace checks passed.
  The unchanged `src/bls12_381.py` retains 100 pre-existing Ruff findings;
  no BLS source cleanup was made. No real parameters, trusted hashes,
  signatures, or secret material were downloaded, stored, or used.

## Phase 9.20.60 — Pure-Python finite-field FFT foundation

The pinned Bellman 0.15.0 [`EvaluationDomain`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/src/domain.rs)
uses the BLS12-381 scalar field in its Groth16 test configuration. The field
has two-adicity `S = 32` and multiplicative generator `7`. Bellman derives
the size-`2^k` root by squaring `ROOT_OF_UNITY` `S-k` times; this equals
`7^((r-1)/2^k) mod r`, where `r` is the scalar modulus. Its domain sizing
rejects when the exponent reaches `S`, so the largest accepted radix-2 size
is `2^31`. Bellman's serial FFT bit-reverses input positions internally and
then uses iterative butterflies; the resulting evaluations are in natural
root-power order. `ifft` uses the inverse root and multiplies by `n^-1`.
`coset_fft` first multiplies coefficient `i` by `7^i`; `icoset_fft` applies
the inverse FFT and then multiplies by `7^-i`.

`src/groth16_fft.py` implements this field convention with canonical Python
integer field elements. `FFTDomain.create()` validates power-of-two sizes,
the Bellman exponent limit, a primitive root of the requested order, the
inverse root/normalization, and the disjointness of the fixed multiplicative
generator coset. The default root is Bellman's root convention; callers may
explicitly supply a different primitive root for the same subgroup order.
`fft()`/`ifft()` and `coset_fft()`/`icoset_fft()` require exactly one
domain-sized sequence and return a new list; coefficients and evaluations
are canonical values in `[0, r)`. Evaluation order is natural `omega**j`,
not bit-reversed. Invalid sizes, roots, lengths, booleans, and noncanonical
field values are rejected. No implicit polynomial padding or representation
conversion is performed.

The maximum `2^31` is a mathematical/library bound, not a practical Python
allocation promise. Domain metadata can be constructed at that boundary
without allocating a coefficient vector, but transforms require the caller
to supply a vector of that size and are not practical in ordinary Python
memory. There is no lower hidden cap; callers must manage memory and runtime.
At this phase, the FFT is used by the witness-specific QAP implementation
below; it still does not perform proving-key evaluation or generate or verify
proofs.

Independent regressions compare small FFT outputs to direct Horner
evaluations at every domain point, check natural ordering using the polynomial
`X`, test roots/inverses/normalization, round-trip zero, constant, sparse and
dense vectors, and independently evaluate coset points. They cover the
maximum accepted domain metadata and rejection immediately above the
Bellman limit, as well as invalid roots, sizes, and field values.

### Phase 9.20.60 benchmark

Measured with CPython 3.10.11 using `time.perf_counter()` on this development
machine; times are single-run observations, not performance guarantees.
`tracemalloc` peak is incremental Python allocation during a forward FFT and
excludes the interpreter and caller-owned input list:

| Domain size | Forward FFT | Inverse FFT | Forward FFT traced peak |
|---:|---:|---:|---:|
| 256 | 0.001560 s | 0.003442 s | 17.9 KiB |
| 1,024 | 0.009473 s | 0.008675 s | 70.4 KiB |
| 4,096 | 0.042741 s | 0.042299 s | 277.1 KiB |
| 16,384 | 0.190285 s | 0.197586 s | 1,110.2 KiB |

The implementation is pure Python with `O(n log n)` field operations and
`O(n)` additional Python-list/integer storage. Large proving domains will
have substantial memory and runtime costs; no production-sized benchmark was
attempted.

### Phase 9.20.60 verification

- CPython 3.10.11 full suite: **185 passed**; focused FFT suite: **11 passed**.
- `compileall` passed for the new implementation and tests.
- Targeted Ruff passed for both changed Python files. Pylance diagnostics were
  empty for those files, and Pylance syntax checks found no syntax errors.
- Wheel and sdist builds passed. The wheel was installed into an isolated
  target; `zycoin.groth16_fft`, an FFT round trip, coin JSON resources, and
  wordlist resources all imported/resolved successfully.
- Benchmark values above are single-run development-machine observations.
  No QAP, proof generation, or verification was added; Sapling spending
  remains gated.

## Phase 9.20.61 — Pure-Python Groth16 QAP construction

The source basis is pinned Bellman 0.15.0 at
[`groth16/src/generator.rs`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/generator.rs),
[`groth16/src/prover.rs`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/prover.rs),
and [`src/domain.rs`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/src/domain.rs).
`KeypairAssembly` records each A/B/C linear-combination coefficient at its
constraint row, with input and auxiliary variable identities kept distinct.
The prover evaluates those linear combinations at the assignment in
synthesis order, appends `x * 0 = 0` for every input (including ONE), and
interpolates the resulting A/B/C evaluation vectors. `EvaluationDomain`
rounds that vector length up to a radix-2 domain and applies the FFT/coset
conventions documented in Phase 9.20.60.

`src/groth16_qap.py` adds:

- `QAPDomain`, which accounts for original constraints, Bellman's dummy
  input rows, and zero padding, then validates the resulting FFT domain.
- `QAPAssignment`, which takes public inputs and auxiliary assignments as
  separate ordered sequences and inserts implicit ONE at variable index 0.
- `QAP.evaluations()` and `QAP.polynomials()`, which stream the existing
  sparse R1CS rows in insertion order to build the assignment-specific A/B/C
  domain vectors and interpolate coefficient vectors. Coefficients and
  assignments must be canonical scalar-field integers.
- `QAP.quotient()`, which first checks every original R1CS equation. It then
  interpolates the three polynomials, evaluates them over Bellman's
  multiplicative-generator coset, computes
  `(A*B-C)/(g^n-1)` there (where `Z(X)=X^n-1` and `g=7`), and applies inverse
  coset FFT. It rejects an unsatisfied row, inconsistent shape/domain,
  coset intersection, or nonzero degree-`n-1` coefficient before returning
  the `n-1` coefficients expected for H.

Checking each original constraint, the dummy `x*0=0` input rows, and the zero
padding rows verifies that `A*B-C` vanishes on the entire domain, so it is
divisible by `Z(X)`.
The explicit highest-coefficient check prevents silently truncating an
unexpected quotient. Small regressions independently evaluate interpolated
polynomials with Horner's rule and compare the coset quotient against
coefficient-domain long division by `X^n-1`; invalid and unsatisfied
assignments are rejected. This is a witness-specific QAP path, not Bellman's
per-variable setup query generation. It does not build H/L/A/B proving-key
queries, evaluate a parameter source, construct proofs, or verify them.

For ZyCoin Spend, 98,777 synthesized rows plus eight inputs (ONE and seven
application inputs) yield 98,785 QAP rows. The next radix-2 domain is 131,072
with 32,287 zero-padding rows; H contains 131,071 coefficients. R1CS public
columns follow ONE and precede the auxiliary columns, matching the assignment
layout used here. The Spend integration regression uses only the existing
deterministic test fixture and local R1CS; it loads no proving parameters and
does not persist the assignment or quotient.

### Phase 9.20.61 benchmark

Measurements used CPython 3.10.11 on the development machine and are
single-run observations, not performance guarantees. The small case used two
constraints, four variables, and a domain of four. The Spend case used 98,777
constraints, 98,646 variables, and a domain of 131,072. `tracemalloc` was
started after Spend circuit synthesis; its peak excludes the already-built
circuit and interpreter baseline. Tracing substantially affects runtime:

| Case | QAP setup | Quotient | Traced peak during quotient | H coefficients |
|---|---:|---:|---:|---:|
| Small R1CS | 0.000618 s | 0.000467 s | 16.7 KiB | 3 |
| Sapling Spend fixture | 0.007475 s | 92.439487 s | 40.27 MiB | 131,071 |

The Spend-sized regression completed without tracing in 30.01 seconds,
including fixture creation and circuit synthesis. The implementation uses
`O(n log n)` field operations and `O(n)` auxiliary Python-list storage; the
quotient path avoids materializing three per-variable polynomial families,
but large domains remain computationally expensive in pure Python. No
proving parameters, CRS queries, or proof generation were involved.

### Phase 9.20.61 verification

- CPython 3.10.11 full suite: **197 passed**. Focused QAP/FFT/R1CS suite:
  **35 passed**. The Spend-sized QAP quotient regression passed using the
  seeded test fixture.
- `compileall` passed for the changed implementation and tests. Targeted Ruff
  passed for `groth16_qap.py` and both QAP/Spend test files. Ruff reported
  **45 pre-existing findings** in `r1cs.py` (typing-style modernization and
  one existing SIM102); these were left unchanged apart from the new
  no-copy constraint iterator.
- Pylance diagnostics were empty for the QAP module and tests; syntax checks
  passed. Signature compatibility confirmed the `iter_constraints()` caller
  and all seven `QAP.quotient()` call sites.
- Wheel and sdist builds passed. The wheel was installed into an isolated
  target; QAP/FFT imports, a quotient computation, coin configurations, and
  wordlist resources all resolved successfully.
- Benchmarks used only a deterministic local test fixture. No proving
  parameters, keys, external proving tools, proofs, or production secrets
  were used. No QAP readiness implies circuit/parameter compatibility;
  proving, verification, and Sapling spending remain unsupported/gated.

## Phase 9.20.62 — Pure-Python Groth16 proving-key query evaluation

The source basis is pinned Bellman 0.15.0
[`groth16/src/prover.rs`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/prover.rs)
and [`groth16/src/generator.rs`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/generator.rs).
`ProvingAssignment` stores input scalars with implicit ONE first and
auxiliary scalars in allocation order. Bellman evaluates:

- `A_query(w) = sum_i A_i * w_i` in G1 for all input and auxiliary variables.
- `B_query_G1(w) = sum_i B_i^G1 * w_i` in G1 and
  `B_query_G2(w) = sum_i B_i^G2 * w_i` in G2, over that same full order.
- `L_query(w) = sum_j L_j * aux_j` in G1, excluding implicit ONE and public
  inputs.
- `H_query(h) = sum_k H_k * h_k` in G1, where `h` is the QAP quotient's
  ascending-degree coefficient sequence of length `domain_size - 1`.

The full proof equations additionally add CRS alpha/beta terms, blinding
terms, and other contributions. This phase implements only the query
linear-combination terms; it does not produce a proof. Bellman's
`ParameterSource` splits input/auxiliary vectors and may use density
trackers. ZyCoin concatenates the mathematically equivalent query order for
the full A/B linear combinations and uses every supplied entry, without
density filtering.

`src/groth16_queries.py` adds immutable `G1Query`/`G2Query` vectors whose
entries are validated for curve membership and prime-order subgroup
membership. The identity is a valid group point and is accepted. A
`QueryScalarAssignment` can only be obtained with `from_qap`; it validates
the full R1CS witness once, binds the resulting ONE/public/auxiliary values
to that QAP, and preserves those boundaries. A-query and both B-query
evaluators require exactly `variable_count` points. L requires exactly the
auxiliary count and uses only its private suffix. H checks both query and
coefficient lengths against `domain_size - 1` before the MSM.

`msm_g1` and `msm_g2` validate vector lengths and canonical Fr scalars before
group operations, then use the existing `multiply_g1`/`multiply_g2` and
`add_g1`/`add_g2` primitives. Zero-scalar and identity-point terms are
skipped. The implementation is a straightforward variable-base MSM, not a
windowed or bucketed algorithm. Existing affine point arithmetic performs
field inversions and scalar-bit-dependent branches; runtime is high and
variable-time. Neither it nor the witness-dependent Python code is suitable
for production secret protection.

Synthetic tests verify hand-computed small linear combinations, zero
scalars, identity points, G1/G2 single and multiple terms, full variable
ordering, L's private-only boundary, H coefficient ordering, malformed
length rejection before scalar multiplication, and rejection of an
unsatisfied witness. The Spend-sized integration uses the deterministic
local test fixture and full-sized identity query vectors; it exercises all
query length/boundary paths without CRS points, parameter files, or proof
generation. A separate small non-identity benchmark is used to illustrate
variable-base MSM cost.

### Phase 9.20.62 benchmark

Measurements used CPython 3.10.11 on Windows and are single-run observations.
The benchmark built the seeded Spend test circuit and QAP once, created the
validated assignment, computed the real local QAP quotient, and then used
full-length synthetic identity-point queries. Per-call tracemalloc peaks are
incremental and do not include the already-built circuit/query vectors or
process RSS.

| Evaluation | Query terms | Time | Peak incremental traced memory |
|---|---:|---:|---:|
| A, G1 | 98,646 | 0.058659 s | 790,500 B |
| B, G1 | 98,646 | 0.059821 s | 790,084 B |
| B, G2 | 98,646 | 0.060011 s | 790,084 B |
| L, G1 | 98,638 | 0.060637 s | 790,592 B |
| H, G1 | 131,071 | 0.075425 s | 1,076 B |
| Small G1 MSM | 4 | 2.582046 s | 7,036 B |
| Small G2 MSM | 4 | 3.011723 s | 9,880 B |

The small MSM used four actual witness assignment scalars and synthetic
points G, 2G, 3G, and 4G; outputs were non-identity. The full Spend vectors
used identity points and therefore skip scalar multiplication; those timings
measure dimension validation, iteration, and memory behavior—not realistic
elliptic-curve throughput. Setup through circuit/QAP creation took
14.077787 s; assignment validation took 0.187388 s; QAP quotient computation
took 15.617018 s; synthetic query-vector construction took 0.060739 s.
Observed shape: 98,777 constraints, 7 public inputs, 98,638 auxiliaries,
98,646 total variables, 98,785 QAP rows, domain 131,072, and H length
131,071. Large non-identity variable-base MSMs remain impractical with the
current affine Python primitives; no full-size non-identity benchmark was
attempted.

### Phase 9.20.62 verification

- CPython 3.10.11 full suite: **210 passed**. Focused BLS12-381/QAP/query/
  R1CS suite: **46 passed**; the Spend-sized QAP/query integration regression
  passed using the deterministic local fixture.
- Targeted Ruff passed for the QAP/query modules and their updated tests;
  compileall and Pylance syntax checks passed. Pylance diagnostics were empty.
  Signature compatibility passed for the five query evaluators, QAP
  assignment conversion/validation, and query-assignment factory.
- Wheel and sdist builds passed. The installed wheel successfully imported
  the QAP/query APIs, evaluated a synthetic query, and resolved coin and
  wordlist resources. `git diff --check` passed.
- Ruff's **45 pre-existing findings** in `r1cs.py` (typing-style modernization
  and one SIM102) remain unchanged. No CRS files, parameters, or secrets were
  downloaded or retained. The synthetic identities and local fixtures do
  not establish parameter authenticity or circuit compatibility; proof
  construction, verification, production readiness, and Sapling spending
  remain unsupported/gated.

## Phase 9.20.63 — Deterministic Groth16 proof-equation assembly

The implementation was grounded in the pinned
[Bellman 0.15.0 prover source](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/prover.rs),
especially `create_random_proof` and `create_proof`. Bellman samples `r`
first and `s` second, then creates the proof from those two scalar-field
elements. ZyCoin does not add an RNG: `assemble_proof_elements` accepts
explicit canonical Fr integers and returns only the three group elements.

For the full witness assignment (implicit ONE, public inputs, then auxiliary
values), Bellman's proof equations are:

```
A = alpha_g1 + r * delta_g1 + A_query
B = beta_g2 + s * delta_g2 + B_query_g2
C = (r*s) * delta_g1 + s * alpha_g1 + r * beta_g1
    + s * A_query + r * B_query_g1 + H_query + L_query
```

`A_query` uses the full A query; both B query variants use the full witness,
with G2 selected for proof B and G1 multiplied by `r` into C. L is evaluated
against auxiliary scalars only, excluding ONE and public inputs. H is the
ascending-coefficient QAP quotient MSM. The field is BLS12-381 Fr. Before
QAP work, the API rejects noncanonical randomizers, malformed QAP shape,
wrong query group types, and incorrect A/B/L/H lengths. The assignment is
checked against the R1CS and its quotient is computed internally. As in
Bellman, identity `delta_g1` or `delta_g2` is rejected; identity points remain
valid in query vectors and other key elements.

The new immutable `Groth16ProvingQueries` combines validated fixed points and
query vectors. `ProofAssemblyResult` is deliberately not a serialized proof.
The tests cover independent generator-multiple equations, zero/nonzero
randomizers, identity query/key points, malformed groups and lengths,
noncanonical randomizers, and an unsatisfied witness. The Spend-sized
regression exercises all full-size query shapes with synthetic identity
query entries and no CRS file or parameter material. This is a structural and
formula regression only; identity MSMs do not characterize realistic
non-identity proving-key performance.

The uninstrumented full-size synthetic assembly took **15.372 s** on CPython
3.10.11 / Windows (98,777 constraints, 98,646 variables, domain 131,072).
With tracemalloc active, query-vector construction plus assembly peaked at
**45,627,803 bytes (43.51 MiB)** of traced Python allocations; it excludes
the circuit, QAP, witness, and process RSS. Tracemalloc raised measured
assembly time to 97.371 s, so that instrumented duration is not representative
of normal runtime. A previous four-term non-identity synthetic MSM took
2.58 s in G1 and 3.01 s in G2; full-size non-identity MSM was not attempted
and should be expected to be impractical with the current affine Python
primitives. No realistic proving throughput is claimed.

No pairing-based proof verifier, trusted parameter source, authenticated
Spend/Output parameter set, authoritative matrix compatibility, or proof
serialization/verification flow is implemented. Thus the group-equation
assembly is not end-to-end Groth16 proof generation, does not establish
parameter or circuit compatibility, and does not make Sapling spending
eligible. Python big-integer and affine group operations remain variable-time
and unsuitable for production secret handling.

### Phase 9.20.63 verification

- CPython 3.10.11 focused proof-assembly/query tests plus Spend-sized
  regression: **19 passed**.
- CPython 3.10.11 full test suite: **215 passed**.
- Changed-file Ruff, `compileall`, Pylance diagnostics, and signature
  compatibility for `assemble_proof_elements`: passed.
- Wheel and sdist builds passed. A `--no-deps` isolated wheel install imported
  the proof/query APIs and accessed the packaged `coins/btcz.json` resource.
- No proving parameters, keys, or production secrets were used; Sapling
  spending remains gated.

## Phase 9.20.64 — Pure-Python Groth16 proof verification

The verifier is based on the pinned
[Bellman 0.15.0 verifier](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/verifier.rs).
`prepare_verifying_key` stores `e(alpha_g1, beta_g2)`, negates `gamma_g2`
and `delta_g2`, and retains the ordered IC vector. `verify_proof` first
requires `len(public_inputs) + 1 == len(IC)`, then computes:

```
acc = IC[0] + sum(public_inputs[i] * IC[i + 1])
e(A, B) * e(acc, -gamma) * e(C, -delta) = e(alpha, beta)
```

The implicit ONE is the unscaled `IC[0]`; application public inputs are
consumed in their given sequence and pair positionally with `IC[1:]`. The
Sapling Spend wrapper requires seven values in the established order
`rk.u, rk.v, cv.u, cv.v, anchor, nullifier_chunk_0, nullifier_chunk_1`,
matching `SPEND_PUBLIC_INPUT_ORDER`. It checks cardinality and preserves
positions; it does not infer names or reorder caller data.

`Groth16VerificationKey` and `Groth16Proof` are immutable representations.
Construction validates G1/G2 types, curve equations, and prime-subgroup
membership for alpha/beta/gamma/delta, every IC point, and proof A/B/C.
Canonical scalar values and exact input count are validated before pairing.
An empty IC vector is rejected because it cannot include ONE. As in the
Bellman equation, identity points are not categorically rejected: identity
IC/key/proof points and an identity input accumulator have their ordinary
group meaning. Identity points pass subgroup checks and contribute pairing
value one. Wrong group types, malformed coordinates, off-curve points,
non-subgroup points, noncanonical inputs, and count mismatches raise explicit
exceptions; a well-formed proof whose equation fails returns `False`.

The implementation multiplies four Miller-loop results,
`e(A,B)`, `e(acc,-gamma)`, `e(C,-delta)`, and `e(beta,-alpha)`, then performs
one final exponentiation and compares with target-group identity. This is
the product-to-one rearrangement of Bellman's prepared-key comparison and
avoids doing a separate final exponentiation for each term. Verification
returns a boolean; it does not authenticate the key or assert that it
belongs to Spend or Output.

Synthetic tests derive a valid proof from small generator multiples using
the scalar equation `a*b = alpha*beta + acc*gamma + c*delta (mod r)`,
check the independently computed IC accumulator, and verify successful and
altered-input/A/B/C results. They also cover IC/input count errors, the
implicit ONE slot, Sapling's seven-slot order/count contract, identity
elements, malformed/off-curve and non-subgroup points, and the four-Miller /
one-final-exponent call count. These deterministic synthetic cases verify
the local equation implementation only; no real Sapling verification key,
proof, or public-parameter file was loaded.

### Phase 9.20.64 benchmark

On CPython 3.10.11 / Windows, one two-public-input synthetic verification
used four Miller loops and one final exponentiation. The uninstrumented run
took **2.608 s**. With `tracemalloc`, it took 6.991 s and peaked at
**300,394 bytes (0.286 MiB)** of traced Python allocations; timing is
perturbed by allocation tracing. This tiny key/proof benchmark is not a
real Sapling proof or key performance estimate. The existing affine pure
Python pairing arithmetic is slow and variable-time.

Neither a real Sapling verifying-key fixture nor authenticated parameters,
authoritative circuit binding, production readiness, or spending eligibility
is established. Sapling spending remains gated.

### Phase 9.20.64 verification

- CPython 3.10.11 focused verification tests: **8 passed**. The combined
  focused BLS/pairing, FFT, QAP, query, proof-assembly, verification, and
  R1CS suite: **70 passed**. Full suite: **223 passed**.
- Changed-file Ruff, compileall, Pylance diagnostics, syntax checks, and
  signature compatibility for the generic and Sapling verification
  functions: passed.
- Wheel and sdist builds passed. The isolated wheel imported the verifier,
  verified an identity-only synthetic proof, and accessed `coins/btcz.json`;
  the sdist includes the new module and this report.
- `git diff --check` passed. The unchanged `src/r1cs.py` Ruff baseline still
  has 45 findings (13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1
  SIM102); none were introduced or edited in this phase.
- No real proving/verification parameters or production secrets were used.
  Successful synthetic verification does not establish real Sapling proof
  verification, parameter authenticity, circuit compatibility, or spending
  eligibility. Sapling spending remains gated.

## Phase 9.20.65 — End-to-end synthetic integration and soundness audit

The new end-to-end regression uses an independently specified arithmetic
relation `x * y = z` with public `x = 3`, private `y = 4`, and private
`z = 12`. Its R1CS has one constraint, three explicit variables, and four
QAP columns including implicit ONE. Bellman-style dummy input rows for ONE
and `x` are followed by one padding row, giving a four-point domain. The
test checks the full witness `(1, 3, 4, 12)` from input validation through
QAP quotient, A/B/L/H query MSMs, explicit-randomizer proof assembly, and
Groth16 verification.

For this test only, query and key exponents are derived from deterministic
public scalars `tau=11`, `alpha=5`, `beta=7`, `gamma=13`, and `delta=17`.
The variable-specific A/B/C row evaluations are specified directly from the
single constraint and input dummy rows, then evaluated at tau with an
independent Lagrange formula. The toy key follows these algebraic recipes:

```
A_i query = A_i(tau) * G1
B_i queries = B_i(tau) * G1 / G2
IC_i = (beta*A_i(tau) + alpha*B_i(tau) + C_i(tau)) / gamma * G1
L_j = (beta*A_j(tau) + alpha*B_j(tau) + C_j(tau)) / delta * G1
H_k = tau**k * (tau**n - 1) / delta * G1
```

`IC` covers ONE and public inputs in order; `L` covers only private columns;
`H` has exactly `n-1` entries for the quotient coefficients. The deterministic
toxic scalars are known and deliberately insecure, and the fixture is not a
trusted setup or a secure proving key. No production setup or cryptographic
security claim is made.

The independent polynomial check does not use QAP interpolation or quotient
construction for its expected values. It evaluates the four row values using
Lagrange interpolation, directly recovers coefficients with the explicit
four-point DFT sum, multiplies the coefficient polynomials, and long-divides
by `X**4 - 1`. It verifies zero remainder, equality with the implementation's
quotient, and the identity `A(tau)B(tau)-C(tau)=H(tau)(tau**4-1)`.
Separately, scalar generator exponents are used to check the complete
randomized proof equation:

```
(alpha + r*delta + A(tau)) * (beta + s*delta + B(tau))
= alpha*beta + gamma*public_accumulator + delta*C_proof
```

The test then checks the original three-pairing Groth16 equality directly
with reduced pairings and separately checks the product-to-one rearrangement
used by the verifier. These checks complement, rather than substitute for,
the implementation's own verification result.

Soundness/boundary regressions reject an invalid R1CS witness and altered
auxiliary assignment, wrong A-query dimensions, invalid explicit randomizers,
and malformed public scalars. Altered public input, an incorrect (but
well-formed) verification key, and altered proof A return `False`.
The fixture exercises ONE insertion, public order, full A/B witness order,
auxiliary-only L indexing, H coefficient/domain dimensions, and `r/s`
placement in A/B/C. It is an equation-path regression, not evidence that the
local R1CS matches Bellman's complete circuit matrix.

### Phase 9.20.65 stage benchmark

One CPython 3.10.11 / Windows run used `tracemalloc`; per-stage peak deltas
below are incremental traced allocations (not process RSS). Setup includes
constructing and subgroup-validating small synthetic group points.

| Stage | Runtime | Incremental traced peak |
|---|---:|---:|
| Fixture and QAP setup | 0.0007 s | 18,664 B |
| Witness validation | <0.0001 s | 3,408 B |
| QAP quotient construction | 0.0005 s | 8,850 B |
| Synthetic query and VK generation | 11.2138 s | 50,266 B |
| Proof assembly (includes internal witness/QAP/query checks) | 1.1567 s | 13,908 B |
| Verification (four Miller loops, one final exponentiation) | 7.1558 s | 300,858 B |

This tiny setup's point validation and pairings dominate its timings. These
measurements cannot be extrapolated to Sapling-sized proving, key generation,
or verification; no realistic Sapling proving/verification benchmark was
performed. Existing pure-Python affine scalar multiplication and pairing
operations are variable-time and remain unsuitable for production secret
handling.

### Phase 9.20.65 verification

- CPython 3.10.11 focused end-to-end suite: **3 passed**; focused
  R1CS/FFT/QAP/query/proof-assembly/verification/BLS suite: **73 passed**.
  Full Python 3.10.11 suite: **226 passed**.
- The fixture uses only explicit public test scalars and local synthetic
  points. No real proving parameters, verification parameters, external
  provers, secrets, or production endpoints were used.
- Targeted Ruff, compileall, Pylance diagnostics/syntax, and signature
  compatibility for proof assembly and verification passed. Wheel and sdist
  builds passed; the sdist includes this regression and the updated report.
  A `--no-deps` isolated wheel install imported the QAP, proof-assembly, and
  verification APIs, verified a synthetic identity case, and accessed
  `coins/btcz.json`.
- The existing **45 Ruff findings** in unchanged `src/r1cs.py` (13 UP007,
  12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102) remain a separate
  pre-existing baseline and were not altered.
- Synthetic end-to-end success does not establish secure setup validity,
  parameter authenticity, circuit compatibility, real Sapling proof
  compatibility, or production readiness. Sapling spending remains gated.

## Phase 9.20.66 — Circuit compatibility and parameter readiness audit

This is a read-only audit of local Spend/Output synthesis, the complete
synthetic Groth16 path, the pinned Bellman 0.15.0 wire/source descriptions,
and existing parser/compatibility regressions. No circuit equations or
runtime behavior changed. The pinned evidence includes Bellman's
`groth16/src/lib.rs`, `groth16/src/generator.rs`,
`groth16/src/prover.rs`, and `groth16/src/verifier.rs`, plus the pinned
Sapling circuit tests and source documented in the
[circuit implementation report](sapling-circuit-implementation.md).

### Circuit and query dimensions

Local column counts include the implicit ONE column. The QAP domain uses
`constraint_count + application_public_inputs + 1` rows (the last `1` is
ONE's dummy input row), padded to the next power of two. Hence the H query
length is padded domain size minus one. For a correctly dimensioned
Bellman-format query layout:

```
IC length = public input count + 1                 # includes ONE
A length = B_G1 length = B_G2 length = total columns
L length = auxiliary columns
H length = padded QAP domain size - 1
```

| Property | Spend | Output | Status |
|---|---:|---:|---|
| Application public inputs/order | 7: `rk.u, rk.v, cv.u, cv.v, anchor, nullifier_chunk_0, nullifier_chunk_1` | 5: `cv.u, cv.v, epk.u, epk.v, cmu.u` | **Verified** as local ordering and against the pinned source/test ordering |
| Implicit ONE | Column 0; IC slot 0 | Column 0; IC slot 0 | **Verified** for local QAP and Bellman wire convention |
| Local rows / source reference | 98,777 / 98,777 | 7,827 / 7,827 | Spend: **Partially Verified** (count match only); Output: semantic relation **Verified**, exact ordered-matrix equality **Unverified** |
| Local columns | 98,646 = ONE + 7 public + 98,638 auxiliary | 7,827 = ONE + 5 public + 7,821 auxiliary | **Verified** by local R1CS assembly and deterministic tests |
| Local matrix fingerprint | `f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9` | `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a` | **Verified** as deterministic local `zycoin-r1cs-matrix-v1` fingerprints only |
| Matching authoritative upstream matrix fingerprint | Not available | Not available | **Unverified** |
| Auxiliary-column identity/order vs Bellman | Source-order evidence and selected boundary mappings exist; no complete typed upstream allocation/matrix export | Complete upstream typed export and semantic mapping for all 7,821 auxiliaries; allocation order differs | Spend: **Partially Verified** for selected facts; Output identities: **Verified**, exact allocation-order equality: **Unverified** |

The local proving-query dimension expectations are therefore:

| Local circuit | IC | A / B_G1 / B_G2 | L | QAP rows before padding | Padded domain | H |
|---|---:|---:|---:|---:|---:|---:|
| Spend | 8 | 98,646 each | 98,638 | 98,785 | 131,072 | 131,071 |
| Output | 6 | 7,827 each | 7,821 | 7,833 | 8,192 | 8,191 |

These are local expected lengths, derived from the verified local circuit
counts and the QAP/query formulas. No actual Spend or Output parameter
stream was loaded, so no parameter's observed lengths were compared with
these rows. Bellman's parser-level relationships are checked independently:
IC includes ONE; A equals IC plus L; B_G1 and B_G2 equal A; H is one less
than a power of two. Those structural checks do not prove that a stream
belongs to either local circuit.

### Evidence and readiness status

| Property | Status | Evidence / remaining limitation |
|---|---|---|
| Local Spend/Output public ordering and ONE insertion | **Verified** | Local assemblers and QAP use ONE, then public inputs in declared order, then auxiliary assignments; pinned source/test ordering is documented above. |
| Local row/column counts and local fingerprints | **Verified** | Deterministic local circuit tests and explicit metadata; fingerprints are versioned local encodings, not upstream hashes. |
| Spend whole-circuit equivalence | **Unverified** | Matching row count, public order, and component transcriptions do not provide authoritative ordered A/B/C rows or exact typed auxiliary mapping. Bellman's published test digest is a different test-system hash format and cannot be compared to the local SHA-256 matrix fingerprint. |
| Output whole-circuit relation equivalence | **Verified** | Complete semantic mapping covers all six typed inputs and 7,821 auxiliaries with matching assignments. All 7,827 constraints match as a relation multiset after factor/scalar transformations and expanded-polynomial comparison. The exact ordered A/B/C matrices differ, and exact Groth16 query translation remains **Unverified**. The Bellman TestConstraintSystem digest is not a matrix fingerprint. |
| Mapping local circuits to Bellman parameter query slots | **Unverified** | A/B/L/IC/H dimensions can be checked, but the parameter stream contains no circuit ID, input names/order, or matrix fingerprint. Spend's matching count is not a mapping proof. Output's complete export does not yet provide a complete local-to-upstream variable/query permutation. |
| Canonical uncompressed parameter point decoding | **Verified** | Fixed-width decoding, canonical coordinates/flags/infinity representation, curve checks, and prime-subgroup checks are exercised by synthetic tests. |
| Parser bounds, section order/count relationships, full-consumption and EOF | **Verified** | Bounded streaming reader, typed H/L/A/B_G1/B_G2 order, cross-section count validation, truncation/trailing-data rejection, and single-pass tests. Configured limits are resource ceilings, not proven production-parameter size limits. |
| Trusted digest comparison | **Partially Verified** | The parser hashes exact original bytes and optionally compares a caller-provided expected SHA-256. `trusted_digest_verified` reflects the caller's boolean assertion; the library cannot establish that the expected digest came from a trusted source. |
| Parameter authenticity / provenance | **Unverified** | No independently supplied trusted hash/signature, provenance record, or ceremony validation is available. A self-asserted trust flag is not authentication. |
| Synthetic R1CS-to-verification path | **Verified** for its deterministic fixture | Phase 9.20.65 checks an `x*y=z` witness through QAP, test-only query construction, proof assembly, and pairing verification, with independent polynomial and pairing equations. |
| Real Sapling Spend/Output proof verification | **Unsupported / Blocked** | No real circuit-compatible parameter files, authenticated verification keys, or verified real proof fixtures were used. |
| Sapling spending eligibility / production readiness | **Blocked** | Circuit compatibility, parameter authenticity, real proof behavior, and constant-time/production security are not established. Spending remains gated. |

### What would close the remaining gates

Circuit compatibility requires an independently produced, pinned-source
artifact for the exact upstream circuit: ordered A/B/C matrix rows, typed
`Input`/`Aux` variable identity and allocation sequence, public-input slot
names/order, implicit ONE handling, exact row and column counts, and a
canonical serialization/fingerprint contract. It must be checked against
the local circuit using independently reviewed mapping code and fixtures;
counts or the Bellman test-system digest alone cannot substitute.

Parameter authenticity separately requires a parameter digest or signature
published through an independently trusted channel, with its circuit/version
binding and ceremony provenance documented. The key must then pass the
bounded parser and its query-dimension checks against the established
authoritative circuit artifact. None of these artifacts is bundled or
claimed here. No new regression was needed: existing tests cover those
concrete local parser boundaries and synthetic query/compatibility
conditions; they cannot create missing upstream evidence.

### Phase 9.20.66 verification

- CPython 3.10.11 focused R1CS, Spend/Output, parameter parser,
  compatibility, QAP, query, proof assembly, and verification tests:
  **134 passed**.
- Full CPython 3.10.11 test suite: **226 passed**.
- `compileall` over `src` and `tests`: **passed**.
- Targeted Ruff checks on the Groth16 compatibility/parser/QAP/query/proof/
  verification modules and relevant tests: **passed**. The unchanged
  `src/r1cs.py` has 45 existing Ruff findings (13 UP007, 12 UP006, 9 UP045,
  8 UP037, 2 UP035, 1 SIM102); they are outside this documentation-only
  audit and were not modified.
- Workspace Pylance diagnostics report no findings in the reviewed Groth16
  source modules. Existing diagnostics elsewhere include unresolved `js`
  imports in the client modules, the `setuptools` source diagnostic in
  `setup.py`, and unused-symbol warnings. Signature-compatibility checks on
  the parser and compatibility assessment entry points found no call sites
  to validate.
- Source distribution and wheel builds: **passed**. Installing the wheel
  into an isolated target and importing the Groth16 modules and packaged
  coin JSON resources: **passed**.
- No production parameter, secret, credential, or transaction was used;
  circuits and Sapling spending remain unchanged and gated.

## Phase 9.20.67 — Output circuit compatibility investigation

The Output assembly was traced relation-by-relation against the pinned
[`sapling-crypto` Output circuit](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs),
its [Jubjub ECC gadget](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/ecc.rs),
its [Pedersen circuit gadget](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit/pedersen_hash.rs),
and Bellman 0.15.0's lookup/Boolean gadgets. The 7,827 upstream rows are
from the pinned `TestConstraintSystem` regression. No upstream matrix export
was available.

### Exact row accounting

| Output synthesis section | Pinned Bellman rows | ZyCoin before | ZyCoin after | Explanation |
|---|---:|---:|---:|---|
| Value commitment and `cv.u/v` | 1,265 | 1,265 | 1,265 | 64 value bits; 64-bit fixed-base multiply (22 windows, 21 additions); 252 `rcv` bits and 252-bit fixed-base multiply (84 windows, 83 additions); point addition and two public bindings. The local `rcv` decomposition intentionally has no canonical-range comparator, as in the pinned source. |
| `g_d`, representation, `esk`, and `epk.u/v` | 4,315 | 4,315 | 4,315 | 20 rows for point interpretation and non-small-order checks; 776 strict representation rows; 252 `esk` bits; 3,265 variable-base rows (252 two-row selections, 251 five-row doublings, 251 six-row additions); and two public bindings. |
| `pk_d` representation | 256 | 256 | 256 | 255 little-endian `v` bits and the `u` sign bit, Boolean-constrained, without an in-circuit curve check. |
| Note Pedersen hash internals | 982 | 1,738 | 1,738 | The remaining structural mismatch: local Edwards lookup/addition synthesis has 756 more rows than Bellman's Montgomery-segment implementation. |
| `rcm` bits and fixed-base multiplication | 1,002 | 1,878 | 1,002 | 252 Boolean `rcm` bits plus 84 lookup windows and 83 additions. Before the correction, ZyCoin added 876 canonical-range-check rows and 622 range-check auxiliary variables; pinned `field_into_boolean_vec_le` does not add that range restriction. |
| Note randomization and `cmu` binding | 7 | 7 | 7 | Six-row point addition and one public-coordinate binding. |
| Local scalar `value` and bit-reconstruction binding | 0 | 1 | 0 | ZyCoin had allocated one extra scalar and equality row. The pinned circuit reuses the 64 already-constrained value bits directly in note contents. |
| **Total** | **7,827** | **9,460** | **8,583** | After the two source-backed corrections, the entire remaining 756-row delta is the local Pedersen implementation. |

The corrected local auxiliary-variable inventory is exhaustive for the
deterministic Output fixture. Bellman's counterparts identify the source
allocation step; they are not claims of a column-by-column mapping:

| Local variable allocation | Local auxiliary variables | Pinned source allocation step |
|---|---:|---|
| 64 value bits | 64 | `u64_into_boolean_vec_le` in `expose_value_commitment`; reused as the first 64 note bits. |
| 252 `rcv` bits | 252 | `field_into_boolean_vec_le`, then value-commitment fixed-base multiplication. |
| Value-commitment lookup/addition intermediates | 947 | Value and `rcv` `fixed_base_multiplication`, then `EdwardsPoint::add` for `cv`. |
| `g_d` coordinates | 2 | `EdwardsPoint::witness` allocates `u`, then `v`. |
| `esk` bits | 252 | `field_into_boolean_vec_le` before the variable-base `g_d.mul`. |
| `g_d` curve/non-small-order and `epk` multiplication intermediates | 3,284 | `interpret`, three `double` calls plus nonzero-`u`, and per-bit conditional selections, doublings, and additions in `EdwardsPoint::mul`. |
| `pk_d` representation bits | 256 | 255 `v` bits plus the `u` sign bit; no curve-check allocation. |
| `rcm` bits | 252 | `field_into_boolean_vec_le` after the note hash. |
| `g_d` strict-representation intermediates | 774 | `g_d.repr` calls strict bit decomposition on `u` and `v`. |
| Local Pedersen hash intermediates | 1,738 | `pedersen_hash` lookup windows, within-segment additions/conversions, and segment accumulation; local Edwards representation differs from pinned Montgomery segments. |
| `rcm` fixed-base multiplication intermediates | 750 | 84 window lookups and 83 ordered point additions. |
| Randomized commitment addition intermediates | 6 | `EdwardsPoint::add` for `cm = hash + [rcm]R`. |
| **Total auxiliary variables** | **8,577** | Five public inputs and implicit ONE are not auxiliary variables. |

The three local synthesis stages are now measured as 1,265 value-commitment
rows, 3,539 ephemeral-key rows (including the 20 `g_d` point checks and two
public bindings), and 3,779 note-commitment rows. The latter comprises the
776-row `g_d` representation, 256 `pk_d` Boolean rows, 1,738 local Pedersen
rows, 252 `rcm` Boolean rows, 750 fixed-base multiplication rows, six
randomization rows, and one `cmu` binding.

For the remaining Pedersen delta, the pinned NoteCommitment message has 576
data bits plus six constant personalization bits, producing window groups
`[63, 63, 63, 5]`. Bellman's count is 982 internal rows. The corresponding
local count is 1,738: its lookup rows contribute 580 versus Bellman's 386;
within-segment additions contribute 1,140 Edwards rows versus 570
Montgomery rows; Bellman's four segment conversions use eight rows, while
three inter-segment additions use 18 rows in both implementations. The net
difference is `194 + 570 - 8 = 756`. This is a constraint-shape difference,
not evidence of a different hash result. The local Pedersen equations were
not changed in this phase.

### Relation, allocation, and ordering findings

- The five application public inputs remain `cv.u`, `cv.v`, `epk.u`,
  `epk.v`, `cmu`, after implicit ONE. Their local indices remain 1 through 5
  and their values match the pinned vector.
- The value commitment, `g_d` curve/non-small-order checks, `esk` scalar
  multiplication, point additions, `pk_d` bit representation, Pedersen
  preimage order, `rcm` multiplication, and output coordinate bindings
  express the pinned relations. The local affine Edwards addition rows use
  the same six-equation form as the source; the Pedersen implementation
  differs in representation and group-operation shape.
- The pinned circuit Booleanizes `rcm` as a 252-bit field decomposition and
  feeds those bits to fixed-base multiplication without requiring the bit
  integer to be below the scalar modulus. ZyCoin now follows that constraint
  behavior for Output. Host witness validation still accepts only canonical
  Jubjub field elements. A regression checks the circuit relation for the
  `r + 1` bit representation, which produces the same subgroup point as
  scalar 1, while the strict-range helper rejects it.
- The local Output assembly now passes the linear combination of its shared
  value bits into note synthesis instead of allocating a redundant private
  scalar and enforcing an extra reconstruction row. This is exactly the
  pinned reuse of the value bits; the value commitment still constrains all
  64 bits as Boolean.
- Allocation and row order are not Bellman-identical. ZyCoin allocates all
  five public variables first, allocates both value and `rcv` bit arrays
  before constraining the value commitment, and synthesizes the `g_d`
  representation after the `epk` relation. The pinned synthesis allocates
  and constrains value bits/multiplication before `rcv`, inputizes `cv`
  before `g_d`, constrains the `g_d` representation before `esk`/`epk`, and
  allocates `rcm` only after the note hash. Public ordering is preserved, but
  private auxiliary ordering and constraint ordering differ.
- The local `pk_d` circuit path constrains its 256 representation bits but
  does not add a curve equation. Its host witness validator requires a
  non-identity subgroup `Point`; that is a host-side precondition, not an
  added R1CS relation. The pinned circuit likewise assumes its typed payment
  address and does not synthesize a `pk_d` curve check.

At the end of Phase 9.20.67, the Output assembly had
**8,583 rows / 8,577 auxiliary variables**,
including five application inputs and implicit ONE among its 8,583 total
columns. It remains **Mismatched / Blocked** against the 7,827-row pinned
test. The exact local row delta is accounted for, but an independent upstream
matrix export is still required to establish whole-circuit equivalence:
ordered A/B/C rows, public names/order, typed auxiliary identities, allocation
sequence, and a canonical serialization/fingerprint contract must be
compared. The pinned test hash and matching point outputs do not provide that
artifact. No parameter compatibility or Sapling spending eligibility is
claimed.

### Phase 9.20.67 verification

- Focused Output, Spend, gadget, R1CS, QAP, and Groth16 tests:
  **134 passed** on CPython 3.10.11.
- Full CPython 3.10.11 suite: **227 passed**.
- `compileall` over `src` and `tests`: **passed**.
- Targeted Ruff on the changed implementation and test file: **passed**.
  The unchanged `src/r1cs.py` Ruff baseline remains 45 findings (13 UP007,
  12 UP006, 9 UP045, 8 UP037, 2 UP035, 1 SIM102); no unrelated cleanup was
  performed.
- Pylance diagnostics for `src/sapling_gadgets.py` and
  `tests/test_sapling_gadgets.py`: **no diagnostics**. All five resolved
  call sites for `constrain_sapling_output` are signature-compatible; the
  internal fixed-base helper has no direct call sites to check.
- Source distribution and wheel builds plus isolated wheel import/resource
  checks: **passed**. The sdist contains this completed Phase 9.20.67
  report.
- No production parameters, secrets, credentials, or live transactions were
  used; the existing Output API remains the default and Sapling spending
  remains gated.

## Phase 9.20.68 — Output Pedersen constraint-shape reduction

The pinned `Output::synthesize` sends the 576-bit
`value || repr(g_d) || repr(pk_d)` note message to the same Sapling
NoteCommitment Pedersen gadget whose exact segment/window semantics were
audited for Spend. Its six constant personalization bits precede the message;
three-bit windows are signed using the third bit, with four lookup entries
for the low two bits. Bellman uses the `lookup3_xy_with_conditional_negation`
shape, Montgomery affine additions within each 63-window segment, two-row
Montgomery-to-Edwards conversion per segment, and Edwards addition across
segments. The Output hash has segments of 63, 63, 63, and 5 windows.

The existing `representation="montgomery"` implementation and the
test-only `synthesize_pedersen_hash` transcription were compared on the
actual pinned Output note-encryption fixture. Their isolated matrices are
byte-for-byte identical in canonical ordered A/B/C serialization:

| Output note Pedersen synthesis | Rows | Total columns | Aux columns | Local matrix fingerprint |
|---|---:|---:|---:|---|
| Existing Montgomery implementation | 1,558 | 1,559 | 1,558 | `b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76` |
| Independent Bellman-source Python transcription | 1,558 | 1,559 | 1,558 | `b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76` |

Of the 1,558 auxiliary columns, 576 are caller-allocated message bits and
982 are Pedersen-intermediate allocations. This reuses the established
source-derived Montgomery route only for the
Output note commitment. `constrain_sapling_output` now explicitly selects
that representation; `constrain_pedersen_hash` retains Edwards as its default,
and Spend/Merkle callers are unchanged.

The complete Output regression additionally constructs a comparison circuit
whose Pedersen call is replaced by the independent transcription. Its full
local matrix serialization is identical to the Montgomery-backed Output
matrix, with matching public values and note-commitment point. This verifies
that the Output integration wires that subcircuit at the same row/column
position; it is **not** an upstream-exported whole-circuit matrix.

| Complete local Output fixture | Rows | Total columns | Aux columns | Local matrix fingerprint |
|---|---:|---:|---:|---|
| Output-specific Montgomery path | 7,827 | 7,827 | 7,821 | `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a` |
| Same local assembly with transcribed Pedersen | 7,827 | 7,827 | 7,821 | Identical ordered local matrix |
| Pinned Bellman Output test | 7,827 | Not independently exported | Not independently exported | Published Bellman test-system hash is not this local fingerprint format |

Thus the 756-row mismatch is eliminated without removing constraints or
changing the default Edwards path: the local Output count now matches the
pinned test count. The subcircuit test compares full ordered matrices and
checks the output coordinates. The full Output regression checks its
fingerprint and column count, all five public inputs, and tampering of the
public inputs, note bits/representations, Pedersen lookup output, Montgomery
addition slope, Montgomery conversion coordinate, and ephemeral-key
intermediate. Each tampering case fails satisfaction for both the production
and reference-substituted local assemblies.

The existing Spend Pedersen regression still compares the NoteCommitment
matrix and all 32 depth-personalized Merkle matrices against the independent
transcription; the Output-only selection does not route any Merkle or Spend
call through a changed default.

**Status:** Output constraint count is now matched, and its standalone
NoteCommitment Pedersen matrix is matched to the source-derived transcription.
Whole Output Bellman equivalence remains **Unverified**. The production local
assembler allocates shared value/`rcv` bit arrays before constraining the
value commitment and allocates `g_d` representation after the `epk` relation;
the pinned circuit's private allocation and constraint order differs. The
comparison transcription is test-only Python, not an independent Bellman
matrix export. Establishing exact whole-circuit equivalence still requires an
authoritative export with ordered A/B/C rows, public inputs, auxiliary
identities/order, and serialization contract. No parameter compatibility or
Sapling spending eligibility is claimed.

### Phase 9.20.68 verification

- Focused Pedersen, Output, Spend, R1CS, QAP, query, proof assembly, and
  verification tests: **142 passed** on CPython 3.10.11. This includes all
  32 depth-personalized Spend Merkle Pedersen matrix regressions.
- `compileall` over `src` and `tests`: **passed**. Targeted Ruff on the
  modified source and test modules: **passed**.
- Pylance diagnostics for `src/sapling_gadgets.py` and
  `tests/test_sapling_gadgets.py`: **no diagnostics**. Signature checks found
  all 6 `constrain_sapling_output` and all 7 `constrain_pedersen_hash` call
  sites compatible.
- Wheel and sdist builds passed. Isolated wheel imports of the Sapling and
  Groth16 modules and access to packaged coin JSON resources passed. The
  sdist contains the completed Phase 9.20.68 reports.
- The unchanged `src/r1cs.py` Ruff baseline is 45 findings: 13 UP007,
  12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102. These are unrelated
  and remain unmodified.
- No production parameters, secrets, credentials, or live transactions were
  used; Sapling spending remains gated.

## Phase 9.20.69 — Full Spend/Output allocation and matrix audit

This audit measured fresh deterministic local assemblies and compared them to
the pinned `sapling-crypto` 0.9.0 / Bellman 0.15.0 synthesis source and its
published test assertions. The local allocation manifests and matrix
fingerprints are regression-pinned. Upstream's pinned tests provide circuit
counts and circuit-system hashes, but do not export the ordered A/B/C rows or
the complete typed `Aux(n)` identity map. Source allocation order is therefore
audited and transcribed below; it is not an independently synthesized
upstream matrix.

### Independently reconciled local dimensions

| Property | Spend | Output | Evidence and status |
|---|---:|---:|---|
| Pinned upstream constraints | 98,777 | 7,827 | Directly asserted by the pinned upstream circuit tests |
| Local constraints | 98,777 | 7,827 | Measured from the complete deterministic assemblies |
| Local total columns, including `ONE` | 98,646 | 7,827 | Recounted from local allocation manifests |
| Local application public inputs | 7 | 5 | Spend: `rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`, `nullifier_chunk_0`, `nullifier_chunk_1`; Output: `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu` |
| Local auxiliary columns | 98,638 | 7,821 | Independently summed from the exhaustive contiguous allocation ranges below |
| Local `ONE` column | index 0 | index 0 | Explicit local variable and matrix column |
| Upstream input namespace | `Input(0..7)` | `Input(0..5)` | Pinned `TestConstraintSystem` convention; `ONE` is `Input(0)` |
| Exact whole-circuit matrix equivalence | **Unverified** | **Unverified** | No authoritative ordered upstream A/B/C plus allocation export is available |

For Spend, the local relation-group row counts independently sum to
98,777: 1,030 + 23,560 + 4,048 + 4,031 + 44,226 + 21,882. For Output, the
local row groups sum to 7,827: 1,265 value-commitment rows, 3,539
`g_d`-check/ephemeral-key rows, 776 `g_d` representation rows, 256 `pk_d`
representation rows, 982 Pedersen rows, 1,002 `rcm`/fixed-base rows, and
seven commitment-randomization/binding rows. These reconciliations verify
local assembly accounting, not upstream row-by-row identity.

### Exhaustive local auxiliary allocation maps

Indices below are zero-based R1CS columns; ranges include both endpoints.
Spend's columns 0–7 are `ONE` and its seven public inputs. Output's columns
0–5 are `ONE` and its five public inputs. Each auxiliary row in these tables
is one contiguous local allocation range; together the ranges cover every
auxiliary column without gaps or overlap.

| Spend allocation stage | Local auxiliary columns | Count |
|---|---:|---:|
| `ak` coordinates | 8–9 | 2 |
| `ar` bits | 10–261 | 252 |
| Randomized authorization-key relation | 262–1,036 | 775 |
| `nsk` bits | 1,037–1,288 | 252 |
| `nk` fixed-base multiplication | 1,289–2,038 | 750 |
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

| Output allocation stage | Local auxiliary columns | Count |
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

These are complete *local* maps, backed by whole-manifest SHA-256 assertions
in the Spend and Output circuit tests. They do not assign local auxiliary
indices to upstream `Aux(n)` values. Component-level source transcriptions
remain limited to the already-tested Pedersen and BLAKE2s paths; no full
transcription exists for all Jubjub, value-commitment, allocation-sharing,
and row-order behavior.

### Public inputs, synthesis ordering, and known differences

The local public-input identity is unambiguous and verified. Spend maps local
columns 1–7 to the pinned input order
`rk.u`, `rk.v`, `cv.u`, `cv.v`, `anchor`, then the two packed nullifier
chunks; Output maps columns 1–5 to `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu`.
Both keep `ONE` at column 0. The source's input and auxiliary namespaces are
separate, so inputization interleaved with synthesis does not itself change
these `Input(n)` identities.

The private allocation sequences do differ:

- **Spend:** the local builder reserves all public columns first, materializes
  `pk_d` representation before the value commitment, allocates `rcm` bits
  before the note-commitment gadget, and allocates the position scalar and
  all 32 position bits before the level-by-level Merkle loop. Pinned Spend
  inputizes `rk` after randomized-key synthesis, `cv` after value-commitment
  synthesis, anchor after the Merkle root, and packed nullifier inputs last.
  Upstream allocates `pk_d` representation after the value commitment,
  `rcm` after note Pedersen, each direction bit within its Merkle level, and
  the anchor alias before inputization. The local position reconstruction
  row/scalar and upstream anchor alias row/auxiliary differ but cancel in
  total counts; equal totals do not identify their matrices.
- **Output:** the local builder reserves all five public columns and both
  `value`/`rcv` bit arrays before value-commitment intermediates. Pinned
  synthesis allocates value bits, completes the value-base multiplication,
  then allocates `rcv` bits before inputizing `cv`. Locally, `g_d` coordinates
  and `esk` bits precede the ephemeral-key relation; the pinned flow checks
  and represents `g_d` before `esk`. The local `g_d` representation is
  deferred until the note-commitment step, and local `rcm` bits precede
  Pedersen intermediates; pinned Output represents `g_d` before `esk` and
  allocates `rcm` only after Pedersen. Upstream inputizes `epk` after its
  multiplication and `cmu` last; the local builder reserves both public
  positions at entry.

The semantic input order, implicit-ONE convention, source equations, and
local deterministic allocation maps are verified to the levels described
above. The exact upstream auxiliary map, ordered complete matrix
coefficients, and whole-circuit parameter-query mapping remain
**Unverified**. Matching row/column counts do not resolve those differences.

### Output fingerprint history

| Output local snapshot | Rows | Columns | Auxiliary | Local matrix fingerprint | Change |
|---|---:|---:|---:|---|---|
| Before Phase 9.20.67 shape corrections | 9,460 | 9,206 | 9,200 | `885355201f02148a550d319a65274ec2ef8e1ecd4402dd10045bf37843c07739` | Initial local implementation |
| After Phase 9.20.67 corrections | 8,583 | 8,583 | 8,577 | `4beaf11952ebd89819813c34df45e3c9a4084c6323cc6be54fae66f051f7719d` | Removed 876 unsupported `rcm` range rows/622 auxiliaries and one redundant value-equality row/auxiliary |
| After Phase 9.20.68 Montgomery Pedersen path | 7,827 | 7,827 | 7,821 | `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a` | Replaced the Output-only Pedersen shape; 756 rows and auxiliaries removed |

The Spend snapshot did not change across Phases 9.20.67–69: 98,777 rows,
98,646 columns, and fingerprint
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
These are fingerprints in ZyCoin's local `zycoin-r1cs-matrix-v1`
serialization. They establish local determinism and change history only;
they are not comparable to the pinned upstream circuit-system hash format.

### Evidence status and remaining blocker

| Property | Status | Basis |
|---|---|---|
| Spend/Output public-input order and implicit `ONE` | **Verified** | Pinned source order, local indices, and regressions |
| Local Spend/Output row, column, and auxiliary totals | **Verified** | Independent counts and complete contiguous allocation partitions |
| Local Spend/Output matrix determinism and Output change history | **Verified** | Pinned local manifests/fingerprints and prior phase snapshots |
| Pinned upstream total row counts | **Verified** | Upstream test assertions |
| Spend component source equations and audited allocation order | **Partially Verified** | Source-derived traces; full ordered Bellman rows are not exported |
| Output Pedersen matrix | **Partially Verified** | Byte-identical to test-only pinned-source transcription, not upstream execution |
| Whole Spend/Output ordered A/B/C matrix and auxiliary mapping | **Unverified / Blocked** | No authoritative complete ordered matrix/allocation export |
| Exact local-to-upstream proving-query layout | **Unverified / Blocked** | Equal counts and source procedure alone do not prove row/column identity |
| Authenticated parameters or Sapling proving eligibility | **Unsupported / Blocked** | No authenticated parameters or whole-circuit binding; spending remains disabled |

Pinned source can establish the intended allocation *procedure*, but its test
hash and aggregate counts cannot be inverted into the ordered matrix or
semantic auxiliary mapping. Obtaining the missing evidence requires a
deterministic export from the pinned Bellman/Sapling synthesis (or a separately
audited complete implementation that emits the identical canonical export).
That export must include public inputs, typed auxiliary identities, every
ordered A/B/C row, and an agreed canonical serialization. This phase did not
add Rust, native code, external runtime dependencies, real parameters, or
secrets.

### Phase 9.20.69 verification

- CPython 3.10.11: full test suite **228 passed**; focused Spend/Output
  circuit tests **38 passed**.
- The regressions pin the complete local variable manifests, all contiguous
  auxiliary allocation ranges, public input/ONE slots, circuit matrices, and
  deterministic witness satisfaction.
- `compileall` and targeted Ruff for the modified circuit test modules passed.
  Pylance reported no diagnostics for either modified test file; signature
  checks found all 6 Output and all 7 Spend assembly call sites compatible.
- Wheel and sdist builds passed. A clean-target wheel install imported
  `zycoin.sapling_gadgets` and `zycoin.sapling_spend_circuit` and read all
  eight packaged coin JSON resources.
- The unchanged `src/r1cs.py` Ruff baseline remains **45 findings**:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

  ## Phase 9.21.27 — Authentic Output proving-query MSM validation

  The test-only
  [authentic-query MSM benchmark](../tests/benchmark_sapling_output_authentic_msm.py)
  used the official external Output parameter file with the production
  streaming parser. The file was 3,592,860 bytes and matched SHA-256
  `2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` and
  BLAKE2b-512
  `657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
  The 52,836-byte transcript suffix was consumed but not cryptographically
  verified; the external file remains outside the repository.

  Authentic sections contained H 8,191, L 7,821, A 6,298, B_G1 4,850,
  B_G2 4,850, and IC 6 points. Sparse A/B indices were restored to the
  7,827-variable layout with identity entries; B_G1/B_G2 mappings agreed.
  The deterministic witness assignment hash was
  `b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`;
  the QAP domain was 8,192, matrix fingerprint
  `cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`,
  and query-map fingerprint
  `b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.
  The harness checked H ascending quotient-coefficient order and L auxiliary
  order.

  Full optimized MSM results for all five sections matched exact point
  accumulations computed by partitioning each section and recombining the
  partial results. This checks optimized implementation consistency, not an
  independent full-vector oracle. First and last 12-term subsets per section
  exactly matched the test-only affine double-and-add reference. Timings were
  A/G1 1.236 s, B/G1 0.983 s, B/G2 7.361 s, H/G1 2.588 s, and L/G1 1.603 s,
  13.771 s total; the synthetic full-dimension total was about 14.0 s.
  Parsing and point/subgroup validation took 47.333 s; validated query-object
  construction took 47.031 s. End-to-end benchmark time, including witness
  reconstruction and checks, was 159.863 s. Peak process working set was
  57,360,384 bytes (about 54.7 MiB). Edge checks covered empty and identity-only
  inputs, scalars 0/1/modulus-minus-one, rejection of the scalar modulus, and
  term counts 31/32/33, 127/128/129, and 511/512/513.

  Focused BLS12-381 arithmetic, projective MSM, query, QAP/FFT, parameter
  parser, Output QAP-reference, Output-query, and compatibility-manifest
  regressions passed **125 tests and 132 subtests**. No authentic proof or
  parameter data was generated or retained. The result establishes
  authentic-query MSM behavior, not independent full-vector equivalence,
  proof-generation correctness, query-to-circuit binding, ceremony validity,
  Spend compatibility, or production readiness.
  Additional Bellman synthesis and exact Output correspondence regressions
  passed **51 tests and 36 subtests**.

## Phase 9.21.28 — Independent complete authentic Output MSM verification

The test-only
[Bellman accumulation runner](../tests/reference/sapling-output-qap/src/bin/authentic_output_msm_reference.rs)
and
[Python validation driver](../tests/validate_sapling_output_authentic_msm.py)
independently compute complete H, L, A, B_G1, B_G2, and IC accumulations
from the official hash-pinned Output parameters and deterministic satisfying
witness. Bellman 0.15 computes its own QAP quotient using its evaluation
domain, reconstructs the scalar vectors from the assignment and checked
sparse query-index mapping, and uses the ordered auxiliary assignment for L.
IC separately combines the constant ONE point with all five public inputs.
No Python scalar vector is exported to Bellman, and no Groth16 proof is
created. The generated reference point export is temporary and deleted after
the comparison.

The official file hash is SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4`; its
BLAKE2b-512 is
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
Witness assignment, matrix, and map fingerprints are respectively
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`,
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`,
and `b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.
Query section counts are H 8,191, L 7,821, A 6,298, B_G1 4,850,
B_G2 4,850, and IC 6. The 723-byte Bellman result export SHA-256 is
`af22fb8571fefc1c3929e1e8949b098442042c2ad26e2d797747a3cab5e5b72e`.

All six Python accumulations matched Bellman by exact canonical encoding;
none of the six results was the identity. Mutation checks rejected an
altered scalar, reordered query points, an incorrect sparse index, and a
changed public-input order. Zero-scalar, identity-only, empty-input, and
window-boundary tests also passed. Affine reference comparisons remain the
existing beginning/end 12-term subsets; full-section correctness is instead
established by the independent Bellman point equality.

Bellman accumulation timings were H 3.173 s, L 2.192 s, A 1.686 s, B_G1
1.311 s, B_G2 4.244 s, and IC 0.002 s; QAP quotient construction was
0.029 s. Runner wall time including startup and parameter loading was
27.118 s; peak RSS was 34,553,856 bytes. Python accumulation times were H
2.606 s, L 1.582 s, A 1.215 s, B_G1 0.967 s, B_G2 7.189 s, and IC 0.020 s,
13.559 s total. The complete Python run took 165.009 s with a reported
100,200,448-byte process peak working set.

The focused arithmetic, projective MSM, query, QAP/FFT, parser, Output QAP
reference, Output query compatibility, Bellman synthesis, and compatibility
manifest regressions passed **165 tests and 168 subtests**. The pre-existing
authentic proof-interoperability test was not run because it generates a
proof, which this task expressly prohibits. The matrix and query mapping
fingerprints are unchanged. No claim is made about proof-generation
correctness, parameter-to-circuit/ceremony binding, ceremony validity, Spend,
or production readiness.

## Phase 9.21.18 — Authentic parameter compatibility audit

The parameter parser previously required each serialized A/B query section to
contain one point per circuit variable. Pinned Bellman 0.15.0 instead filters
identity points from A and B independently; B_G1 and B_G2 have matching
sparse positions. The parser now accepts independently compact A/B counts
bounded by the variable total and still requires B_G1/B_G2 counts to agree.

Zcash's official Spend and Output files append a ceremony transcript after
the Bellman parameter serialization. The parser now offers explicit
`allow_trailing_data` mode, bounded by the existing total-byte limit, and
includes all trailer bytes in SHA-256/BLAKE2b-512 manifests. Strict EOF remains
the default, and the trailer is not independently parsed or cryptographically
validated apart from whole-file digest comparison.

The official source declares Spend (47,958,396 bytes;
BLAKE2b-512
`8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c`)
and Output (3,592,860 bytes;
BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`).
These values come from
[`librustzcash` parameter constants](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/lib.rs);
its [`HashReader`](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/hashreader.rs)
uses BLAKE2b. They are separate from the Phase 9.20.41 SHA-512 digests and
Z23 SHA-512 pins; different algorithms account for the different values.
Direct Python streaming of both official URLs matched the BLAKE2b values, the
exact file lengths, and the prior SHA-512 values. No file was retained.

Streaming the exact Bellman headers yielded:

| Circuit | IC | H | L | A | B_G1 / B_G2 | Transcript |
|---|---:|---:|---:|---:|---:|---:|
| Spend | 8 | 131,071 | 98,638 | 85,390 | 61,300 / 61,300 | 52,836 bytes |
| Output | 6 | 8,191 | 7,821 | 6,298 | 4,850 / 4,850 | 52,836 bytes |

These are source-format count scans with the query point bodies streamed and
skipped; all whole-file hashes and byte counts matched. Actual VK and IC
points were decoded and subgroup-checked by the Python parser (14 Spend
points, 12 Output points), but query points were not individually decoded.
Point/query values, circuit binding, VK compatibility, proving-key
compatibility, and production proof generation remain **Unverified**. No real
Sapling verification vector was available in the inspected repository; the existing
end-to-end Groth16 test is synthetic.

Focused validation: `tests/test_groth16_parameter_parser.py` passed **39
tests and 45 subtests**; the Sapling, Bellman, QAP, Groth16, and compatibility
regressions passed **271 tests and 569 subtests**. No authentic file was
retained, loaded into the prover, or used to generate or broadcast a
transaction.

## Phase 9.21.26 — Pure-Python Output proving performance

The test-only
[Output proving benchmark](../tests/benchmark_sapling_output_proving.py)
reconstructs the pinned 7,827-row/7,827-column Output circuit and satisfying
Zcash note-encryption witness, then measures validation, QAP, A/B/H/L
accumulations, and proof-element assembly at the official query dimensions
(A 6,298, B_G1/B_G2 4,850 each, H 8,191, L 7,821). The official sparse query
mapping is expanded with identity entries at absent columns. To avoid
retaining or using the authentic proving key, query points are synthetic
deterministic subgroup points. Thus these are reproducible algorithm timings,
not authentic proof results.

The affine baseline performed about 408 modular exponentiation inversions
for one 255-bit scalar multiplication. Projective scalar multiplication
reduces this to one final affine-conversion inversion; measured medians were
0.1442→0.00468 s for G1 and 0.1625→0.02611 s for G2 (30.8x and 6.2x). The
Pippenger-style projective bucket MSM and mixed additions matched an
independent affine implementation exactly on the 32-term test sample. At
full synthetic dimensions, the five query accumulations took 14.0 s in
total, dominated by B_G2 at 7.48 s; proof-element assembly took 14.76 s.
QAP quotient construction was 0.662 s, and witness synthesis 1.45 s.

Using exact assignment/quotient scalar bit lengths and popcounts, then
calibrating affine operation cost, estimates the previous affine full query
accumulation at 2,919 s (about 48.7 minutes). The optimized compute path
would be about 16.2 s including local witness synthesis once query points are
already loaded. This excludes parameter loading and authentic point
validation and must not be interpreted as measured authentic proving time.
The benchmark peaked at 53,092,352 bytes process working set; a small
32-term memory sample shows the expected modest window-bucket overhead.
Detailed methodology, fingerprints, exact timings, and remaining G2 Fp2
allocation bottleneck are in the
[implementation report](sapling-circuit-implementation.md#phase-92126--pure-python-output-proving-performance-benchmark).

The combined arithmetic, pairing, query, FFT/QAP, proof, parser, and Bellman
QAP-reference tests passed **119 tests**; the opt-in authentic Output
interoperability test was skipped because its external parameter file was
not available. No Python-generated authentic proof was attempted. Exact
Output query-value compatibility, ceremony validity, Spend compatibility,
and production proof readiness remain **Unverified**.

## Phase 9.21.25 — Authentic Sapling parameter ceremony transcript audit

The suffix format is the `ebfull/phase2` 0.2.2 format at pinned revision
`0c2b25fe8879deeb46530e91a5654d353a9bf94c`: 64-byte setup hash, 4-byte
big-endian contribution count, then 544 bytes per record (three uncompressed
G1 points, one uncompressed G2 point, and a 64-byte chained transcript
digest). Spend and Output each encode count 97 and 52,836 suffix bytes. Their
complete file hashes, prefix lengths, suffix hashes, and setup hashes are
tabulated in the [implementation report](sapling-circuit-implementation.md#phase-92125--authentic-sapling-parameter-ceremony-transcript-audit).

The upstream verifier reconstructs initial parameters from a matching
circuit and Phase-1 file, then verifies setup identity, the complete
contribution chain and proof relations, final delta, and H/L scaling. The
required `phase1radix2m17` (Spend) and `phase1radix2m13` (Output) files are
absent, and exact ceremony-era circuit implementations are not pinned in the
test runner. Consequently, no full verifier run or cryptographic
contribution validation was performed. The Zcash loader's whole-file digest
check is not ceremony verification.

Parser tests show that altered/truncated bytes fail against the trusted
whole-file digest, while a caller-supplied digest can authenticate an opaque
trailer without interpreting its contents. The parser and
compatibility-manifest suites passed **60 tests**. The opt-in Output
query/proof regression also passed (**1 test**, 75.51 seconds), preserving
32,016 exact point matches and the same Bellman proof accepted by the Python
verifier. Ceremony validity, Python proving readiness, and Spend
compatibility are **Unverified**; no production implementation or parameter
file was changed or retained.

## Phase 9.21.24 — Exact Output proving-query parser compatibility

The test-only Bellman 0.15 runner loads the official hash-pinned Output
parameters with Bellman's checked `Parameters::read`, then independently
exports canonical uncompressed encodings of IC, H, L, A, B_G1, and B_G2.
ZyCoin's production parameter parser decodes the original external file;
the test compares every encoded point and section index in streaming order.
The exact result is **32,016/32,016 matches**, with no point mismatch, missing
or extra entry, reordering, or serialized identity point. The framed Bellman
export hash is
`b56a9951fb00b54fee097a382fd78ebe19d98c6936461c14bd601d0414cf2bc1`
(3,539,187 bytes). Per-section canonical byte fingerprints and the complete
evidence are recorded in the
[implementation report](sapling-circuit-implementation.md#phase-92124--exact-sapling-output-query-decoding-compatibility)
and [compatibility manifest](sapling-circuit-compatibility-manifest.json).

IC ordering is ONE, `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`; H indexes are
quotient coefficient degrees 0–8190; and L indexes map to Aux(0–7820).
The sparse A/B mapping was regenerated from the pinned ordered matrix and
complete variable correspondence, matching fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.
Negative tests reject changed/reordered point bytes, missing/extra points,
misordered or truncated sections, and incorrect sparse indexes.

The Bellman invocation took 12.99 seconds with 33,840 KiB peak RSS. The Python
comparison took 47.64 seconds; the complete Python test process peaked at
219,467,776 bytes working set, including earlier proof verification. The
parameter file and generated query export were temporary and removed.

This establishes exact compatibility between the two implementations'
interpretation of the same serialized parameter vectors. It does **not**
establish that the authentic vector values were generated from the exact
pinned Output matrix or validate the appended ceremony transcript. Query-to-
circuit/ceremony binding, Spend compatibility, Python proving, and production
proof readiness remain **Unverified**.

### Phase 9.21.24 validation

- Opt-in official-parameter exact query comparison and proof interoperability:
  **1 passed**; 32,016/32,016 exact point matches.
- Negative query order/encoding/count/section/sparse-index tests: **6 passed**.
- Combined parser, query-map, Output correspondence/rows, QAP, and
  compatibility-manifest regressions: **105 tests passed**.
- Test-only Bellman runner `cargo check --offline`, Rust formatting, Python
  syntax, and task-scoped Ruff checks passed.

## Phase 9.21.23 — Authentic Output Groth16 interoperability

The test-only
[Bellman prover](../tests/reference/sapling-output-qap/src/bin/authentic_output_prover.rs)
reads the externally stored official Output parameters with Bellman 0.15's
checked parser and reconstructs the exact pinned Output matrix from the
upstream row artifact. It uses the QAP fixture's pinned Zcash note-encryption
witness, whose assignment SHA-256 is
`b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea`.
The 3,592,860-byte parameter file matched SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4`,
SHA-512
`a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152`,
and BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
The checked Bellman reader accepted the complete key/query stream; the
previous individual subgroup scan covers all 32,010 query points, with zero
rejections. Query sections and IC were H 8,191, L 7,821, A 6,298, B_G1
4,850, B_G2 4,850, and six IC entries including ONE. The public-input order
was `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`.

Bellman generated and verified a deterministic 192-byte proof with SHA-256
`8c8823da4046dc6e88640876018ec2bfeab2682d2f0a9dbfe5e085e18443c4c1`.
ZyCoin's pure-Python verifier accepted the canonical proof and rejected a
changed public input, a validly encoded changed proof, and malformed/truncated
encodings. The canonical uncompressed VK fingerprint is
`d7a655f6f58745f17bf5344682d25d15967e39b575d072335e14ace0a871bd0c`.
Verification took 1.99 seconds; the complete Python test process peaked at
130,772,992 bytes working set. The optimized Bellman runner, including
parameter parsing and its verification, took 3.84 seconds with 27,960 KiB
peak RSS. Parameter/proof files remain outside the repository.

The fixture uses deterministic XorShift randomizers for testing only; this
is not a production randomness strategy.

The Python-to-Bellman direction was not attempted. The current Python
assembler requires 25,222 nonzero G1 and 5,679 nonzero G2 scalar
multiplications for this witness. Measured full-width timings of 0.144
seconds per G1 and 0.165 seconds per G2 multiplication project to about 76
minutes before parameter validation, QAP work, and point wrappers; this is
an estimate, not a proof-generation measurement.

This proves one-way operational interoperability for the tested relation,
parameter file, and witness. It does not independently establish every
authentic query value, validate the ceremony transcript, constitute a formal
parameter-to-circuit proof, or establish production readiness. Full
proving-query compatibility and Python proving remain **Unverified**. Spend
is not evaluated by this milestone.

### Phase 9.21.23 validation

- Opt-in authentic interoperability test: **1 passed**.
- The final targeted regression totals are recorded in the corresponding
  implementation report and compatibility manifest.

## Phase 9.21.22 — Independent Sapling Output QAP reference

The test-only
[Bellman QAP runner](../tests/reference/sapling-output-qap) uses Bellman
0.15.0 at revision `b726862a4ece8a627e7fea486d77b502a6edbb0b` to calculate
the QAP from the pinned Output ordered-row artifact, independently of
`src/groth16_qap.py`. It follows Bellman's `EvaluationDomain` interpolation
and prover quotient path, then checks the polynomial quotient identity by
FFT convolution. The pinned matrix SHA-256 is
`c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761`; the
variable mapping fingerprint is
`c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc`.

The checked-in full-vector fixture
[`sapling_output_bellman_qap_reference.json`](../tests/fixtures/sapling_output_bellman_qap_reference.json)
is 14,821,991 bytes with SHA-256
`0d13e5d1e073139fdb6c2e609a77acb6a296ea7582cb0d92337a3f6ec71ed571`.
For each of three assignments—the pinned Zcash note-encryption vector, a
zero-value boundary, and `u64::MAX`—the independent reference and Python
implementation match every canonical A/B/C evaluation, interpolated
coefficient, and H coefficient exactly. The reference confirms 7,827 rows,
six dummy input rows including ONE, 359 padding rows, domain size 8,192,
8,191 H coefficients (degrees 0–8,190), satisfaction, and quotient
divisibility. The matrix is pinned upstream evidence; assignments come from
fresh local synthesis at the established identical variable columns.

The fixture also records a full Output witness with a tampered public input,
which Bellman marks unsatisfied and for which no quotient is generated.
Python tests reject that assignment before quotient construction. Rust
reference tests reject unsatisfied relations and malformed/noncanonical
field encodings; artifact regeneration is byte-for-

The focused QAP/manifest selection passed 22 Python tests; the combined
Sapling Output/Spend, Bellman, QAP, Groth16, and compatibility regressions
passed 301 Python tests. Both Rust reference unit tests passed.

This independently verifies Output's R1CS-to-QAP construction for the
established pinned matrix and tested witnesses. It does **not** establish
authentic parameter query-value compatibility, validate the ceremony
transcript, prove proving/verification-key compatibility, or establish
production proof readiness. Those statuses remain **Unverified**. No Spend
result is inferred.

## Phase 9.21.21 — Authentic Output query-to-circuit compatibility audit

This audit keeps the Output query layout separate from the values encoded
in the authentic query points. The official
[`sapling-output.params`](https://download.z.cash/downloads/sapling-output.params)
file is 3,592,860 bytes. The exact streamed bytes match both the published
BLAKE2b-512 digest
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`
and the SHA-512 digest
`a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152`.
The SHA-512 value is pinned in the
[Z23 `params_init.c`](https://github.com/z23c/z23/blob/7df112acb8584c0a0df4858838b868e0f20e0396/core/modules/sapling/src/params_init.c);
the official filename and published BLAKE2b-512 are recorded by
[`librustzcash`](https://github.com/zcash/librustzcash/blob/main/zcash_proofs/src/lib.rs).
This establishes the identity/designation of the public Sapling Output
parameter file. The Bellman serialization has no circuit ID, matrix hash, or
query-index labels, and its 52,836-byte trailing ceremony transcript was not
independently validated. Therefore this provenance does not cryptographically
bind the actual point values to the pinned matrix.

The pinned [Sapling circuit source at
`88a7946`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
was exported and compared against the local Output implementation. The
test-only variable correspondence covers all 7,827 columns (ONE, five public
inputs, and 7,821 auxiliaries) with no unmatched or ambiguous assignments.
The [ordered row artifact](../tests/fixtures/sapling_output_row_correspondence.json)
contains exact A/B/C term matches for all 7,827 rows at the same indices.
Its upstream export SHA-256 is
`ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe`; the
compared matrix fingerprint is
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`.
The query-map artifact's legacy `upstream_matrix_fingerprint` field is not
used as matrix evidence: its value `c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`
is the Bellman TestConstraintSystem BLAKE2s hash, not a matrix fingerprint.

The [deterministic Output query map](../tests/fixtures/sapling_output_parameter_query_index_mapping.json)
has file SHA-256 `c447b68e9ec795304a3cd067eb25c2891cfa25490aed16f50e4de1973b0b0199`
and mapping fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.
It is reconstructed from the pinned ordered matrix, complete variable map,
and authentic compact A/B counts using Bellman's preserved input-then-aux
variable order:

| Section | Authentic count | Established index meaning |
|---|---:|---|
| IC | 6 | Slot 0 is ONE; slots 1–5 are `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u` |
| A | 6,298 | Compact indices follow nonzero A support; first `Input(0)`/column 0, last `Aux(7818)`/column 7,824 |
| B_G1 / B_G2 | 4,850 each | Same compact B support and positions; first `Input(0)`/column 0, last `Aux(7820)`/column 7,826 |
| L | 7,821 | Dense `Aux(0..7820)` in columns 6–7,826 |
| H | 8,191 | Quotient-polynomial coefficient degrees 0–8,190; never constraint-row indices |

Bellman's pinned [parameter writer](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/lib.rs)
serializes these sections in H, L, A, B_G1, B_G2 order. The pinned
[generator](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/generator.rs)
adds one dummy `x*0=0` row for each input including ONE, computes H points
for powers `tau^i` in order, and omits identity A/B points while preserving
variable order. Thus the compact A/B indices can be assigned from the exact
structural support; the H positions refer to QAP coefficients, not rows.
All **32,010** Output proving-query points (H 8,191; L 7,821; A 6,298;
B_G1/B_G2 4,850 each) remain covered exactly once by the subgroup-validation
manifest, with zero rejections. The six IC points were separately
decoded/subgroup-checked by the parameter parser.

For QAP comparison, a pinned Zcash note-encryption witness fixture was used.
The upstream ordered A/B/C rows were rebuilt into a separate test-only R1CS
from the pinned row artifact, and both that system and fresh local Output
synthesis were passed through ZyCoin's Python QAP implementation. The two
assignments satisfy their systems; ordered matrix fingerprints, all A/B/C
domain evaluations, polynomial coefficient arrays, and quotient coefficients
match exactly. The QAP shape is 7,827 circuit rows + 6 dummy-input rows =
7,833 rows, padded by 359 to an 8,192-point domain; it has five application
public inputs and 7,821 auxiliary columns. The 8,191 H coefficients use
ascending degree order. The SHA-256 of the fixture quotient coefficients
(32-byte little-endian scalars) is
`07df9be6c741c02bb72c8ea03e1a8852f4211bfaeed6e734d0813fc4ca3319ca`.
The Bellman generator/prover sources were independently checked for the
same IFFT/coset-FFT/divide-by-vanishing/icoset-FFT and coefficient ordering
conventions. This is a QAP shape/construction comparison against an
independent pinned *matrix* fixture, not an independent Bellman-generated
QAP-polynomial fixture.

**Conclusion:** Output variable ordering, row matrix, query-index layout,
parameter-file identity, point validity, and local/reference QAP results are
verified to the scope above. Authentic query-value compatibility remains
**Unverified**: no independent authentic A/B/L/H/IC query-value fixture,
ceremony reproducibility data, or validated transcript binds those points
to this exact matrix and verification key. Matching counts, subgroup
membership, index maps, and QAP structure are not sufficient to make that
claim. No Spend conclusion is inferred and no production proof readiness is
claimed.

## Phase 9.21.20 — Authentic query subgroup validation

The bounded pure-Python parser was updated to use the exact BLS12-381
endomorphism criteria documented by
[`zkcrypto/bls12_381` G1](https://github.com/zkcrypto/bls12_381/blob/main/src/g1.rs)
and [G2](https://github.com/zkcrypto/bls12_381/blob/main/src/g2.rs), with
proof references
([ePrint 2021/1130](https://eprint.iacr.org/2021/1130) and
[ePrint 2022/352](https://eprint.iacr.org/2022/352)). G1 checks
`phi(P)=-[x²]P`; G2 checks `psi(P)=[x]P`, where
`x=-0xd201000000010000`. These are exact checks for every point, not
probabilistic aggregate tests. Projective arithmetic avoids the repeated
field inversions in affine scalar multiplication. The separate affine
`[SCALAR_MODULUS]P == O` path remains available as a test oracle.

The authentic files were streamed and validated without retaining them or
query points. Canonical encoding, curve membership, subgroup membership,
section counts, zero-identity policy, and whole-file digests were all checked.
Every decoded query point was consumed once by the parser:

| Circuit | H | L | A | B_G1 | B_G2 | Checked | Rejected | Elapsed | Peak working set |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Spend | 131,071 | 98,638 | 85,390 | 61,300 | 61,300 | 437,699 | 0 | 664.903 s | 30,683,136 B |
| Output | 8,191 | 7,821 | 6,298 | 4,850 | 4,850 | 32,010 | 0 | 49.120 s | 30,711,808 B |

Deterministic validation manifest:
[`sapling-query-subgroup-validation.json`](sapling-query-subgroup-validation.json),
SHA-256 `925c7f7b906f1fa8e9338b084d6ec2e852a9d21ab487755a75d977a3a9efa2ea`,
validation fingerprint
`191e50613f303091c5fc4cfc88f45f36f1fe316b6fe12cd4c531671b6b349aa5`.
It records per-section results and fingerprints, original query-mapping
artifact hashes/fingerprints, and the canonical whole-file hashes. Mapping
artifacts were not rewritten.

The focused BLS12-381, parser, and compatibility-manifest tests passed (**69
tests**). Across the targeted BLS12-381, parser, Groth16 (including FFT,
end-to-end, proof, QAP, query, and verification), Bellman, Spend, Output,
gadget, and compatibility regressions, **306 tests passed**. This validates
subgroup membership of the queried points only. Spend's remaining variable
identity, exact matrix alignment, query-value compatibility, authentic key
compatibility, and production proof readiness remain **Unverified**.

## Phase 9.21.19 — Authentic query point scan and sparse-index mapping

The official Spend (47,958,396 bytes) and Output (3,592,860 bytes) parameter
streams were fetched and processed sequentially without retaining either
file. SHA-512, BLAKE2b-512, and lengths again matched the canonical pins. The
auditor decoded all 469,709 A, B_G1, B_G2, H, and L query points using
canonical uncompressed G1/G2 decoding and curve-equation checks, with
subgroup checks disabled. No query identity points were observed. It also
verified all section counts and serialization boundaries and hashed each raw
section (count prefix plus point bytes); the trailing 52,836-byte transcript
was included in the whole-file digest. VK and IC subgroup checks from Phase
9.21.18 remain intact. Query subgroup membership is not established.

The complete query scan took 77.661 seconds for Spend and 6.826 seconds for
Output, including network transfer. Peak process working sets were 30,228,480
and 30,232,576 bytes. The timing is environment/network-dependent; decoded
points were not retained. The existing pure-Python subgroup-check benchmark
implies roughly 17.7 hours for 469,709 points at the measured G1 rate, before
allowing for G2 costs, so whole-query subgroup validation was not attempted.

| Circuit | H | L | A | B_G1 | B_G2 | Curve/canonical checked | Subgroup checked | Encoding/curve invalid or identity |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Spend | 131,071 | 98,638 | 85,390 | 61,300 | 61,300 | 437,699 | 0 | 0 |
| Output | 8,191 | 7,821 | 6,298 | 4,850 | 4,850 | 32,010 | 0 | 0 |

No malformed, off-curve, or identity query point was observed. Per-section
SHA-256 fingerprints (including the section count prefix) are recorded in
[`sapling-circuit-compatibility-manifest.json`](sapling-circuit-compatibility-manifest.json).

Sparse query indices are reconstructed from structural support and Bellman's
input-then-auxiliary order, not ordinal row assumptions:

| Circuit | A | B_G1 / B_G2 | Local columns mapped |
|---|---:|---:|---|
| Output | 6,298 | 4,850 / 4,850 | A 6,298; B 4,850 |
| Spend | 85,390 | 61,300 / 61,300 | A 85,389; B 61,300 |

For Output, support counts match the authentic compact sections and the
mapping uses the exact 7,827-row ordered matrix and complete semantic
variable correspondence. Its mapping fingerprint is
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`;
the fixture is
[`sapling_output_parameter_query_index_mapping.json`](../tests/fixtures/sapling_output_parameter_query_index_mapping.json)
(SHA-256 `c447b68e9ec795304a3cd067eb25c2891cfa25490aed16f50e4de1973b0b0199`).

For Spend, the pinned exported R1CS support exactly matches the official A/B
counts. The mapping retains all upstream identities but leaves the local
column null for `Aux(76805)` at A query index 63,616, because the v7
correspondence does not establish a local counterpart. B_G1 and B_G2 share
the same 61,300 indices and all have local-column mappings. L is dense and
maps 98,637 of 98,638 auxiliaries; IC maps all eight inputs including ONE.
All 98,645 accepted public/auxiliary identities passed an independent
assignment-consistency check after semantic matching.
H indices map to quotient coefficient degrees, not constraint rows. The
machine-readable artifact is
[`sapling_spend_parameter_query_index_mapping.json`](../tests/fixtures/sapling_spend_parameter_query_index_mapping.json)
(SHA-256 `dccf499fcdb7e6dfef6d850d4d60187b515dc32e5c3c8bfa2acb8c51e9a5cf23`;
mapping fingerprint `183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08`).
Its source Spend export SHA-256 is
`b9a1bab4df36059e3c324cd07c0baa96062501bc266cf46005ab0d7c35751046`, and
the unchanged v7 variable-mapping fingerprint is
`26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656`.

These are query-index-to-variable mappings, not mappings from individual
proving-query points to constraint rows. H is indexed by QAP quotient degree;
A/B/L/IC are variable-indexed. Matching dimensions, sparse support, or
successful point decoding does not establish that the authentic query values
are compatible with ZyCoin's prover. Phase 9.21.33 establishes exact
parser-to-Bellman point bytes and ordering for all Spend IC and query
sections, while the independent subgroup validation remains successful.
However, one auxiliary identity remains unmapped, the local and pinned
ordered matrices differ, and authentic query-to-circuit binding, Spend QAP
compatibility, key compatibility, and production proof generation remain
**Unverified**. Output's exact ordered matrix result does not upgrade those
claims.

### Pinned Spend export: query-compatibility status

The pinned Spend trace is now exported for fixture iteration 0 (8 inputs,
98,638 auxiliaries, 98,777 rows). Its canonical reference-matrix fingerprint
is `cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127`;
the current local Spend matrix fingerprint is
`f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9`.
Test-only allocation-provenance traces now capture Bellman's event order and
namespace hierarchy and local Python allocation call frames. The current
gadget-level mapping establishes 8 public/ONE variables and 28,150 auxiliary
identities (758 retained mappings and 27,392 Merkle-path allocations, 856 at
each of 32 levels). All assignments agree as a post-match check; there are
zero ambiguous IDs and 70,488 unresolved auxiliaries on each side. The
correspondence artifact SHA-256 is
`29d5115a32dea0c6a0d985d2897f8676a277c3b8179b900d0363b989464f3f48`; its
mapping fingerprint is
`b2728d464630bc579659cfd1415f405b8f0fcf0bd4c5d0699f3850de00f8f762`.
The trace details and their limitations are recorded in the
[Spend implementation report](sapling-circuit-implementation.md).
Consequently, the matrix difference is not yet a relation-equivalence
verdict, and no complete variable/row permutation or QAP input translation
has been demonstrated.

Spend proving-key compatibility, verification-key compatibility, and
production proof generation therefore remain **Unverified**. The matching
row count and pinned Bellman test hash are not evidence of query compatibility.
The pinned export, unresolved variable inventories, local ordinal diagnostics,
and evidence boundaries are recorded in the
[compatibility manifest](sapling-circuit-compatibility-manifest.json).

## Phase 9.21.10 — Output R1CS alignment and Groth16 readiness

The pinned Output reference and ZyCoin now match exactly as ordered R1CS
matrices for the deterministic fixture: 6 inputs including ONE, 7,821
auxiliaries, and 7,827 rows. Variable indices and assignments match
one-to-one; all ordered A/B/C terms and coefficients match natively, with no
row permutation, factor swap, normalization, or expanded-polynomial-only
case. The aligned local production fingerprint is
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`.

The previous local fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a` was
superseded by this allocation/factorization alignment; Output dimensions and
witness semantics remain unchanged. Production and fresh-recorder matrix
serializations, labels, variable maps, assignments, and satisfaction results
match.

The variable correspondence artifact SHA-256 is
`3c9ce93d3bbaed16488492ea58017846b997378fceed70d7e145a1328430d113`;
the row correspondence artifact SHA-256 is
`c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761`.
Variable-index mismatch count is zero. Row classifications are 7,827 native
matches, zero swaps, zero normalizations, zero expanded-only matches, and
zero unmatched or ambiguous rows.

This is R1CS evidence, not proof that real proving-key or verification-key
query points are compatible. Authentic Sapling parameter/query material and
an independent proof-verification fixture are still absent. Therefore real
proving-key compatibility, verification-key compatibility, and production
Output proof generation remain **Unverified**.

Validation: the Bellman synthesis, Output/Spend, QAP, Groth16, and
compatibility regression set passed **226 tests**. Both correspondence
artifacts regenerated twice with stable SHA-256 values.

## Phase 9.21.07 — Exact Output synthesis and QAP readiness

The full semantic relation comparison remains verified, but exact ordered
Bellman R1CS alignment is not established. The audit identifies reordered
`rcv`, `g_d`/`esk`, and `rcm`/Pedersen allocation stages, plus 260 row
relations whose match required polynomial expansion rather than factor swap
or nonzero scaling. A complete persisted local-to-upstream variable and row
index correspondence is still needed before the production synthesis order
or equations can be changed safely.

No Output circuit, QAP, or query code changed. Output remains 7,827 rows ×
7,827 columns with fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
Exact Bellman matrix equivalence, exact query translation, real proving-key
compatibility, real verification-key compatibility, and production Output
proof generation remain **Unverified**.

### Phase 9.21.07 validation

- Bellman synthesis tests: **39 passed**, including the corrected ownership
  and fresh-backend boundary expectations; pre-mutation assertions remain.
- QAP, Groth16, and compatibility-manifest tests: **102 passed**.
- Sapling gadget/Output and Spend regression tests: **73 passed**.
- Repository-wide `git diff --check` reports trailing whitespace only in
  unrelated, pre-existing `src/manager.py` edits.

## Phase 9.21.08 — Output variable mapping evidence

A deterministic, machine-readable correspondence fixture now records all
6 inputs (including ONE) and 7,821 auxiliary variables against fresh local
Output synthesis. Each pair includes both identities, semantic allocation
role, and witness assignment. The pinned source export hash is checked by the
Python-only generator; pairing is derived from unique translated source/local
role keys, not from assignment equality.

The fixture has 7,827 unique pairs, zero unmatched variables, zero ambiguous
semantic keys, and zero assignment mismatches. Its mapping fingerprint is
`9df59fefa7c21df06f07049b97776b17251a4f01566d0da0c3ca9756b5351812`; the
assignment-pairs fingerprint is
`57e33a5911cba3b585b550fa24f4dcbecb099da11bcf86bc0b4053709003cbc1`.
See the implementation report and compatibility manifest for the fixture
path and artifact digest.

This evidence maps variables and assignments only. It does not provide the
per-row correspondence or exact ordered A/B/C comparison needed to justify
Bellman matrix alignment. Exact matrix alignment, Groth16 query compatibility,
real proving-key/verification-key compatibility, and production Output proof
generation remain **Unverified**.

### Phase 9.21.08 validation

- Correspondence, QAP/Groth16, and compatibility tests: **105 passed**.
- Bellman synthesis tests: **39 passed**; Output and Spend tests: **73 passed**.
- Targeted Ruff and changed-file whitespace checks passed.

## Phase 9.21.09 — Output row correspondence and query implications

The deterministic row-correspondence artifact
[`tests/fixtures/sapling_output_row_correspondence.json`](../tests/fixtures/sapling_output_row_correspondence.json)
maps all 7,827 local rows one-to-one to the pinned Bellman export using the
verified variable mapping. It records exact A/B/C terms and coefficients,
row labels and indices, normalized factor mapping where applicable, and
expanded `A*B-C` terms for each of the 260 expanded-only rows.

The verified classification is 5,973 native A/B/C rows, 252 A/B swaps,
1,342 nonzero factor normalizations, and 260 expanded-polynomial-only
matches; there are no unmatched or ambiguous rows. The row-map fingerprint
is `c87e79dd0c55c61c46e5ff8cea9fbec1c84801db7298a5eb73aece26b0f070a9`,
the mapped-coefficient fingerprint is
`c42f36a3b4197daf9bf10340ffb9081066431baede06d75a0f0fe04c42cdd215`, and
the artifact SHA-256 is
`893441e69dae735dffb4e0a4b22c0a88bae8bf44857327d09668a424b2b9d971`.
The 7,827 × 7,827 production matrix and fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a` remain
unchanged. Fresh production and recorder ordered matrix serializations
match; the recorder reports its own serialization-specific fingerprint.

The row mapping does not establish exact ordered A/B/C synthesis: 5,529
rows are at non-identical indices, and 1,594 rows need a factor swap or
normalization while 260 need expanded-relation comparison. Therefore neither
this mapping nor relation equivalence establishes Bellman QAP/query
compatibility. Real proving-key compatibility, verification-key
compatibility, and production proof generation remain **Unverified**.

### Phase 9.21.09 validation

- Focused row-correspondence tests: **9 passed**.
- Combined Bellman synthesis, Sapling Output/Spend, QAP, Groth16, and
  compatibility regressions: **226 passed**.
- Full artifact regeneration was deterministic across two runs; SHA-256:
  `893441e69dae735dffb4e0a4b22c0a88bae8bf44857327d09668a424b2b9d971`.
- Targeted Ruff and changed-report whitespace checks passed.

## Phase 9.21.06 — Output Groth16 query compatibility

The complete semantic correspondence translates the witness vector exactly:
ONE and the five public inputs retain their indices, and all 7,821
auxiliaries map through the established permutation. Bellman's query layout
is also established: A and B_G1/B_G2 have 7,827 entries in input-then-aux
order; L has 7,821 auxiliary entries; IC has six input entries including
ONE; and H has 8,191 ascending-degree entries. The QAP uses 7,827 circuit
rows, six appended dummy-input rows, 359 zero-padding rows, and an 8,192
domain. The local and pinned implementations use natural root-of-unity
ordering and coset generator 7.

These are indexing and construction facts, not query-point compatibility.
Bellman's generator evaluates the per-variable A/B/C QAP polynomials at
secret `tau`, combines them with `alpha`, `beta`, `gamma`, and `delta` for
the L/IC queries, and derives H from the quotient. Output's row ordering and A/B/C factorization differ; the later complete
correspondence records all row pairs, with 260 matching only after expanded
`A*B-C` comparison. Thus the index permutation alone cannot determine local
query points from Bellman's query sections.

The pinned sources reviewed were
[Bellman prover](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/prover.rs),
[query generator](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/generator.rs),
[evaluation domain](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/src/domain.rs),
and [verifier](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/verifier.rs).
Local QAP/query behavior is implemented in `src/groth16_qap.py`,
`src/groth16_fft.py`, `src/groth16_queries.py`, `src/groth16_proof.py`,
`src/groth16_parameters.py`, and `src/groth16_verification.py`.

A bounded synthetic test uses disclosed toxic-waste scalars
`tau=11, alpha=5, beta=7, gamma=13, delta=17` and proof randomizers
`r=19, s=23`. Its two equivalent two-row R1CS fixtures differ by row
permutation and nonzero A/B swaps/scalings. Per-variable QAP evaluations,
quotient coefficients, A/B query points, and IC points differ; H query points
agree for the shared domain, tau, and delta. Each fixture's own proof verifies
under its own synthetic key, while cross-verification fails. Exact vectors
and query lengths/order are pinned in the test. The SHA-256 fingerprints of
the fixture ABC polynomial coefficients are
`4ac16be4127e30ea9f809af1e2ec1a0721a4d19817f6d5f9187de3f5a20f160c`
and
`fe6cc0832cada50c17ff87071cd04a102c9835fe7880d8fd4f6c224043f5a1fa`;
the quotient coefficient fingerprints are
`33e4df9d5b1a8070e4d813a65534d4b3cad05f47db35e6e45353a24c941f89a5`
and
`4bb457f9a9b998bcd62c861e968d34d1bd1c9c85a2ba8ba90866f6393cb29dc3`.
This is not a real Output parameter compatibility test.

Real proving-key compatibility, verification-key compatibility, and
production Output proof generation remain **Unverified**. No authenticated
Sapling Output parameter stream, trusted query-value export, or pinned real
proof/public-input fixture was used. The production Output matrix and
fingerprint remain unchanged; no production circuit code or allocation order
was modified. See [Phase 9.21.06](sapling-circuit-implementation.md#phase-92106--output-groth16-query-compatibility-analysis)
and the [machine-readable compatibility manifest](sapling-circuit-compatibility-manifest.json).

### Phase 9.21.06 verification

- QAP/FFT/query/proof/verification tests: **88 passed**; the updated
  row-permutation/factor-scaling synthetic regression also passed when
  rerun with exact polynomial and quotient fingerprints.
- Sapling Output/Spend regression suite: **87 passed**; compatibility
  manifest tests: **14 passed**.
- The standalone Bellman synthesis suite had two failures in untouched
  scalar-bit ownership/type-boundary assertions. They do not establish or
  alter real query compatibility.

## Phase 9.20.72 — Bellman recorder semantic conformance

The Phase 9.20.71 recorder audit was extended to variable allocation,
`alloc_input`, namespace paths, ordered linear combinations, constraint
insertion, and setup-mode dummy rows against pinned Bellman 0.15.0 source.
Scope creation does not register a named object; allocations and constraints
do, so repeated namespace scopes with distinct child paths are allowed. The
recorder now has a hand-calculated two-row fixture exercising direct and
namespaced APIs, interleaved input/aux allocation, A/B/C builders, dummy row
placement, query indices, and domain sizing. Malformed, foreign, forged, and
noncanonical references fail explicitly.

Matrix serialization/fingerprinting now canonicalizes each LC by combining
duplicate variables modulo the scalar field, dropping zero terms, and sorting
typed indices. Full recorder serialization still records the original term
order, zero terms, annotations, and assignments. Thus algebraically
equivalent LCs share matrix fingerprints without pretending the canonical
view is Bellman's internal append-order vector.

A second isolated comparison uses the test-only Bellman BLAKE2s transcription
on a one-byte Sapling nullifier-hash input. The recorder's mapped matrix
matches local R1CS (20,094 rows; 20,051 total columns) and the output digest
matches Python `hashlib`. As with the prior Pedersen comparison, this is
cross-implementation agreement—not upstream execution or an authoritative
matrix export. The recorder is not integrated into complete Spend or Output
synthesis; circuit compatibility, parameter compatibility, and spending
remain blocked.

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
- No circuit equations or production APIs changed. Sapling spending remains
  gated; no real proving parameters, secrets, credentials, or transactions
  were used.

## Phase 9.20.73 — Output recorder reconstruction boundary

The Output assembly and its value-commitment, ephemeral-key, and note-
commitment gadget sequence were inspected. The first hard boundary is the
entrypoint `constrain_sapling_output`: it requires a production `R1CS`
instance before witness validation or any variable/constraint allocation.
A regression confirms that passing the existing recorder adapter raises
there and leaves the recorder unchanged; **zero Output rows were emitted**.

The next boundary is not a single missing row translator: the actual gadget
path has concrete `Variable`/`LinearCombination` checks and relies on R1CS
`boolean`, `range_check`, `multiply`, `enforce_equal`, and witness-evaluation
semantics. A faithful implementation must adapt these operations and their
allocation order across the full gadget path. No attempt was made to bypass
these checks or synthesize the existing matrix by hand.

The existing production-R1CS snapshot (five public inputs, 7,827 rows,
7,821 auxiliaries, fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`) is
reference evidence only; no recorder public-input, allocation, ordered-row,
or fingerprint comparison was performed. This phase changes no production
Output behavior. Upstream Bellman aggregate assertions remain source-
verified, but complete upstream matrix equivalence, parameter compatibility,
and Sapling spending remain **Unverified / Blocked**.

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

## Phase 9.20.74 — Backend-neutral synthesis scope

Phase 9.20.74 introduces a small `SynthesisBackend` contract and migrates
`constrain_jubjub_point` for both the production R1CS and recorder backends.
The standalone fixture's production matrix remains six columns including ONE
and four rows with fingerprint
`2285a26c3911777b051fc133f62d8b2778a01fbe758c4d7bb63d0e5f153869a8`. The
recorder emits the corresponding real allocations and A/B/C constraints;
its local-column serialization equals the production matrix serialization.
This is evidence for one shared gadget only, not an upstream matrix export.

The full Output entrypoint still rejects non-R1CS systems before witness
validation/allocation. Value commitment, scalar multiplication, point
validation, value commitment, scalar multiplication, point representation,
Pedersen, and note commitment retain concrete variable/LC checks and
R1CS-only methods, including Boolean/range checks and witness-value access.
BLAKE2s is not in the Output synthesis call chain. Therefore complete Output
recorder reconstruction remains **Blocked**, whole-circuit equivalence
remains **Unverified**, and Sapling spending remains gated. Spend and
production proving behavior were not changed. See the Phase 9.20.74 coupling
audit and regression evidence in the
[circuit implementation report](sapling-circuit-implementation.md) and
[compatibility manifest](sapling-circuit-compatibility-manifest.json).

### Phase 9.20.74 verification

- Full-suite results are recorded in the circuit implementation report after
  completion of the Python 3.10.11 run: **249 passed**. Focused
  recorder/gadget/manifest tests: **53 passed**.
- Targeted Ruff and compileall passed. Pylance diagnostics were empty for
  changed Python modules and tests; all 17 call sites of
  `constrain_jubjub_point` passed signature-compatibility checking.
- Wheel and sdist builds passed; the sdist includes the new synthesis
  interface and final reports. Clean-target wheel imports and packaged
  BitcoinZ resource access passed.
- `git diff --check` and compatibility-manifest JSON parsing passed.
- The 45 pre-existing Ruff findings in `src/r1cs.py` remain:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.75 — Backend-neutral point allocation

`allocate_jubjub_point` now performs its actual coordinate allocation through
the shared `SynthesisBackend` contract, preserving the `u`-then-`v` witness
assignment order. A deterministic fixture confirms production private
columns 1 and 2 map to recorder `Aux(0)` and `Aux(1)` after implicit ONE,
with identical local-column matrix bytes and fingerprint
`880efe8a2dffdedc69b198304e12aa7b2519c661cd0d6541be92ce50cee4d124`.
Assigned and unassigned witnesses, nested namespace order, and malformed
point rejection are tested. This is only allocation-helper agreement; no
Output composition, constraints, or upstream matrix were reconstructed.

The concrete `R1CS` guard and freshness validation at
`constrain_sapling_output` remain unchanged. Other Output gadgets retain
concrete R1CS variable/LC ownership, range/Boolean, witness-read, and
allocation dependencies. Whole Output equivalence remains unverified and
Sapling spending remains gated.

### Phase 9.20.75 verification

- CPython 3.10.11 full test suite: **250 passed**; focused
  recorder/gadget/manifest tests: **54 passed**.
- Targeted Ruff, compileall, Pylance diagnostics and signature checks,
  `git diff --check`, wheel/sdist builds, and clean-target wheel import and
  resource checks passed.
- The existing 45-finding Ruff baseline in `src/r1cs.py` is unchanged:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.

## Phase 9.20.76 — Backend-neutral Jubjub point representation

`constrain_jubjub_repr` now uses backend-neutral strict field-bit synthesis
for both Jubjub coordinates. The shared helper preserves bit allocation,
Boolean/conditional-Boolean relations, prefix-AND witness allocation,
reconstruction equations, row order, and the return order of `v` bits plus
the parity bit of `u`. On a deterministic fixture, recorder and production
R1CS both emit 776 rows and 777 columns including ONE; their ordered
local-column matrix serializations and assigned witness values match. The
production fingerprint remains
`32695731f48144ff08bc2b0cce8394f7fe0f160e3cd22d71b84dbe1fdf28dda0`.
Tampered coordinates, representation bits, and a noncanonical modulus alias
are rejected by the production constraint evaluator. Unassigned values are
preserved on both backends.

The existing Spend/Merkle callers keep the same R1CS-facing API. The Output
entrypoint's concrete R1CS guard and unrelated value commitment, scalar
multiplication, unchecked `pk_d` representation allocation, Pedersen, and
note commitment paths remain unchanged. No upstream matrix or complete
Output equivalence is claimed; parameter and spending gates remain intact.

### Phase 9.20.76 verification

- Focused suite: **62 passed**. Targeted Ruff, compileall, JSON validation,
  whitespace checks, Pylance diagnostics/signature checks, wheel/sdist
  builds, and isolated wheel import/resource checks passed.
- Full CPython 3.10.11 test suite: **252 passed**.

## Phase 9.20.77 — Backend-neutral Jubjub conditional selection

The point-or-identity relation used for each variable-base scalar bit now
uses the shared `constrain_jubjub_select` operation on both production R1CS
and the recorder. Its selector Boolean constraint remains caller-owned and
stays in its prior row position. Both selector fixtures have 3 rows and 8
local columns including ONE, with equal matrix serializations and witnesses.
Production fingerprint:
`ffc4829f0e72c68da37758b7c077b8793a155658b36406ab577e61fd44b9d920`.
Tests cover selectors 0/1, invalid selectors, selected-coordinate tampering,
unselected-coordinate changes, and foreign ownership before mutation.
Curve-membership and strict representation checks remain separate and
continue to cover invalid points and noncanonical aliases. No scalar
multiplication or point-validation migration is claimed; the Output entry
guard and proving/spending gates remain unchanged.

### Phase 9.20.77 verification

- Focused suites: **64 passed**. Targeted Ruff, compileall, JSON validation,
  Pylance/signature checks, wheel/sdist builds, and isolated wheel
  import/resource checks passed.
- Full CPython 3.10.11 suite: **254 passed**.
- This local cross-backend comparison is not an authoritative Bellman matrix
  export or complete Output equivalence.

## Phase 9.20.78 — Backend-neutral affine Jubjub doubling

The scalar-multiplication base-doubling building block now runs through
`SynthesisBackend` on production R1CS and the recorder. For both the
spending-key base and identity fixtures, each backend emits five rows and
eight columns including ONE; the base fixture's local fingerprint is
`12ba0c9c8b468d3aab43719068b117d58ebc06777ee7647ae0724378e586c8d6`.
Ordered matrix serialization and assigned intermediates match, and the
result agrees with the independent host doubling operation. Regression tests
tamper both result coordinates and each intermediate, and reject foreign
variables before mutation. Scalar-bit allocation, selector integration,
accumulation, and full scalar-multiplication synthesis remain concrete R1CS.
The Output entrypoint and all proving/spending gates are unchanged.

### Phase 9.20.78 verification

- Focused suites: **67 passed**. Targeted Ruff, compileall, JSON validation,
  Pylance/signature checks, wheel/sdist builds, and isolated wheel
  import/resource checks passed.
- Full CPython 3.10.11 suite: **257 passed**.
- Local cross-backend agreement does not establish Bellman matrix or complete
  Output equivalence.

## Phase 9.20.85 — Audit and isolate Boolean handling in Output representation

Phase 9.20.85 is audit-only. The Output `pk_d` representation allocation
remains unchecked and unchanged. Production Output evidence shows exactly
64 Boolean rows for value bits and 252 for `rcv` during value commitment,
then 256 for `pk_d` and 252 for `rcm` during note commitment, each in
ascending bit order before its lookup/hash use.

The `pk_d` bits are allocated without constraints, then constrained exactly
once by `_constrain_note_commitment` before `rcm`. Its Montgomery Pedersen
call uses `message_bits_preconstrained=True` and therefore does not duplicate
the message Boolean rows; the six personalization ones are constants.
`rcm` Boolean rows are owned by note commitment and are skipped again in
fixed-base multiplication because Output disables scalar-range enforcement
and marks those bits preconstrained. Value bits are Boolean-constrained by
their value-base fixed multiplication; the note commitment reuse flag also
prevents duplicate rows. Fixed-base/Pedersen lookup equations are separate
from Boolean constraints.

The direct concrete Boolean APIs are `R1CS.boolean` calls in fixed-base
multiplication and note-commitment bit loops. `_constrain_jubjub_scalar_bit`
already expresses the Boolean equation with backend `enforce`, but it is not
used by the `pk_d` loop and still has an R1CS-specific ownership branch.
Recommended next slice: route only the 256 `pk_d` Boolean checks through
that helper and backend ownership API. Compare exact labels and ordered
matrices for production and recorder one-bit fixtures, test 0/1 and tampered
assignments plus foreign-variable rejection before mutation, and preserve
the full Output matrix fixture.

Full Output recorder synthesis remains **Blocked**; upstream Bellman matrix
equivalence remains **Unverified**. No fixed-base, value-commitment,
Pedersen, note-commitment orchestration, or guard migration was performed.

### Phase 9.20.85 verification

- CPython 3.10.11 full suite: **275 passed**; focused Output, recorder, and
  compatibility-manifest tests: **13 passed**. Ruff, `compileall`, and
  `git diff --check` passed. Pylance diagnostics were empty for the changed
  Python files; signature compatibility checks found all 5 Output entrypoint
  callers and all 8 unchecked-allocation callers compatible. Wheel and sdist
  builds passed. A clean-target wheel installation imported `zycoin` and
  loaded all 8 packaged coin JSON resources.

## Phase 9.20.86 — Backend-neutral `pk_d` Boolean enforcement

Only the existing 256 `pk_d` Boolean checks in `_constrain_note_commitment`
were routed through `_constrain_jubjub_scalar_bit`. Allocation, check order,
labels, namespace, equation, and placement before `rcm` constraints are
preserved. The helper's ownership check occurs before its shared
`SynthesisBackend.enforce` operation.

Production and recorder emitted the same 256 ordered rows for the nested
namespace fixture, with matching variable maps and assignments; local
fingerprint: `d7ea7fec9edd70b8333431e6cc81379702bc6b7ce37676eac784893493608168`.
The full Output regression retains its complete local 7,827-row matrix
fingerprint and verifies that preconstrained downstream Pedersen reuse does
not add duplicate Boolean rows. Production rejects an assigned non-Boolean
bit, and foreign-backend variables fail before mutation.

The Output guard and unchecked `pk_d` allocator remain unchanged. Full Output
recorder synthesis is **Blocked**; upstream Bellman matrix equivalence is
**Unverified**.

### Phase 9.20.86 verification

- CPython 3.10.11 full suite: **276 passed**; focused `pk_d`, Output, and
  compatibility-manifest tests: **13 passed**. Ruff, `compileall`, and
  `git diff --check` passed. Pylance diagnostics were empty for all changed
  Python files; `_constrain_note_commitment`'s 11 call sites passed signature
  compatibility checks. Wheel and sdist builds passed; the sdist contains
  the implementation, tests, and compatibility manifest. A clean-target
  wheel import loaded all 8 packaged coin JSON resources.

## Phase 9.20.87 — Audit of Output `rcm` Boolean enforcement

The 252 Output `rcm` witness bits are generated little-endian from note
commitment randomness and allocated after the 256 `pk_d` bits at production
columns 5063–5314. The Output regression asserts their exact ordered names,
contiguous variable identities, and assignments against the witness tuple.

`_constrain_note_commitment` owns the 252 Boolean rows through direct
`R1CS.boolean` calls; the Output call leaves
`randomness_bits_preconstrained=False`. Labels are
`Sapling Output note commitment rcm bit[index]`. The rows immediately follow
the `pk_d` Boolean rows and immediately precede note-commitment content-hash
constraints. Witness values are read and checked against `witness.rcm_bits`
before the constraints are added.

Pedersen does not consume `rcm`. The later fixed-base randomness
multiplication does reuse its variables but, since Output disables scalar
range enforcement, marks them preconstrained and adds no duplicate Boolean
rows. Therefore this path is still concrete-R1CS and is not already
backend-neutral. The next isolated migration should route only these 252
checks through `_constrain_jubjub_scalar_bit`, preserving their current
labels and placement.

No synthesis implementation, API, equation, or Output guard changed.
Full Output recorder synthesis remains **Blocked**; upstream Bellman matrix
equivalence remains **Unverified**.

### Phase 9.20.87 verification

- CPython 3.10.11 full suite: **276 passed**; focused Output and
  compatibility-manifest tests: **12 passed**. Ruff, `compileall`, manifest
  JSON validation, and `git diff --check` passed. Pylance diagnostics were
  empty for the changed Python files; `_constrain_note_commitment`'s 11 call
  sites passed signature compatibility checks. Wheel and sdist builds
  passed; the sdist includes the implementation, tests, and manifest. A
  clean-target wheel import loaded all 8 packaged coin JSON resources.

## Phase 9.20.88 — Backend-neutral `rcm` Boolean enforcement

The 252 `rcm` Boolean rows in `_constrain_note_commitment` now use
`_constrain_jubjub_scalar_bit`; no allocation or other note-commitment logic
changed. The existing preconstrained branch, LSB-first sequence, labels,
namespace handling, and row placement are unchanged. Production and recorder
emitted matching 252-row matrices for the nested-namespace fixture, with
matching variable mappings and witness values. Fingerprint:
`2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467`.

The full Output regression retains the 7,827-row matrix, exact `rcm` row
placement, and no-duplicate checks for downstream fixed-base multiplication.
Production rejects non-Boolean assignments; cross-backend variables fail
before mutation. The Output guard is unchanged.

Full Output recorder synthesis remains **Blocked**; upstream Bellman matrix
equivalence remains **Unverified**. The next isolated Boolean migration
candidate is fixed-base scalar-bit enforcement for Output value and `rcv`.

### Phase 9.20.88 verification

- CPython 3.10.11 full suite: **277 passed**; focused `rcm`, Output, and
  compatibility-manifest tests: **13 passed**. Ruff, `compileall`, manifest
  JSON validation, and `git diff --check` passed. Pylance diagnostics were
  empty for the changed Python files; `_constrain_note_commitment`'s 10 call
  sites passed signature compatibility checks. Wheel and sdist builds
  passed; the sdist includes the implementation, tests, and manifest. A
  clean-target wheel import loaded all 8 packaged coin JSON resources.

## Phase 9.20.89 — Audit of Output value and `rcv` Boolean enforcement

Output allocates 64 value bits at columns 6–69 and 252 `rcv` bits at
columns 70–321, both LSB-first and before value commitment synthesis. The
full Output regression asserts their names, mappings, and witness assignments.

The shared owner for both Boolean groups is
`_constrain_sapling_value_commitment` through
`_constrain_fixed_base_jubjub_mul`. The 64 value checks occur before value
lookup rows. The 252 `rcv` checks occur after value fixed-base synthesis and
before rcv lookup rows. Both loops call `R1CS.boolean` directly, not
`_constrain_jubjub_scalar_bit`; Output disables scalar-range enforcement and
leaves `bits_preconstrained=False`, so both Boolean loops execute. The witness
is prevalidated and each bit vector is read/compared against its witness.

Note commitment reuses value bits with `value_bits_preconstrained=True` and
adds no duplicate Boolean checks; `rcv` is not reused downstream. The
fixed-base Boolean loop and surrounding value-commitment path remain
concrete-R1CS. Recommended next isolated migration: route only that shared
Boolean loop through `_constrain_jubjub_scalar_bit`, preserving its
preconstrained and scalar-range branches.

No synthesis behavior or API changed. Full Output recorder synthesis remains
**Blocked**; upstream Bellman matrix equivalence remains **Unverified**.

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

The Boolean loop in `_constrain_fixed_base_jubjub_mul` now uses
`_constrain_jubjub_scalar_bit`. Only that enforcement call changed; branch
conditions, scalar-range handling, preconstrained behavior, row order/labels,
and placement remain unchanged. Output still emits 64 value rows and 252
`rcv` rows at the original locations, and its complete 7,827-row local
matrix fingerprint is unchanged. Value bits remain marked preconstrained
when reused in note commitment; the preconstrained fixed-base path still
emits no duplicate rows.

Isolated production/recorder fixtures match ordered rows, names, variable
mappings, and assignments under a nested namespace. Value and `rcv` local
matrix fingerprints:
`0647ab54621fcd156c698b16eac2aef84b1529bd5230926f6cf570ff820d7abc` and
`2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467`.
Production rejects non-Boolean assignments; cross-backend variables fail
before mutation. `crypto.py` and the Output entrypoint guard are unchanged.

Full Output recorder synthesis remains **Blocked**; upstream Bellman matrix
equivalence remains **Unverified**.

### Phase 9.20.90 verification

- CPython 3.10.11: full suite **278 passed**; focused fixed-base/manifest
  tests **12 passed**. Ruff and compileall passed; Pylance reported no
  diagnostics in changed Python files. All five existing fixed-base helper
  call sites remain signature-compatible. Final wheel/sdist builds,
  clean-target wheel import/resource checks (8 coin JSON files), and
  `git diff --check` passed.

## Phase 9.20.92 — Audit fixed-base 3-bit lookup relation

The Output lookup consumes ascending LSB-first triples `(a,b,c)` and indexes
the table by `a+2b+4c`. Each window table is `(0P,...,7P)` and the next
window base is `8P`. Output's 64-bit value uses 22 windows, with the final
two high bits padded by zero; its last `bc` product constant-folds, leaving
65 value lookup rows. The 252-bit `rcv` uses 84 full windows and 252 rows.
Total Output lookup rows: 317, after existing bit enforcement.

For each coordinate, the helper constructs `base` from table entries 0, 2,
4, and 6, constructs an interpolation `factor` from entries 0 through 7,
then enforces `factor * a = selected - base`, in `u` then `v` order. Full
variable windows append `b*c=bc` first, then the `u` and `v` coordinate
rows. Selected point `u/v` witnesses are allocated before lookup; `bc` is
the only lookup multiplication intermediate. The fixed-base wrapper reads
scalar bit assignments before windows; lookup rows validate selected
coordinates without explicitly reading them.

The lookup remains concrete-R1CS: its signature uses `R1CS`, `Variable`
coordinates and concrete `CircuitBit` aliases; constant/negated-bit reads
use `_read_blake_bit`; multiplication, linear combinations, and A/B/C
enforcement use concrete R1CS paths. Output has no namespace scope; its
composed label prefix is embedded in the string labels. The implementation
is also shared by Spend fixed-base multiplications.

The all-eight-pattern production regression confirms ordered row labels,
A/B/C expressions, selected assignments, and satisfaction. It is not
recorder evidence. The next isolated migration is `_constrain_lookup3_point`
and only its variable-aware `_constrained_bit_and` dependency. Full Output
recorder synthesis remains **Blocked**; upstream Bellman matrix equivalence
remains **Unverified**.

### Phase 9.20.92 verification

- CPython 3.10.11 focused lookup, compatibility-manifest, Output 7,827-row,
  and fixed-base Spend regressions: **14 passed**.
- Ruff, compileall, manifest JSON parsing, and Pylance diagnostics for changed
  Python tests passed. Repository-wide `git diff --check` reports unrelated
  existing trailing whitespace in `src/manager.py:117,119,123`; audit files
  are clean. Full suite and package builds were not rerun. No synthesis
  implementation was modified.

## Phase 9.20.93 — Backend-neutral fixed-base 3-bit lookup

The unsigned Output lookup now uses `SynthesisBackend` for multiplication,
linear combinations, ownership checks, and enforcement. Production and
recorder direct-synthesis tests match all eight patterns and the partial
zero-padded window: 6 rows/7 columns including ONE for a full window and
3 rows/4 columns for the partial window. Ordered local matrices, labels,
variable mappings, witness assignments, selected coordinates, foreign-owner
rejection, and invalid/unassigned witness behavior are covered. The separate
signed Pedersen lookup and table are unchanged; its shared AND helper
regressions pass.

The complete production Output check remains 7,827 rows and 7,827 columns.
Full Output recorder synthesis remains **Blocked** because the enclosing
fixed-base orchestration and other nested Output paths are still concrete
R1CS. Upstream Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.93 verification

- CPython 3.10.11 Sapling gadget plus compatibility-manifest suites:
  **48 passed**.
- Targeted Ruff, compileall, Pylance diagnostics, and Pylance signature
  compatibility checks passed. Existing unrelated Ruff findings in
  `src/r1cs.py` were not changed.
- Full project suite, packaging, and clean-target wheel checks were not run.

## Phase 9.20.94 — Backend-neutral fixed-base window orchestration

The post-validation fixed-base loop is extracted as
`_constrain_fixed_base_windows`, using the generic point allocator, unsigned
lookup, and affine addition. Scalar validation, witness reads, and
Boolean/range branches remain in the concrete wrapper. The helper validates
all bit ownership before allocations.

Production/recorder parity for a two-window four-bit trace is **11 rows and
16 columns including ONE**. Both local matrices have SHA-256 digest
`d0bb18f6a9dbb97594fb879fd6946be554b9f68cb35acefe59f829319e0f8d72`.
The test compares ordered local matrices, names/labels with namespace separators normalized, variable
mappings, witness assignments, and result coordinates. A foreign variable
in the later window is rejected before mutation. The complete production
Output regression remains 7,827 rows and 7,827 columns.

Full Output recorder synthesis remains **Blocked** by concrete scalar
admission/witness/range logic and other Output subpaths. Upstream Bellman
matrix equivalence remains **Unverified**.

### Phase 9.20.94 verification

- CPython 3.10.11 Sapling gadget and compatibility-manifest suites:
  **50 passed**, including Output and Spend regressions.
- Targeted Ruff, compileall, Pylance diagnostics, and signature checks passed.
- Full project suite and package builds were not run.

## Phase 9.20.95 — Backend-neutral fixed-base scalar validation

The fixed-base wrapper now delegates scalar admission, witness validation,
ownership checks, Boolean rows, and its original packed/range-enforced branch
to `_constrain_fixed_base_scalar` over `SynthesisBackend`. The separate
window helper and validation-before-window ordering remain unchanged.

Production/recorder parity covers the 252-bit range-enforced scalar path
(876 rows, 875 columns including ONE) and the integrated 84-window
fixed-base call (1,626 rows, 1,625 columns including ONE). The latter has
common local matrix digest
`aadef2e1b28c133bb86798085aa92f66525af7eac38d46e673f8f003bfb401f0`.
Boundary-value, invalid/unassigned, out-of-range, mismatched-witness,
foreign-variable, and preconstrained cases pass without adding duplicate
checks or mutating a backend on rejected input. Existing Output production
rows/columns remain 7,827 by 7,827, and the entrypoint guard is unchanged.

This is local cross-backend evidence only. Full Output recorder synthesis
remains **Blocked** by other concrete Output dependencies; upstream Bellman
matrix equivalence remains **Unverified**.

### Phase 9.20.95 verification

- CPython 3.10.11 Sapling gadget suite: **43 passed**; compatibility-manifest
  suite: **11 passed**.
- Targeted Ruff, compileall, Pylance diagnostics, and changed-file
  `git diff --check` passed.
- Full project suite and package builds were not run.

## Phase 9.20.96 — Remove the concrete Output backend guard

The Output entrypoint now checks the `FreshSynthesisBackend` protocol and its
freshness capability rather than requiring concrete `R1CS`. Production R1CS
and the recorder implement freshness and public-input-position queries.
The first exposed concrete helper, the fixed-base value-commitment relation,
was migrated to `SynthesisBackend`.

The isolated relation matches in both backends at **1,889 rows and 1,888
columns including ONE**, with identical local ordered matrices, labels,
variable order/names, and assignments. Common SHA-256:
`885b7d51797f2d65e89e4ada3e8bdd5ca8fc3187eef421fbe4f7463bbc65d592`.
Production Output remains **7,827 rows and 7,827 columns**.

The Output entrypoint reaches the next concrete dependency and then rejects
recorder variables in `constrain_sapling_ephemeral_key`. That failed recorder
attempt has already emitted 1,265 rows, allocated 6 inputs including ONE,
and allocated 1,517 auxiliary variables. Invalid witnesses and non-fresh
backends are rejected before mutation. The next migration boundary is the
ephemeral-key relation plus its scalar-multiplication/point-validation
dependencies. Full Output recorder synthesis remains **Blocked**; upstream
Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.96 verification

- CPython 3.10.11 Sapling gadget/Spend regressions and
  compatibility-manifest tests: **56 passed**.
- Targeted Ruff on the changed gadget, protocol, recorder, and test files,
  compileall, Pylance diagnostics, and signature checks passed. Ruff's
  `E,F` check on `r1cs.py` reports five unrelated existing E501 lines (58,
  67, 401-403); they were left untouched.
- Full-project tests and package builds were not run.

## Phase 9.20.97 — Backend-neutral Sapling ephemeral-key constraints

The ephemeral-key relation now uses `SynthesisBackend` for variable
ownership, witness reads, public-input positions, and Boolean enforcement.
Its point-witness validation and three-doubling non-small-order composition
are backend-neutral. Existing scalar multiplication and Jubjub arithmetic
helpers preserve the 252-bit little-endian bit order, allocation order,
equations, labels, and enforcement order.

Production/recorder ephemeral-key synthesis matches for the reference
fixture and scalar boundaries 0, 1, and the Jubjub scalar modulus minus one
at **3,539 rows and 3,544 columns including ONE**, with identical ordered local matrices,
normalized labels, variable mappings, witness assignments, and results.
Common local SHA-256:
`c70a14e6c311b6b029651659ff03a7fec711bd2c4333ccecca138280c65d0a1b`.
Invalid/unassigned bits, foreign variables, out-of-range scalars, and
mismatched witnesses are rejected before this relation mutates either
backend.

A fresh complete Output recorder attempt passes this operation, then stops
at the separate concrete note-commitment value check after **4,804 rows,
6 inputs including ONE, and 5,309 auxiliary variables**. Complete Output
recorder synthesis remains **Blocked**; this partial state is not a complete
circuit result. The production Output matrix remains **7,827 rows and
7,827 columns**, fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No value-commitment, fixed-base, note-commitment, or Pedersen implementation
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

## Phase 9.21.00 — Pinned Bellman Output equivalence audit

The local production/recorder Output result is **7,827 rows × 7,827 columns**
with unchanged production fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
This is not upstream Bellman equivalence. Pinned source and the local
allocation manifest establish three stage-order differences: value and `rcv`
allocation relative to value-base computation; `g_d` representation relative
to `esk`/`epk`; and `rcm` allocation relative to note Pedersen. Without a
complete upstream typed allocation/assignment trace and ordered A/B/C export,
whole-matrix identity and exact query mapping remain **Unverified**.

The pinned Output test source asserts 7,827 rows, six inputs including ONE,
and Bellman TestConstraintSystem hash
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`.
The hash is not a matrix fingerprint. An execution attempt stopped before
test execution because `link.exe` was unavailable. The report's audit records
the minimum isolated upstream export needed next; no Rust/native dependency
or tool was added to ZyCoin.

## Phase 9.21.01 — Output allocation-order effects

The three source-verified ordering differences have different observable
effects. Allocating `rcv` before value-base auxiliaries changes Aux positions
and positional assignment/query entries, while the relation call order still
emits the value multiplication before the `rcv` multiplication. Moving
`g_d` representation from before `esk`/`epk` to after the ephemeral-key
relation changes both Aux order and enforcement-row order. Moving `rcm`
allocation/Boolean rows from after Pedersen to before Pedersen changes both
Aux order and row order. These ordering changes are not themselves proof of
different cryptographic relations, but an explicit semantic variable and row
mapping is required before compatibility can be assessed.

The current Python recorder cannot execute the pinned Rust synthesizer and
the semantic fixture lacks upstream typed variable assignments and ordered
A/B/C terms. The required artifact is an external, test-only observer export
for the fixture: typed Input/Aux allocation identities and values, each raw
ordered A/B/C row, and a satisfaction result. The upstream test hash is only
a cross-check, not a matrix fingerprint. Output/Bellman equivalence and exact
proving-query mapping remain **Unverified**; no production circuit code,
equations, or Python-only runtime architecture changed.

## Phase 9.21.02 — Output export and mapping status

The external test-only export now contains six typed inputs including ONE,
7,821 assigned auxiliary variables, and 7,827 satisfied ordered A/B/C rows.
The pinned Output test and observer both pass against source revisions
`88a7946b4a3066787776e11f0a502654167e022d` and
`b726862a4ece8a627e7fea486d77b502a6edbb0b`; copied Sapling synthesis source
hashes match the pinned checkout. Recomputing Bellman's
`TestConstraintSystem::hash` from the exported rows reproduces
`c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`.
That digest is an upstream test-system hash, not a matrix fingerprint.

ZyCoin's fresh production and recorder runs remain equal at 7,827 rows ×
7,827 columns with the unchanged production fingerprint. All public input
assignments and the value, `rcv`, `esk`, and `rcm` bit assignments match under
their semantic identities. The export confirms the recorded Aux and row-order
differences. It does not yet provide a complete local-to-upstream semantic
variable permutation, row-reordered A/B/C equivalence result, or exact
Groth16 query map. Therefore the evidence cannot yet decide whether a
permutation alone suffices or production allocation/enforcement order needs
adjustment. Output/Bellman equivalence and Sapling parameter eligibility
remain **Unverified / blocked**; Spend was not synthesized by this external
export task.

The focused Output, Spend, and compatibility-manifest regression suites pass:
**85 passed** on CPython 3.10.11. The local production Output dimensions and
fingerprint remain unchanged.

## Phase 9.21.03 — Semantic Output matrix comparison status

The fresh local Output R1CS and pinned upstream export both contain 7,827
rows and 7,827 columns including ONE, and both satisfy their fixture.
Production fingerprint remains
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
The checked semantic mapping covers the six public inputs and 820 named
auxiliaries (value, `rcv`, `esk`, and `rcm` bits). The other 7,001
auxiliaries do not yet have a complete semantic correspondence. Repeated
witness assignments make value-only matching ambiguous.

An exact coefficient comparison of the mapped value-bit-0 Boolean row
differs: ZyCoin uses `x * (x - 1) = 0`, while upstream uses `(1 - x) * x =
0`. They encode the same Boolean zero set, but the A/B factors and sign are
not identical. Thus a variable permutation alone cannot make the exact
matrices equal; a variable/row multiset comparison and row permutation have
not been completed. No exact query/proving-key transformation follows from
the current evidence. Overall Bellman equivalence, whether the production
circuit may remain unchanged with mappings, and exact query mapping remain
**Unverified**. No production code was changed.

## Phase 9.20.99 — Backend-neutral Sapling Pedersen hash

The Edwards and Montgomery Pedersen implementations now use
`SynthesisBackend` for input ownership/witness reads, Boolean enforcement,
intermediate allocation, and row emission. Production R1CS calls retain their
existing overload and return type; Pedersen inputs, constants, generators,
bit order, equations, labels, and enforcement order are unchanged.

The isolated Output note-hash relation matched between production and
recorder on both representations: Montgomery **1,558 rows × 1,559 columns**
and Edwards **2,314 × 2,315**. The Montgomery production matrix fingerprint
is `b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76`;
the common serialized-matrix SHA-256 is
`fc2a2fd1437f7eeb4e4081a9bf36525ff6adeccb17a644aafdf8d98642700b74`.
Ordered matrices, labels, variable mappings, witness assignments, and
outputs match. Both production satisfaction and independent recorder-row
evaluation pass. Invalid, unassigned, foreign, and malformed bit inputs are
rejected before backend mutation.

A fresh full Output synthesis now completes on production and recorder.
Their ordered matrices, labels, variable mappings, and assignments match at
**7,827 rows × 7,827 columns**, and both satisfy. The production fingerprint
is unchanged at
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
No further concrete backend dependency was exposed on this path. This does
not demonstrate equivalence with upstream Bellman; that remains
**Unverified**, and all proving-parameter and Sapling-spending gates remain.

### Phase 9.20.99 verification

- Combined Sapling gadget/Output/Spend and compatibility-manifest suites:
  **63 passed**, including **284 subtests**. The isolated Pedersen input
  rejection/parity checks also pass.
- Ruff `E,F` checks passed with the existing `E501` baseline excluded;
  `compileall`, manifest JSON parsing, and changed-file whitespace checks
  passed. Pylance diagnostics were empty and all nine Pedersen call sites
  passed signature compatibility.

## Phase 9.20.98 — Backend-neutral note-value commitment boundary

The internal note-commitment helper now accepts backend-neutral variables
and linear combinations, using a protocol operation to validate ownership
and read the assigned note-value expression. The existing note-value range
decomposition and Boolean equations, bit/allocation order, witness checks,
representation constraints, and fixed-base/addition composition are retained.
The exported `constrain_note_commitment` public signature is unchanged.

A fresh Output-prefix comparison stopped immediately before Pedersen
synthesis in each backend. Production and recorder match at **6,088 rows
and 6,089 columns including ONE**, with identical ordered local matrices,
labels, variable mappings, and witness assignments. Common local SHA-256:
`ee6e68379fb5e5eb144d460fd483acab8b69f68ffdf8e3437a15948502e62c6e`.
Invalid, unassigned, foreign, and out-of-range note values are rejected
before the note helper mutates the backend. The production prefix satisfies;
the recorder does not provide satisfaction evaluation.

A separate fresh full Output recorder attempt exposes `constrain_pedersen_hash`
as the next concrete blocker, stopping after **6,088 rows, 6 inputs including
ONE, and 6,083 auxiliary variables**. Complete Output recorder synthesis
remains **Blocked**. Production Output remains **7,827 rows and 7,827
columns**, with the original fingerprint
`98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
Pedersen synthesis and cryptographic equations were not changed. Upstream
Bellman matrix equivalence remains **Unverified**.

### Phase 9.20.98 verification

- CPython 3.12.10 Sapling gadget/Output, Spend, and compatibility-manifest
  suites: **82 passed**. Final focused Output, note-commitment, and manifest
  rerun: **16 passed**.
- Ruff `E,F` checks passed with unrelated baseline `E501` findings excluded.
  `compileall`, manifest JSON validation, and task-file whitespace checks
  passed.

## Phase 9.20.84 — Backend-neutral unchecked Jubjub representation allocation

The Output `pk_d` representation allocator
`allocate_unchecked_jubjub_repr` now uses `SynthesisBackend.alloc_private`
for its existing 256 allocations: 255 little-endian `v` bits followed by
the `u` parity bit, with unchanged names and order. The production R1CS
overload and its return type are preserved. No rows or validation are added;
off-curve points remain accepted by this unchecked allocator.

Production/recorder tests match allocation order, local variable mappings,
names, witness values, and zero emitted rows for identity, generator,
negative generator, and off-curve boundary fixtures. Invalid `None`, object,
and foreign-backend variable inputs fail before target-backend mutation.
Since the existing API takes a concrete `Point`, it does not support
unassigned representation witnesses; `None` is rejected.

The Output entrypoint guard is unchanged. Full Output recorder synthesis
remains **Blocked**, and upstream Bellman matrix equivalence remains
**Unverified**. This local allocation-only parity does not unblock note
commitment or alter the broader Phase 9.20.83 dependency map.

### Phase 9.20.84 verification

- CPython 3.10.11 full suite: **275 passed**; focused allocator, namespace,
  invalid-input, note-commitment, and manifest suite: **15 passed**.
- Ruff, compileall, Pylance diagnostics (no diagnostics in changed Python
  files), all eight signature call sites, and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install imported
  `zycoin.sapling_gadgets` and read all eight packaged coin JSON resources.

## Phase 9.20.83 — Output synthesis dependency audit

Phase 9.20.83 is audit-only. It traces the complete local
`constrain_sapling_output` path through value commitment, ephemeral-key
multiplication, note commitment, fixed-base multiplication, and Montgomery
Pedersen hashing. It records exact public-input order, production private
allocation ranges, nested constraint call order, and concrete backend
assumptions in the compatibility manifest. No synthesis code, equations,
public APIs, or guards changed.

The Output entrypoint still requires a fresh concrete `R1CS`; its freshness
checks and full-witness validation run before allocations. `cv.u`, `cv.v`,
`epk.u`, `epk.v`, and `cmu.u` are allocated first. Private allocation then
proceeds through value/`rcv` bits and both fixed-base products; `g_d`, `esk`,
its curve/non-small-order and scalar-multiplication relations; unchecked
`pk_d` representation bits and `rcm`; then `g_d` strict representation,
Montgomery Pedersen, `rcm` fixed-base multiplication, commitment addition,
and public `cmu.u` binding. The production-local allocation ranges are
preserved in the manifest, not represented as recorder identities.

The Montgomery Pedersen input is six personalization bits plus 576 message
bits (64 value, 256 `g_d` representation, 256 `pk_d` representation): 194
three-bit chunks split into 63/63/63/5 chunk segments. Output passes
`enforce_scalar_range=False` for its fixed-base products and supplies the
preconstrained value decomposition, so the helper's optional range/packing
branches do not execute. Direct Boolean checks and witness reads still do.

The variable-base scalar path and point allocation, representation, selection,
doubling, and addition are already shared. Remaining concrete dependencies
are the entrypoint freshness/allocations, value commitment and fixed-base
lookup/Boolean/witness APIs (optional range/packing branches are not selected
by Output), ephemeral/non-small-order witness reads,
note commitment's concrete LC and value evaluation, and Montgomery Pedersen's
concrete `_PedersenNum` and R1CS witness/allocation/enforcement APIs.
Fixed-base/lookup, note/Pedersen, and ephemeral/non-small-order routines have
interdependent pieces and should migrate together within their respective
bounded subpaths.

The recommended next isolated operation is `allocate_unchecked_jubjub_repr`:
the `pk_d` 256-bit representation allocator (`v` bits then `u` parity) uses
only private allocation, an operation already available on both backends.
Tests can compare its exact allocations and no-row behavior without changing
note commitment, curve-check behavior, or the Output guard.

**Full Output recorder synthesis remains blocked. Upstream Bellman matrix
equivalence remains unverified.** Local parity on migrated helpers is not
evidence of upstream equivalence.

### Phase 9.20.83 verification

- CPython 3.10.11 full and focused suites, Ruff, compileall, Pylance/signature
  checks, `git diff --check`, wheel/sdist builds, and isolated wheel import
  and resource checks passed.
- No production synthesis code was modified.

## Phase 9.20.82 — Backend-neutral scalar multiplication orchestration

The full existing `constrain_jubjub_scalar_mul` path now uses
`SynthesisBackend`; both production R1CS and recorder execute the same
validation and synthesis logic. It retains witness-shape and backend bit
ownership/assignment checks, matching bit-value validation, the 252
little-endian traversal, optional caller-preconstrained bits, per-index base
doubling, point selection, and first-selected-point then affine-addition
accumulation. Intermediate points and every row remain in their original
order. No scalar range/reconstruction constraint was introduced. The
production Output entrypoint guard is unchanged.

Fixtures for zero, one, `0x1234`, and `SCALAR_MODULUS - 1` on the
spending-key base and zero/one on the identity base match the independent
host multiplication. Production and recorder matrices, all 252 bit mappings,
all variable mappings, and witness values match. The matrix has 3,521 rows
and 3,523 columns including ONE, with local fingerprint
`1e53bdeacde8d6565d678691dc5a47723f9bcdf781aced9a50cf8dee94c8216f`.
Tampering with scalar bits, accumulators, and final coordinates fails for
nonidentity bases; unassigned and foreign values are rejected before
mutation.

This is not whole Output synthesis or upstream Bellman execution. Remaining
concrete R1CS surfaces include the Output entrypoint and ephemeral-key
composition, value commitment/fixed-base multiplication, non-small-order
composition, note commitment, and Pedersen synthesis. Spend synthesis,
proving behavior, parameter trust, and Sapling spending gates are unchanged.

### Phase 9.20.82 verification

- CPython 3.10.11 full suite: 272 passed; focused scalar, recorder, Sapling
  gadget, and manifest suite: 76 passed.
- Ruff, compileall, Pylance diagnostics (no diagnostics in changed Python
  files), all 11 signature call sites, and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install imported
  `zycoin.sapling_gadgets` and read all eight packaged coin JSON resources.

## Phase 9.20.81 — Backend-neutral scalar multiplication accumulation

Scalar multiplication traverses bits least-significant first. The existing
per-bit order remains Boolean constraint, base doubling for indices greater
than zero, selected-point allocation/selection, then accumulation. Its host
witness initializes to the identity and adds each selected point. Circuit
synthesis does not allocate the identity: selected point zero is the first
accumulator, and later selected points are added through the existing affine
addition gadget. For each later bit, the next accumulator coordinates are
allocated before that addition's four multiplication intermediates and two
coordinate rows. Zero-bit selections remain identity points and are still
added at subsequent indices.

The shared accumulation helper is called from the original point in the
production loop, retaining the interleaved layout. It checks ownership before
allocating, maps the supplied witness accumulator, and uses the existing
backend-neutral point allocator and affine addition. The rest of the scalar
multiplication routine and its type/witness validation remain
concrete-R1CS coupled.

For four-bit zero, one, and `0xB` scalars with the spending-key base and
identity base, production and recorder accumulation fixtures agree in
ordered matrices, allocation mappings, and witness values. Independent
host summation and `base.multiply(scalar)` agree with the resulting
accumulators. Each accumulation-only fixture has 18 rows, 27 columns
including ONE, and fingerprint
`2a095999443d2a45416b2e06c6003fcb83f736d1401f38e3dd1334867cda33a0`.
Tampering with accumulator coordinates or addition intermediates fails;
unassigned values are preserved; malformed and foreign inputs are rejected
before mutation.

No strict point representation or scalar-range relation was added. This
local cross-backend comparison is not authoritative Bellman matrix evidence
or full Output equivalence. Proving behavior, parameter trust, and Sapling
spending gates remain unchanged.

### Phase 9.20.81 verification

- Focused recorder, scalar multiplication, Sapling gadget, and manifest
  suites: **73 passed** on CPython 3.10.11.
- Targeted Ruff, compileall, JSON validation, Pylance diagnostics,
  signature-compatibility checking, and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install exercised the
  recorder accumulation and loaded all 8 packaged coin configurations.
- Full CPython 3.10.11 suite: **269 passed**.

## Phase 9.20.80 — Backend-neutral scalar bit decomposition

The Output `esk` witness is host-validated as a Jubjub scalar and represented
by 252 little-endian private bits. The shared synthesis helpers allocate
those bits and enforce the existing per-bit Boolean relation on both
production R1CS and the recorder. They preserve the Output allocation order
and Boolean-row placement within scalar multiplication.

This decomposition has no in-circuit scalar reconstruction equation or
less-than-scalar-modulus comparator. The equality between `esk` and the
weighted bit sum is checked during host witness validation; host validation
also rejects values outside the scalar range. The isolated Boolean bit rows
therefore do not provide either relation, and no new constraints are claimed.

For zero, one, an intermediate scalar, and `SCALAR_MODULUS - 1`, the 252
ordered Boolean rows and mapped bit witnesses agree across local backends.
The 253-column local matrix fingerprint is
`2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467`.
Invalid non-Boolean tampering fails; a Boolean bit flip remains accepted in
the isolated slice, and unassigned values remain unassigned. This is local
cross-backend agreement, not authoritative Bellman matrix evidence.

Full scalar multiplication and the Output entrypoint remain concrete-R1CS
coupled. No proving, parameter-trust, or spending-gate behavior changed.

### Phase 9.20.80 verification

- Focused recorder, Sapling gadget, and compatibility-manifest suites:
  **70 passed** on CPython 3.10.11.
- Targeted Ruff, compileall, JSON validation, Pylance diagnostics,
  signature-compatibility checking, and `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install exercised the
  252-bit recorder synthesis and loaded all 8 packaged coin configurations.
- Full CPython 3.10.11 suite: **266 passed**.

## Phase 9.20.79 — Backend-neutral affine Jubjub addition

The existing affine addition helper now synthesizes through `SynthesisBackend`
for both production R1CS and the Bellman-style recorder. It preserves the
four multiplication rows and two division-relation rows and does not change
the equations or caller allocation behavior. Production and recorder matrix
serialization and witness assignments agree for representative points,
identity on either side, equal points, and inverse points. The representative
fixture has six rows, eleven columns including ONE, and local fingerprint
`b9c3cfc17d0b5201e6f4c69a10138911190b747f9c09ffcc6ee56a0fbadce39c`.
The helper still requires caller-provided on-curve constraints and points in
the affine-addition domain. This is the existing incomplete affine formula:
the helper does not establish subgroup membership or handle denominator
poles for arbitrary curve points. The edge fixtures do not establish formula
completeness beyond their intended subgroup domain. This is
cross-implementation agreement only; it is not an authoritative Bellman
matrix export or whole Output equivalence.

Scalar-bit allocation, selector composition, accumulation, full scalar
multiplication, and the Output entrypoint remain concrete-R1CS coupled.
Proving behavior, parameter trust, and Sapling spending gates are unchanged.

### Phase 9.20.79 verification

- Focused recorder, Sapling gadget, and compatibility-manifest suites:
  **65 passed**; full CPython 3.10.11 suite: **261 passed**.
- Targeted Ruff, compileall, JSON validation, Pylance diagnostics,
  signature-compatibility checks for all 19 addition call sites, and
  `git diff --check` passed.
- Wheel and sdist builds passed. A clean-target wheel install imported the
  gadget, synthesis interface, and recorder and read all 8 packaged coin
  configurations.

## Phase 9.20.70 — Bellman synthesis evidence and compatibility manifest

The machine-readable
[Spend/Output compatibility manifest](sapling-circuit-compatibility-manifest.json)
records local allocation evidence separately from source-derived Bellman
facts. Its source pins are Sapling Crypto
`88a7946b4a3066787776e11f0a502654167e022d` and Bellman
`b726862a4ece8a627e7fea486d77b502a6edbb0b` (0.15.0).

### What the pinned source establishes

- Sapling's [`src/circuit.rs`](https://github.com/zcash/sapling-crypto/blob/88a7946b4a3066787776e11f0a502654167e022d/src/circuit.rs)
  establishes the top-level Spend and Output gadget-call order and the
  locations where their public points are inputized.
- Bellman's
  [`TestConstraintSystem`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/src/gadgets/test/mod.rs)
  initializes `Input(0)` as `ONE`; `alloc_input` and `alloc` advance
  independent input and auxiliary vectors; and each `enforce` appends an
  ordered A/B/C triple. The upstream circuit tests assert Spend's 98,777
  rows, eight inputs including ONE, and TestConstraintSystem hash
  `d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89`;
  Output's corresponding assertions are 7,827 rows, six inputs, and hash
  `c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee`.
  Bellman's `hash()` computes BLAKE2s-256 with default parameters over
  dimensions and ordered A/B/C terms. Those test-system digests are not
  matrix fingerprints in ZyCoin's serialization.
- Bellman's
  [`groth16/src/generator.rs`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/groth16/src/generator.rs)
  adds one dummy `x * 0 = 0` constraint per input (including ONE), then
  allocates setup query vectors indexed by inputs followed by auxiliaries:
  A in G1, B in G1/G2, IC for inputs, L for auxiliaries, and H with
  `domain_size - 1` entries. The
  [`EvaluationDomain`](https://github.com/zkcrypto/bellman/blob/b726862a4ece8a627e7fea486d77b502a6edbb0b/src/domain.rs)
  pads the resulting row count to a power of two. This yields source-derived
  domain sizes of 131,072 for Spend (`98,777 + 8` rows before padding) and
  8,192 for Output (`7,827 + 6`).
- The pinned ECC and Pedersen sources establish component operations and
  nested call structure. They do not provide a complete flattened trace of
  every variable identity and A/B/C term.

### What remains execution-dependent

Source reading identifies synthesis procedure, public inputization order,
namespace rules, and the rules by which indices and rows are appended. It
does not yield the complete typed `Aux(n)` identity sequence or every
flattened row's A/B/C linear combinations without tracing the behavior of all
nested gadget implementations. In particular, Bellman's setup `KeypairAssembly`
discards annotation strings and stores coefficients by `Input`/`Aux` index;
the Groth16 queries therefore contain no semantic auxiliary names.

The upstream unit tests publish aggregate counts and `TestConstraintSystem`
hashes, not serialized complete A/B/C rows or a typed auxiliary-allocation
export. Reproducing those values independently would require running the
pinned synthesizer with an observing constraint system, or implementing and
executing a complete equivalent synthesizer. Neither is done here. The
existing Python Pedersen and BLAKE2s files are source-derived component
transcriptions, not Bellman exports, and their component fingerprints are
identified as such in the manifest.

The manifest retains both complete local allocation-manifest hashes and
their ranges. It compares known public inputs, row counts, and QAP domain
sizes, while preserving explicit `Unverified` states for upstream auxiliary
identities, full row ordering/A/B/C terms, whole-circuit matrix fingerprints,
and exact proving-query mapping. A source/test-system hash is not substituted
for an upstream matrix fingerprint. The phase also corrected stale local
Output dimensions and fingerprint in the runtime compatibility metadata;
current Output metadata is 7,827 rows / 7,827 columns / 7,821 auxiliaries.

**Conclusion:** a complete authoritative ordered Bellman matrix cannot be
established from the currently available source assertions and partial
transcriptions without executing or implementing another complete
Bellman-compatible constraint synthesizer. Under the Python-only restriction,
the strongest supportable outcome is the source-bounded manifest. Whole
Spend/Output equivalence and parameter compatibility remain **Unverified /
Blocked**; Sapling spending remains gated.

### Phase 9.20.70 verification

- CPython 3.10.11: full test suite **234 passed**; focused manifest,
  parameter compatibility, Spend/Output, and QAP set **91 passed**.
- The manifest tests validate required fields for both circuits, contiguous
  complete local allocations, deterministic canonical serialization, pinned
  source provenance, runtime metadata consistency, and explicit unknown
  states when upstream exports are absent.
- `compileall`, targeted Ruff, and `git diff --check` passed. Pylance reported
  no diagnostics for the modified manifest test, compatibility metadata, or
  parser test; all 7 compatibility-assessment call sites passed signature
  checks.
- Wheel and sdist builds passed. The sdist includes the JSON manifest, both
  updated reports, and its regression test. A clean-target wheel install
  imported the compatibility and circuit modules and read all eight
  packaged coin JSON resources.
- The unchanged `src/r1cs.py` Ruff baseline remains **45 findings**:
  13 UP007, 12 UP006, 9 UP045, 8 UP037, 2 UP035, and 1 SIM102.
- No circuit equations or allocation behavior changed. No Rust, native code,
  external prover, real parameter, secret, credential, or production
  transaction was used.

## Phase 9.20.71 — Pure-Python Bellman synthesis recorder

The new bounded recorder in `src/bellman_synthesis.py` models the audited
Bellman synthesis subset: typed input/auxiliary identities, implicit ONE,
namespace paths, ordered LC terms and A/B/C rows, setup dummy-input
constraints, and the input-then-aux query layout. A separate local-R1CS
adapter makes the differing column conventions explicit. The deterministic
recorder matrix serialization and fingerprint use ZyCoin-specific domains;
matrix fingerprints include dimensions and ordered terms, not annotation
labels, and are not comparable to Bellman's TestConstraintSystem hash.

An independently specified fixture pins allocation identities, a hand
calculated row, setup rows and indexing. A small transcribed Pedersen
component agrees across the local R1CS and recorder implementations, with
matching mapped matrix serialization and output point. This is a bounded
cross-implementation test only: the Python transcription was not executed
by Bellman, and it does not supply an upstream matrix export. Complete
Spend/Output synthesis was not migrated.

**Status:** recorder subset **Verified** by local fixtures; Pedersen
cross-implementation agreement **Partially Verified**; authoritative
Bellman matrix export, whole-circuit equivalence, proving-key compatibility,
and Sapling spending **Unverified / Blocked**. Modeled and unsupported
ConstraintSystem behavior is itemized in the
[compatibility manifest](sapling-circuit-compatibility-manifest.json).

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

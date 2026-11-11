# ZyCoin technical reports

Individual reports summarize the technical evidence available for each major
subject. The [historical compatibility record](coin-registry-compatibility-audit.md)
retains the original chronological findings, per-network tables, test results,
and provenance; it is the source record for the focused reports below.

## Registry and transparent wallet

- [Coin registry and network compatibility](coin-registry-and-network-compatibility.md) —
  dynamic JSON discovery and the per-network capability matrix.
- [BIP-39 mnemonic and seed handling](bip39-mnemonic-and-seed-handling.md) —
  recovery phrase validation and shared seed use.
- [Transparent derivation and address generation](transparent-derivation-and-address-generation.md) —
  BIP-44 paths, coin-type evidence, and address serialization.
- [Transparent transaction construction and signing](transparent-transaction-signing.md) —
  supported BitcoinZ P2PKH subset and signing limitations.

## Clients

- [Electrum client compatibility](electrum-client-compatibility.md) —
  configured transports, RPC checks, and endpoint availability.
- [Bitcore client compatibility](bitcore-client-compatibility.md) —
  REST history, transactions, response normalization, and Socket.IO findings.
- [Lightwalletd compatibility](lightwalletd-client-compatibility.md) —
  compact scanning, bounded live evidence, and scanner limits.

## Sapling

- [Authoritative Sapling Spend reference baseline](sapling-spend-authoritative-reference.md) —
  pins the source revisions used by the independent Bellman reference,
  documents the ordered synthesis contract and Python port map, and
  distinguishes the reference source pin from unverified official-parameter
  circuit binding.
- [Sapling Spend Bellman export and alignment status](sapling-circuit-implementation.md) —
  pinned Spend allocation provenance and partial row correspondence;
  98,637 of 98,638 auxiliary identities and 98,775 of 98,777 rows are mapped.
  [Phase 9.21.17](sapling-circuit-implementation.md#phase-92117--independent-spend-semantic-equivalence-audit)
  documents the anchor substitution, little-endian position interpretation,
  and evidence-supported semantic equivalence of the pinned exports; exact
  ordered matrix alignment and formal/source-level equivalence remain
  unverified. [Phase 9.21.33](sapling-circuit-implementation.md#phase-92133--independent-spend-parameter-point-compatibility)
  records exact Bellman 0.15/Python parser equality for all Spend IC and query
  point encodings. [Phase 9.21.34](sapling-circuit-implementation.md#phase-92134--independent-sapling-spend-qap-compatibility)
  independently compares complete satisfying-witness QAPs: both quotient
  divisibility checks pass, but all eight canonical QAP vectors differ, so
  exact Spend QAP equivalence remains unverified. Neither result establishes
  parameter-to-circuit binding or ceremony validity. The earlier Phase
  9.21.36 Sapling regression run passed 201 tests with 1 skipped; the full
  Phase 9.21.37 run passed 205 tests with 1 skipped. [Phase 9.21.35](sapling-circuit-implementation.md#phase-92135--spend-qap-transformations-and-proving-query-semantics)
  traces the QAP differences to row permutations, A/B swaps and nonuniform
  scaling, expanded-relation matches, and the explicit helper projection.
  Semantic relation equivalence is evidence-supported for the pinned exports;
  proving-query compatibility remains unverified.
  [Phase 9.21.36](sapling-circuit-implementation.md#phase-92136--sapling-spend-circuit-specific-setup-requirements)
  records the exact local matrix/QAP identity, reusable Groth16 components,
  parameter layout, and missing ceremony prerequisites.
  [Phase 9.21.37](sapling-circuit-implementation.md#phase-92137--memory-bounded-full-size-synthetic-spend-setup)
  records the full-size test-only synthetic setup, query sections, proof
  assembly/verifier checks, resource measurements, and the explicit use of a
  scalar-exponent oracle rather than full-vector production MSM. A secure
  local Spend setup, parameter binding, and ceremony validity remain
  unverified. [Phase 9.21.38](sapling-circuit-implementation.md#phase-92138--official-sapling-spend-full-vector-query-accumulation)
  independently compares full official-parameter accumulations: IC, L, A,
  B_G1, and B_G2 match, but H differs for the deterministic satisfying
  witness. The official parameters therefore do not establish support for
  the local Spend QAP; no proof was generated and the Spend gate remains
  closed. The complete Sapling regression run passed 206 tests with 1
  skipped in 2,844.775 seconds.
  [Phase 9.21.39](sapling-circuit-implementation.md#phase-92139--isolating-the-official-spend-h-query-mismatch)
  independently recomputed ZyCoin's quotient from its A/B/C evaluation
  vectors with Bellman 0.15 and cross-accumulated both coefficient vectors
  against both official H-query decodings. It isolates the mismatch to the
  different upstream/local QAP evaluation vectors; H point indexing and
  scalar conventions agree. The full Sapling regression rerun passed 206
  tests with 1 skipped in 3,005.919 seconds, including Output interoperability.
  The existing test-only synthetic setup regression ran as part of the full
  suite; this follow-up added no synthetic setup or proof.
- [Sapling Output authentic query-to-circuit audit](sapling-circuit-implementation.md#phase-92121--authentic-output-query-to-circuit-compatibility) —
  verified parameter-file identity, query-index layout, and local/pinned-matrix
  QAP comparison; see also
  [Phase 9.21.24](sapling-circuit-implementation.md#phase-92124--exact-sapling-output-query-decoding-compatibility)
  for exact point-by-point equality between ZyCoin's parsed official Output
  query points and the values loaded by Bellman 0.15,
  [Phase 9.21.25](sapling-circuit-implementation.md#phase-92125--authentic-sapling-parameter-ceremony-transcript-audit)
  for the independent `phase2` transcript-format/boundary audit and the
  missing Phase-1 inputs that leave cryptographic ceremony verification
  **Unverified**,
  [Phase 9.21.22](sapling-circuit-implementation.md#phase-92122--independent-sapling-output-qap-reference)
  for independent Bellman 0.15 QAP vectors across three witnesses and
  [Phase 9.21.23](sapling-circuit-implementation.md#phase-92123--authentic-sapling-output-groth16-interoperability)
  for Bellman-to-Python verification of one authentic-parameter proof.
  [Phase 9.21.28](sapling-circuit-implementation.md#phase-92128--independent-complete-authentic-output-msm-verification)
  independently matches all five complete authentic query accumulations and
  the IC/public-input accumulation against Bellman 0.15; this does not
  establish proof generation or ceremony validity.
  Parser-to-Bellman query serialization is verified; independent
  query-to-circuit/ceremony binding and production readiness remain
  Unverified.
- [Pure-Python BLS12-381 arithmetic and pairing](bls12-381-arithmetic-and-pairing.md) —
  field/curve primitives, pinned pairing-vector verification, and performance
  and security limitations.
- [Sapling Groth16 proof-generation readiness](sapling-groth16-proof-generation.md) —
  Phase 9.21.37 records the insecure full-size synthetic Spend setup and its
  full-vector MSM limitation. Phase 9.21.35 analyzes the relation-preserving Spend QAP rewrites and the
  unresolved proving-query transformation; Phase 9.21.34 records the
  independent Spend QAP comparison and its differing canonical vectors.
  Phase 9.21.28 independently verifies complete
  authentic Output MSM and IC accumulation equality with Bellman 0.15 (no
  proof generated),
  proof-generation blockers; the Phase 9.20.41 public-parameter hash and
  circuit-compatibility audit; and the Phase 9.20.56 Bellman parameter-wire
  format, BLS12-381/R1CS capability map, security requirements, and
  dependency-ordered roadmap. Phase 9.20.57 adds the bounded, single-pass
  Bellman parameter reader and uncompressed G1/G2 codecs, tested with
  synthetic fixtures. Phase 9.20.58 adds full streaming point/structure
  validation and a canonical manifest with a digest of the exact source
  bytes; trusted-hash comparison is supported, but no trusted hash or
  signature is supplied. Phase 9.20.59 adds explicit Spend/Output metadata
  and a per-property compatibility gate; it intentionally rejects a positive
  compatibility result without trusted digest-to-circuit binding and
  authoritative matrix evidence. No production parameter files were
  downloaded or retained. Phase 9.20.60 adds reference-tested radix-2 FFT,
  inverse FFT, and coset transforms. Phase 9.20.61 adds witness-specific
  R1CS-to-QAP interpolation and coset quotient construction with a
  Spend-sized regression. Phase 9.20.62 adds validated G1/G2 proving-query
  MSM evaluation for A, B, L, and H against synthetic query vectors.
  Phase 9.20.63 adds deterministic A/B/C proof-equation assembly from
  explicit randomizers and validated synthetic query inputs, including a
  Spend-sized identity-query regression. Parameter authentication,
  end-to-end proof generation, and real Sapling verification remain
  unsupported. Phase 9.20.64 adds BLS12-381 Groth16 verification against
  synthetic keys/proofs with ordered IC accumulation, subgroup validation,
  and a four-Miller-loop/one-final-exponent pairing product. This does not
  authenticate keys or establish Spend compatibility; Sapling spending
  remains gated. [Phase 9.21.22](sapling-groth16-proof-generation.md#phase-92122--independent-sapling-output-qap-reference)
  adds independent Bellman 0.15 QAP evaluation, polynomial, and quotient
  comparisons for three witnesses; authentic query-value compatibility and
  proof readiness remain Unverified. [Phase 9.21.21](sapling-groth16-proof-generation.md#phase-92121--authentic-output-query-to-circuit-compatibility-audit)
  documents Output variable/query index ordering, the local-versus-pinned
  matrix QAP comparison, authentic parameter identity, and why actual query
  value compatibility remains Unverified. Phase 9.21.20 documents individual
  subgroup validation for every authentic query point. [Phase 9.21.23](sapling-groth16-proof-generation.md#phase-92123--authentic-output-groth16-interoperability)
  demonstrates Bellman-to-Python verification of one proof generated with
  the authentic Output parameters. [Phase 9.21.24](sapling-groth16-proof-generation.md#phase-92124--exact-output-proving-query-parser-compatibility)
  adds exact Python-parser/Bellman point equality for all 32,016 Output
  query and IC points; parameter-to-circuit/ceremony binding and production
  readiness remain Unverified. [Phase 9.21.30](sapling-groth16-proof-generation.md#phase-92130--production-safe-sapling-output-proving-api)
  documents the restricted production-facing Output API, secure-randomness
  path, two independently verified randomized proofs, rejection tests, and
  remaining ceremony/circuit-binding limits. See the [API usage and security
  notes](../docs/sapling-output-proving.md).
  [Phase 9.21.31](sapling-groth16-proof-generation.md#phase-92131--production-output-api-security-audit)
  documents the security audit, fixes parameter-object reconfiguration
  through `dataclasses.replace`, and records accepted Python/ceremony
  limitations and verification results.
  [Phase 9.21.32](sapling-groth16-proof-generation.md#phase-92132--output-parameter-to-circuit-trust-audit)
  separates exact file integrity, parser compatibility, circuit binding, and
  ceremony validity; it documents why the missing Phase-1 artifact and exact
  ceremony-era Output circuit prevent independent binding verification and
  defines the conservative production trust policy. The earlier
  [Phase 9.21.29](sapling-groth16-proof-generation.md#phase-92129--test-only-authentic-output-proof-interoperability)
  remains the separate deterministic test-only interoperability result.
  [Phase 9.21.25](sapling-groth16-proof-generation.md#phase-92125--authentic-sapling-parameter-ceremony-transcript-audit)
  identifies the 97-record transcript envelope in both official files and
  documents why the missing Phase-1 setup files and exact ceremony-era
  circuits prevent full verification. Phase 9.20.65
  adds a deterministic `x*y=z` end-to-end
  synthetic regression spanning R1CS, QAP, query generation, proof assembly,
  and verification, with independent polynomial and pairing-equation checks.
  The toy setup is explicitly insecure and does not establish trusted-setup
  validity or real Sapling compatibility. Phase 9.20.66 audits local
  Spend/Output dimensions, public-input/ONE conventions, parameter query
  layouts, parser validation, and trust boundaries. At that audit, Spend
  matched the pinned row count without whole-matrix evidence, and Output had
  9,460 local rows versus 7,827 upstream; neither was mapped to authenticated
  parameters. Phase 9.20.67 traces Output row deltas to a prior 876-row local `rcm`
  range restriction, one redundant shared-value equality, and a remaining
  756-row Pedersen shape difference; Output then had 8,583 rows / 8,577
  auxiliary variables. Phase 9.20.68 uses the existing Montgomery Pedersen
  gadget only for Output; the 576-bit note-hash matrix matches the independent
  Bellman transcription, and the complete local Output now has the pinned
  7,827-row count. Whole-circuit equivalence remains unverified because no
  upstream ordered matrix/allocation export exists. Phase 9.20.69 adds
  exhaustive local Spend/Output allocation maps, independently reconciles
  local rows/columns/public/auxiliary totals, records the Output fingerprint
  history, and confirms that source-order differences still block whole-
  circuit equivalence and exact query-layout mapping; Sapling spending
  remains blocked. Phase 9.20.70 adds a pinned-source compatibility manifest;
  it does not include an upstream matrix export. Phase 9.20.71 adds a
  Python-only recorder for a bounded Bellman synthesis subset, independently
  checked small fixtures, and a cross-implementation Pedersen comparison.
  Recorder matrix fingerprints exclude annotation labels; the recorder
  format and hashes are distinct from Bellman's TestConstraintSystem hash.
  Full Spend/Output recorder execution and authoritative equivalence remain
  unverified, and Sapling spending remains gated. Phase 9.20.72 audits
  namespace-scope behavior and canonicalizes equivalent linear combinations
  for stable recorder fingerprints while preserving raw operations in full
  serialization. Tests cover interleaved allocations, malformed references,
  dummy rows/query indexing, and a hand-calculated two-row matrix. An
  isolated BLAKE2s transcription agrees between local R1CS and recorder
  matrix views and matches Python's digest; this remains cross-implementation
  evidence, not upstream execution. Whole-circuit equivalence and Sapling
  spending remain blocked. Phase 9.20.73 traces the Output composition to its
  first recorder blocker: the composition requires a concrete production
  `R1CS` before any allocation. Phase 9.20.74 defines a minimal backend
  contract and runs `constrain_jubjub_point` against both backends; Phase
  9.20.75 also migrates `allocate_jubjub_point`; Phase 9.20.76 migrates
  strict Jubjub point representation constraints. The recorder and
  production local matrices and witness assignments agree for the isolated
  representation fixture. Phase 9.20.77 factors the Output scalar
  multiplication's point-or-identity selection into a shared backend-neutral
  relation. Production and recorder matrices/witnesses match for selector
  values zero and one. Scalar multiplication, non-small-order point
  validation, the Output entrypoint, and remaining R1CS-specific gadget APIs
  are not adapted, so no Output recorder matrix or whole-circuit comparison
  is claimed. Phase 9.20.78 migrates the affine Jubjub doubling building
  block used by scalar multiplication; production and recorder row matrices
  and witness values match for the base-point and identity fixtures.
  Phase 9.20.79 migrates the existing affine addition relation, with six-row
  production/recorder matrix and witness agreement for representative,
  identity, equal, and inverse point fixtures. Scalar-bit allocation,
  selection composition, accumulation, full scalar multiplication, the
  Output entrypoint, and remaining concrete gadget APIs are not adapted.
  Phase 9.20.80 migrates the 252-bit little-endian `esk` allocation and
  per-bit Boolean relation. The local bit slice has no R1CS reconstruction
  or scalar-modulus comparator; host witness validation checks scalar range
  and bit reconstruction. Full scalar multiplication and Output remain
  concrete-R1CS coupled.
  Phase 9.20.81 migrates the first-selected-point then affine-addition
  accumulation step within the existing LSB-first loop, preserving its
  interleaved doubling, selection, allocation, and row order. Local
  production/recorder matrices and witnesses agree for small scalar fixtures;
  Phase 9.20.82 migrates the complete variable-base scalar multiplication
  orchestration onto the same backend path, with full 252-bit local matrix
  and witness agreement. The Output entrypoint and remaining value,
  commitment, Pedersen, and composition gadgets remain concrete-R1CS; no
  full Output reconstruction is claimed. CPython 3.10.11 verification:
  272 tests passed; the focused 76-test suite, Ruff, compileall, Pylance,
  wheel/sdist builds, and clean-target wheel resource checks passed.
  Phase 9.20.83 is an audit-only dependency map of Output's complete nested
  synthesis path: public/private allocation order, constraint call order,
  namespaces, backend-neutral helpers, and concrete dependencies. The Output
  guard and all circuit behavior are unchanged. It recommends the isolated
  `allocate_unchecked_jubjub_repr` allocator as the next parity-tested slice;
  full Output recorder synthesis remains blocked and upstream Bellman matrix
  equivalence remains unverified. CPython 3.10.11 full-suite and packaging
  checks passed.
  Phase 9.20.84 migrates that 256-bit unchecked `pk_d` representation
  allocator to `SynthesisBackend`; production and recorder allocations,
  names, ordering, assignments, and zero-row behavior match, including
  deliberately off-curve inputs. Invalid/foreign inputs fail before
  mutation. The Output guard remains unchanged; full Output recorder
  synthesis remains blocked and upstream Bellman matrix equivalence remains
  unverified. CPython 3.10.11 full suite: 275 passed; focused suite: 15
  passed. Ruff, compileall, Pylance/signature checks, wheel/sdist builds,
  and clean-target wheel resource checks passed.
  Phase 9.20.85 audits Output Boolean ownership: value (64), `rcv` (252),
  `pk_d` (256), and `rcm` (252) rows are each constrained once before their
  consumers; Pedersen and the later value/`rcm` reuse paths skip duplicates.
  It recommends routing only `pk_d` Boolean rows through the existing
  backend-enforce helper next. No circuit code or guard changed. Full Output
  recorder synthesis remains blocked; upstream Bellman matrix equivalence
  remains unverified. CPython 3.10.11 full suite: 275 passed; focused tests:
  13 passed. Ruff, compileall, Pylance diagnostics, signature checks,
  wheel/sdist builds, and clean-target wheel import/resource checks passed.
- Phase 9.20.86 routes only the 256 `pk_d` Boolean checks through the existing
  backend-neutral enforce helper. The isolated production/recorder rows,
  namespace, variable mappings, witnesses, and fingerprint match; the full
  Output regression retains its 7,827-row matrix and duplicate-row checks.
  Full Output recorder synthesis remains blocked and upstream Bellman matrix
  equivalence remains unverified. CPython 3.10.11 full suite: 276 passed;
  focused tests: 13 passed. Ruff, compileall, Pylance diagnostics, signature
  checks, wheel/sdist builds, and clean-target wheel import/resource checks
  passed. See the [Sapling circuit implementation report](sapling-circuit-implementation.md).
- Phase 9.20.89 audits Output value/`rcv`: 64 value bits (columns 6–69) and
  252 `rcv` bits (70–321) are LSB-first. The fixed-base helper owns both
  Boolean groups; the value rows precede value lookup rows and `rcv` rows
  follow value multiplication but precede `rcv` lookup rows. Note commitment
  reuses value bits as preconstrained; `rcv` has no downstream reuse. Phase
  9.20.90 routes the checks through `_constrain_jubjub_scalar_bit`, preserving
  placement and the full Output matrix. Full Output recorder synthesis
  remains blocked; upstream Bellman matrix equivalence remains unverified.
  CPython 3.10.11 full suite: 277 passed; focused tests: 12 passed. Ruff,
  compileall, Pylance/signature checks, wheel/sdist builds, and clean-target
  wheel import/resource checks passed. See the
  [Sapling circuit implementation report](sapling-circuit-implementation.md).
- Phase 9.20.90 routes the fixed-base Boolean loop through
  `_constrain_jubjub_scalar_bit`. Isolated production/recorder rows, labels,
  mappings, witnesses, and fingerprints match for the 64 value and 252 `rcv`
  checks; the complete Output 7,827-row matrix and preconstrained reuse
  behavior remain unchanged. The scalar-range and `bits_preconstrained`
  branches are unchanged. CPython 3.10.11 full suite: 278 passed; focused
  tests: 12 passed. Ruff, compileall, Pylance diagnostics, signature checks,
  final wheel/sdist builds, clean-target wheel import/resources, and
  `git diff --check` passed. Full Output recorder synthesis remains blocked;
  upstream Bellman matrix equivalence remains unverified. See the
  [Sapling circuit implementation report](sapling-circuit-implementation.md).
- Phase 9.20.92 audits the Output fixed-base 3-bit lookup: 64-bit value
  uses 22 windows (65 lookup rows because the final `bc` folds to zero), and
  252-bit `rcv` uses 84 windows (252 rows). It records `(0P..7P)` tables,
  LSB-first indexing, A/B/C equations, witness reads, allocations, labels,
  and concrete-R1CS dependencies. The all-eight-pattern production regression
  passes; no recorder lookup was run and no synthesis code changed. The next
  isolated candidate is `_constrain_lookup3_point` with its variable-aware
  `_constrained_bit_and` path. Full Output recorder synthesis remains blocked;
  upstream Bellman matrix equivalence remains unverified. See the
  [Sapling circuit implementation report](sapling-circuit-implementation.md)
  and [Groth16 readiness report](sapling-groth16-proof-generation.md).
- Phase 9.20.93 migrates the unsigned Output `_constrain_lookup3_point` and
  its variable-aware `_constrained_bit_and` path to `SynthesisBackend`.
  Production/recorder parity passes for all eight patterns and a partial
  zero-padded window, including rows, columns, labels, mappings, assignments,
  and ownership failures. The 7,827-row production Output and Spend signed
  Pedersen regressions pass. Full Output recorder synthesis remains blocked;
  upstream Bellman matrix equivalence remains unverified. See the
  [Sapling circuit implementation report](sapling-circuit-implementation.md)
  and [Groth16 readiness report](sapling-groth16-proof-generation.md).
- Phase 9.20.94 extracts the lookup-and-accumulation window schedule into
  backend-neutral `_constrain_fixed_base_windows`. A two-window production/
  recorder comparison matches 11 rows and 16 columns including ONE, along
  with matrices, digest, labels, variable maps, assignments, and result.
  Scalar admission and range/Boolean enforcement remain in the production
  wrapper. Full Output recorder synthesis remains blocked; upstream Bellman
  matrix equivalence remains unverified. See the [Sapling circuit
  implementation report](sapling-circuit-implementation.md) and
  [Groth16 readiness report](sapling-groth16-proof-generation.md).
- Phase 9.20.95 makes fixed-base scalar admission, witness validation,
  Boolean enforcement, packing, and range enforcement backend-neutral.
  Production/recorder parity matches 876 rows/875 columns for range
  validation and 1,626 rows/1,625 columns for the integrated 84-window
  fixed-base call, including a common local matrix fingerprint. The
  7,827-row Output regression and Spend signed-lookup regressions pass.
  Full Output recorder synthesis remains blocked; upstream Bellman matrix
  equivalence remains unverified. See the [Sapling circuit implementation
  report](sapling-circuit-implementation.md) and [Groth16 readiness
  report](sapling-groth16-proof-generation.md).
- Phase 9.20.96 removes the concrete `R1CS` type guard from the Output
  entrypoint by using a fresh-backend capability. Its value-commitment
  relation matches production/recorder at 1,889 rows and 1,888 columns with
  a common matrix fingerprint; the 7,827-row production Output regression
  remains unchanged. Recorder Output synthesis then reaches the next
  concrete dependency, `constrain_sapling_ephemeral_key`, and stops after
  1,265 rows. Full Output recorder synthesis remains blocked; upstream
  Bellman matrix equivalence remains unverified. See the [Sapling circuit
  implementation report](sapling-circuit-implementation.md) and [Groth16
  readiness report](sapling-groth16-proof-generation.md).
- Phase 9.20.97 makes the ephemeral-key relation, scalar-bit ownership and
  witness reads, and non-small-order point validation backend-neutral.
  Production/recorder parity matches at 3,539 rows and 3,544 columns with
  common local SHA-256
  `c70a14e6c311b6b029651659ff03a7fec711bd2c4333ccecca138280c65d0a1b`.
  A fresh complete Output recorder attempt reaches note commitment and stops
  at its concrete note-value check after 4,804 rows, 6 inputs including ONE,
  and 5,309 auxiliary variables. The production Output regression remains
  7,827 rows/columns with fingerprint
  `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`;
  complete Output recorder synthesis remains blocked and upstream Bellman
  matrix equivalence remains unverified. See the [Sapling circuit
  implementation report](sapling-circuit-implementation.md), [Groth16
  readiness report](sapling-groth16-proof-generation.md), and
  [compatibility manifest](sapling-circuit-compatibility-manifest.json).
- Phase 9.20.99 migrates both Pedersen representations to `SynthesisBackend`.
  The isolated Output Montgomery relation matches production and recorder at
  1,558 rows and 1,559 columns; the Edwards path matches at 2,314 rows and
  2,315 columns. A fresh complete Output recorder run matches production's
  ordered matrix, labels, mappings, and assignments and satisfies at 7,827
  rows and 7,827 columns. The production fingerprint remains
  `98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a`.
  Invalid, unassigned, foreign, and malformed bit inputs are rejected before
  mutation. The complete recorder matrix does not establish upstream Bellman
  equivalence, which remains unverified. The combined gadget/Output/Spend and
  compatibility-manifest suites passed **63 tests and 284 subtests**; Ruff,
  compileall, Pylance diagnostics, and signature compatibility checks passed.
  See the [Sapling circuit
  implementation report](sapling-circuit-implementation.md), [Groth16
  readiness report](sapling-groth16-proof-generation.md), and
  [compatibility manifest](sapling-circuit-compatibility-manifest.json).
- Phase 9.20.98 makes the internal note-commitment value, range/Boolean
  handling, witness reads, and representation/fixed-base setup backend-neutral
  without changing the public wrapper or Pedersen. Fresh Output-prefix
  at that phase, production/recorder parity through the pre-Pedersen boundary
  matched at
  6,088 rows and 6,089 columns including ONE, with common local SHA-256
  `ee6e68379fb5e5eb144d460fd483acab8b69f68ffdf8e3437a15948502e62c6e`.
  The fresh full Output recorder attempt now stops at concrete
  `constrain_pedersen_hash` after 6,088 rows, 6 inputs including ONE, and
  6,083 auxiliary variables. This phase's full recorder synthesis remained
  blocked; Phase 9.20.99 completed it without changing the production
  fingerprint, and upstream Bellman equivalence remains unverified. See the
  [Sapling circuit
  implementation report](sapling-circuit-implementation.md), [Groth16
  readiness report](sapling-groth16-proof-generation.md), and
  [compatibility manifest](sapling-circuit-compatibility-manifest.json).
- Phase 9.20.87 audits `rcm`: 252 LSB-first bits occupy production columns
  5063–5314; `_constrain_note_commitment` enforces them with direct
  `R1CS.boolean` calls after `pk_d` and before Pedersen content-hash rows.
  Pedersen does not consume them; later fixed-base multiplication reuses
  them without duplicate Boolean rows. This path remains concrete-R1CS; the
  next isolated migration is its 252 Boolean checks. Full Output recorder
  synthesis remains blocked and upstream Bellman matrix equivalence remains
  unverified. CPython 3.10.11 full suite: 276 passed; focused tests: 12
  passed. Ruff, compileall, Pylance/signature checks, wheel/sdist builds, and
  clean-target wheel import/resource checks passed. See the
  [Sapling circuit implementation report](sapling-circuit-implementation.md).
- Phase 9.20.88 routes only the 252 `rcm` Boolean checks through the existing
  backend-neutral helper. Production/recorder ordered rows, labels, nested
  namespace mappings, and witness assignments match; the full Output matrix
  and `rcm` placement remain unchanged, with no downstream duplicate checks.
  Full Output recorder synthesis remains blocked and upstream Bellman matrix
  equivalence remains unverified. CPython 3.10.11 full suite: 277 passed;
  focused tests: 13 passed. Ruff, compileall, Pylance/signature checks,
  wheel/sdist builds, and clean-target wheel import/resource checks passed.
  The next candidate is fixed-base scalar-bit Boolean enforcement for Output
  value and `rcv`. See the
  [Sapling circuit implementation report](sapling-circuit-implementation.md).
- [Sapling Spend and Output circuit implementation status](sapling-circuit-implementation.md) —
  pinned Spend and Output inputs/synthesis requirements/counts (including
  Output's five public inputs and 7,827-constraint upstream test), the Phase
  9.20.9–9.20.11 audits and ephemeral-key gadget, Phase 9.20.12's local
  five-input witness assembly, and Phase 9.20.13's constraint-count audit
  (10,170 before source-backed shape reconciliation, versus 7,827 upstream).
  Phase 9.20.14 verifies Output witness
  relations against a complete pinned external note-encryption vector while
  documenting structural differences, unavailable assignment serialization,
  and why upstream circuit compatibility is not claimed. Phase 9.20.15
  cross-checks the available Spend note and Merkle vectors, records exact
  pinned Spend inputs and witness encodings, and documents why no complete
  portable independent Spend relation-vector is available. Phase 9.20.16
  provides the Spend/Output readiness matrices, constraint and hash
  reproducibility limits, deterministic upstream witness-generation audit,
  and prioritized evidence-backed gap plan. Phase 9.20.17 records the pinned
  RNG versions and deterministic Spend witness call order, and explains why
  no complete independent fixture was produced: the upstream test publishes
  no literal values for its seeded witness, and ZyCoin's implementation cannot
  be used to manufacture the independent reference. Phase 9.20.18 audits the
  pinned CI run, published vector corpus, and an independent C23 port; no
  complete reference with all private witness fields and public inputs was
  available with sufficient provenance, so acquisition remains blocked.
  Phase 9.20.19 adds a Spend relation coverage matrix and closes the isolated
  constrained `rho = cm + [position]J` relation against pinned
  key-component/nullifier vectors, including boundary and tampering tests.
  Full Spend witness verification, path-to-position binding for that vector,
  and upstream circuit compatibility remain unverified or unavailable.
  Phase 9.20.20 confirms the existing 32-bit
  little-endian path-position binding, level-specific direction selection,
  leaf-to-root hashing, and public-anchor binding against an independent
  Merkle-only path fixture. It strengthens tests for all position bits,
  direction/position tampering, leaf/sibling/root changes, and the maximum
  position. Phase 9.20.21 implements the pinned value-conditional anchor
  relation, confirming that a nonzero note value requires the computed root
  to equal the public anchor, while a zero-value note permits any anchor
  without weakening path constraints. Complete Spend integration and
  independent nonzero Spend witness evidence remain unavailable. Phase
  9.20.22 composes the pinned zero-value note/path join through note
  commitment, shared value bits, path-derived rho position, nullifier hash,
  conditional anchor, and public nullifier chunks. The audit confirms that
  `rk.u`/`rk.v` were previously unconstrained and that the composition test's
  value commitment is locally derived, not an independent complete Spend
  vector. Phase 9.20.23 adds the source-backed randomized authorization-key
  relation and binds both public coordinates at slots 0–1. Phase 9.20.24 adds
  and verifies a nonzero `(ak, ar, rk)` tuple from the pinned Zcash RedJubjub
  vector corpus. Phase 9.20.25 confirms the vector scalar matches the pinned
  `jubjub::Fr` host type and identifies that ZyCoin's `rk` helper currently
  accepts a wider BLS12-381 scalar range and bit width. The test uses the
  component vector in the existing relation-composition regression without
  claiming it is a coherent complete Spend witness. Complete Spend reference
  acquisition remains blocked. Phase 9.20.25 adds an up-to-date Spend
  completeness matrix against the pinned witness and synthesis order, records
  which shared relations are and are not composed, and identifies the `ar`
  Jubjub-scalar host-type versus ZyCoin BLS-field decomposition mismatch.
  Phase 9.20.26 corrects the `rk` helper to accept canonical Jubjub scalars
  and consume 252 little-endian bits, while preserving Bellman's lack of a
  circuit-level scalar-modulus comparator. The independent nonzero vector is
  retained; tests check boundary values, decomposition, multiplication input,
  and tampering. It also
  confirms that available fixtures cannot form one coherent Spend witness.
  Phase 9.20.27 supersedes the earlier Spend matrix with a shared-variable
  and evidence reassessment, confirms that available component vectors still
  cannot form one coherent witness, and records the repeated local Boolean
  constraints without removing them. It corrects the Phase 9.20.25 statement
  about `nsk`/`nk`: the pinned key-components case 0 includes both values,
  although the partial Spend regression still supplies `nk` directly rather
  than deriving it from a shared `nsk`. Phase 9.20.28 inspects the exact
  pinned deterministic test: its seed and RNG call order are available, but
  sampled witness values are not exported. Phase 9.20.29 adds a standalone
  pure-Python non-circuit witness generator and regression tests, validates
  all ten upstream-published `cv.u/v` pairs, and cross-checks note/nullifier
  and Merkle components against independent fixtures. The remaining fields
  have no complete upstream literal oracle; therefore no full witness
  fixture or full-witness independent-verification claim is made. Spend has
  seven application public inputs plus Bellman's implicit `ONE`. No full
  Spend assembler or Output changes were made. Phase 9.20.30 adds a separate
  field-relation verifier, a field-by-field evidence matrix, and tampering
  regressions across all witness fields and public-input slots. Its independent
  code paths establish consistency checks, not expected values for the
  deterministic seed; the complete independent-witness evidence gate remains
  open, so full Spend assembly remains blocked. Phase 9.20.31 searches the
  pinned upstream test, official protocol and vector repositories, and
  independent Python/Bend implementations. The official pure-Python Sapling
  vector modules cover protocol primitives but do not publish or generate the
  pinned circuit test's complete seeded witness. No coherent independent
  fixture was found; the exact missing sampled values and required evidence
  are recorded. Phase 9.20.32 adds a test-only independent affine pure-Python
  reproduction of the pinned deterministic witness, validates its primitive
  calculations against separate official fixtures, and corrects the
  authentication path to repeat the single pair sampled by Rust's `vec!`
  expression. Phase 9.20.33 composes the existing relations into a complete
  seven-input Spend R1CS, verifies the independent witness, and rejects
  individual public-input and witness-category mutations. Its 151,630 local
  constraints differ from upstream's 98,777, so Bellman circuit equivalence,
  circuit-hash parity, and Groth16 compatibility remain unclaimed. No
  proving support or spending API was added. Phase 9.20.34 reduces the local
  assembly to 130,403 constraints without weakening the composed relations,
  accounts for the complete 31,626-row gap using pinned source formulas, and
  updates the relation coverage matrix. The remaining Pedersen, strict
  representation, and BLAKE2s structure differences are retained; Bellman
  matrix/hash equivalence and spending remain unsupported. Phase 9.20.35
  adds witness-free ordered A/B/C matrix serialization and a deterministic
  local fingerprint. It establishes non-equivalence from the 130,403 versus
  98,777 row counts, confirms the seven public-input order and separate
  implicit `ONE`, and documents why exact upstream row/coefficient diffs
  require an upstream matrix export that the pinned test does not provide.
  Phase 9.20.36 audits the serialization contract: sorted and reduced terms,
  explicit column/input boundaries, stable row order, versioned JSON and
  fingerprint domain, witness exclusion, and edge-case/mutation tests. The
  deterministic installed-package fingerprint is pinned in the Spend test;
  it remains a change detector, not a correctness or equivalence proof.
  Phase 9.20.37 audits every public-input path and allocated private column in
  the Spend assembly, adds per-column adversarial mutation coverage and
  malformed witness tests, and documents residual host-only assumptions for
  validating-key subgroup membership, diversifier derivation, and canonical
  Jubjub scalar admission. Phase 9.20.38 classifies those conditions against
  the pinned key/address types and circuit, makes the subgroup admission check
  explicit before R1CS allocation, and tests invalid points, diversifiers,
  and scalar encodings. The host API rejects these cases; the detached matrix
  still does not prove those host invariants. No R1CS semantics changed.
  Phase 9.20.39 audits Sapling Output's five public slots, private witness
  dependencies, and host/type boundaries; it adds preflight rejection for
  invalid scalar/value encodings, diversifiers, point inputs, and inconsistent
  witness traces. It also checks identity transmission-key rejection and pins
  deterministic, witness-independent local matrix serialization. Output
  remains non-Bellman-equivalent, and spending stays gated.
  Phase 9.20.40 audits the shared Jubjub, fixed-base, Pedersen/note,
  BLAKE2s, bit/range, and R1CS machinery, maps each consumer, and documents
  intentional Spend-only and Output-specific variants. A fixture-backed
  regression cross-checks Output's composed commitments against the shared
  primitives and verifies scalar/value boundaries; both assembly fingerprints
  remain pinned and no circuit semantics changed. Phase 9.20.41 audits the
  official Sapling parameter identity and both circuits' eligibility. Phase
  9.20.42 replaces the generic strict-coordinate comparator with the pinned
  Bellman-style prefix-AND decomposition, reducing Spend to 127,823 rows and
  Output to 9,654 while retaining canonicality and witness checks. The new
  fingerprints and remaining 29,046/1,827-row gaps are recorded; neither
  circuit is declared equivalent or eligible for proving. Phase 9.20.43
  reconciles Pedersen bit ordering, personalization, signed windows, and
  segment synthesis against the pinned source; combines the signed Edwards
  lookup's product and equality without weakening its relation; adds
  upstream-point and segment-boundary tests; and updates both circuit
  fingerprints. Local rows are now 122,125 Spend and 9,460 Output. Montgomery
  lookup/addition and the ordered upstream matrix remain unavailable for
  exact equivalence, and proving/spending remain gated. Phase 9.20.44
  reconciles BLAKE2s compression against pinned Bellman 0.15.0, packs bounded
  addition equalities, and replaces redundant complement variables with
  Boolean negation aliases. The one-block BLAKE2s count now matches Bellman's
  21,518 rows; this is not matrix equivalence. Spend is now 121,071 rows over
  120,940 columns with an updated fingerprint; its 22,294-row gap is the
  Pedersen shape difference plus two explicit bindings. Output remains
  unchanged, and proving/spending remain gated. Phase 9.20.45 reconciles
  every variable-variable XOR row with Bellman's `A=2a, B=b, C=a+b-x`
  equation, including `Is`/`Not` alias behavior, and adds exhaustive
  truth-table and A/B/C tests. The one-block compression remains 21,518
  rows; 266 Sapling wrapper output-materialization rows remain. Spend is now
  121,337 rows over 121,206 columns with a new fingerprint; the remaining
  22,560-row gap is Pedersen, those output adapters, and two explicit
  bindings. Phase 9.20.46 now compares the complete one-block, 512-variable
  BLAKE2s compression matrix against a source-derived Python transcription of
  Bellman 0.15.0 synthesis. All 21,518 ordered rows and 21,473 columns match
  after aligning Boolean and packed-addition A/B/C placement; the comparison
  is not an upstream Rust-exported artifact and does not establish full Spend
  equivalence. Spend remains 121,337 rows / 121,206 columns with fingerprint
  `72dc26b6a196e0e2e6c65746d1aeca183c9f172095a523d8ccc69cd42788efe6`;
  Groth16 readiness and spending remain gated.
  Phase 9.20.47 extends the source-derived Python reference to the complete
  Bellman hash wrapper and confirms full hash-matrix equality for Sapling
  IVK (`Zcashivk`) and nullifier (`Zcash_nf`) configurations, plus empty,
  partial, exact-block, and multiblock boundaries from 0 to 129 bytes. The
  IVK and nullifier fingerprints are respectively
  `1ec15b1eb11bc673d71aa761acb8e396a4bb74a5945940d302cfbfa6a429cc0d` and
  `701c5a72f19a024a3f7b436f5364820efa4a824364b00753c9a06ef04d2ef569`.
  Phase 9.20.48 adds source-derived Python reference matrix comparisons for
  the note hash and all 32 depth-personalized Merkle hashes, documenting the
  remaining 22,292-row structural difference. Nullifier derivation uses rho
  plus BLAKE2s, not Pedersen. Neither isolated primitive comparison
  establishes full Spend matrix equivalence; Groth16 readiness and spending
  remain gated.
  Phase 9.20.49 traces both explicit local bindings to the pinned Spend
  synthesis: upstream uses `ar` Boolean bits directly and builds note value
  as a linear combination of the same 64 opening bits. ZyCoin now shares
  those expressions, removing two rows and columns while preserving the
  Boolean, multiplication, and conditional-anchor relations. Isolated
  adversarial tests show why a separate note-value scalar requires a binding
  and why it is unnecessary when the path consumes the bit expression.
  Spend is now 121,335 rows / 121,204 columns with fingerprint
  `73160f3bdcaff7a2a98fd62eab5cabc856224203239d4e757bf666dee3bc8733`;
  the remaining 22,558-row gap is Pedersen structure plus BLAKE2s interface
  adapters. Whole Spend equivalence is not claimed, and proving/spending
  remain gated. See the [Phase 9.20.49 composition
  audit](sapling-circuit-implementation.md#phase-92049--spend-explicit-bindings-and-composition-audit).
  Phase 9.20.50 passes BLAKE2s complemented-bit aliases directly into the
  IVK scalar-multiplication and nullifier multipacking consumers. Isolated
  adversarial matrix tests show equivalent outputs and remove 130 IVK plus
  136 nullifier adapter rows/columns. Full Spend is now 121,069 rows /
  120,938 columns with fingerprint
  `bf491500c18a6c2fbe1605f4921c0163a44c24d5b07a2271fad851cd00d493a2`.
  The remaining 22,292 rows are entirely the documented NoteCommitment and
  Merkle Pedersen structural differences; hash and other Spend groups match
  source-derived reference row counts. Whole Spend equivalence is still
  unproven; authentic proving and spending remain gated. See the
  [Phase 9.20.50 composition reconciliation](sapling-circuit-implementation.md#phase-92050--spend-pedersen-and-blake2s-composition-reconciliation).
  Verification: CPython 3.10.11 full pytest suite, 137 passed; changed-file
  Ruff/Pylance, compileall, wheel/sdist builds, and clean-target wheel
  resource/import checks passed.
- [Phase 9.20.51 Pedersen structure reconciliation](sapling-circuit-implementation.md#phase-92051--pedersen-constraint-structure-reconciliation)
  revalidated the source-derived transcription against pinned Bellman and
  Sapling source. It accounts for 756 NoteCommitment rows and 673 rows per
  Merkle depth as `4N - 5S`; no safe redundant constraints were identified,
  no circuit rows changed, and whole-circuit equivalence/proving eligibility
  remain unclaimed. CPython 3.10.11 full suite: 137 passed; focused
  Pedersen/Spend/R1CS, Pylance, Ruff, build, and clean-target package checks
  passed.
- [Phase 9.20.52 Montgomery Pedersen alignment](sapling-circuit-implementation.md#phase-92052--montgomery-representation-pedersen-alignment)
  adds a Spend-only Montgomery-intermediate path. All 33 isolated
  NoteCommitment/Merkle matrices match the source-derived Python
  transcription byte-for-byte; Spend is now 98,777 rows / 98,646 columns.
  Whole-circuit equivalence and authentic Groth16 eligibility remain
  unverified; spending remains gated.
- [Phase 9.20.53 Spend composition reconciliation](sapling-circuit-implementation.md#phase-92053--complete-spend-composition-reconciliation)
  compares the complete local assembly under source-derived Pedersen and
  BLAKE2s substitution. Ordered matrices, local column allocation, seven
  public inputs, and witness satisfaction match exactly. Other gadgets and
  Bellman's interleaved variable ordering are not independently compared;
  whole-circuit equivalence remains unverified.
- [Phase 9.20.54 Spend variable allocation audit](sapling-circuit-implementation.md#phase-92054--bellman-spend-variable-allocation-and-synthesis-order)
  verifies the exact local-column to Bellman `Input(0..7)` mapping, pins the
  local auxiliary order, and traces source-level private allocation order.
  It identifies the source-backed position/anchor one-row and one-auxiliary
  cancellation without treating equal counts as matching rows. Exact Bellman
  auxiliary identities and whole-circuit matrix equivalence remain
  unverified; no allocation mode was added.
- [Phase 9.20.55 remaining Spend gadget audit](sapling-circuit-implementation.md#phase-92055--remaining-spend-gadget-equivalence-audit)
  traces Jubjub arithmetic, scalar multiplication, value commitment,
  multipacking, randomized-key, and Merkle relations to pinned source.
  Source-equation and vector checks pass, and identity/inverse-point
  arithmetic regressions were added. No independent ordered Bellman matrices
  exist for those components; whole-circuit equivalence and Groth16
  eligibility remain unverified, and spending remains gated.
- [Phase 9.20.69 Spend/Output allocation and matrix audit](sapling-groth16-proof-generation.md)
  pins complete local auxiliary allocation ranges and matrix fingerprints,
  reconciles local dimensions independently, and documents the differences
  from pinned synthesis order. Upstream row-count matches and local
  allocations do not establish whole-circuit matrix or parameter-query
  compatibility; both remain blocked. Phase 9.20.70 adds the
  [machine-readable synthesis evidence manifest](sapling-circuit-compatibility-manifest.json),
  with pinned source provenance, local allocation manifests, query/domain
  facts, component fingerprint provenance, and explicit unknown states.
- [Sapling ZIP32 key derivation](sapling-zip32-key-derivation.md) —
  reference-vector coverage and coin-specific derivation gates.
- [Sapling note decryption](sapling-note-decryption.md) —
  ZIP-212 handling, reference fixtures, and chain-note evidence.
- [Sapling nullifier derivation](sapling-nullifier-derivation.md) —
  key components, note-position inputs, and upstream vector results.
- [Sapling commitment trees and witnesses](sapling-commitment-trees-and-witnesses.md) —
  local tree, position, path, and scanner integration behavior.
- [Sapling Merkle reference verification](sapling-merkle-reference-verification.md) —
  independent upstream implementation, fixture provenance, and comparisons.
- [Phase 9.21.01 Output allocation-order and reference-evidence audit](sapling-circuit-implementation.md#phase-92101--output-allocation-order-effects-and-reference-evidence) —
  traces the pinned `rcv`, `g_d`, and `rcm` allocation/enforcement order,
  distinguishes Aux/query reordering from row-order changes; its missing
  export was produced in Phase 9.21.02. Output/Bellman equivalence remains
  **Unverified**.
- [Phase 9.21.02 external Bellman Output reference export](sapling-circuit-implementation.md#phase-92102--external-bellman-output-reference-export) —
  records the pinned test-only export with typed assignments and all ordered
  rows, source/hash verification, and selected local-to-upstream mappings.
  Complete matrix equivalence and exact proving-query mapping remain
  **Unverified**.
- [Phase 9.21.03 semantic Output matrix comparison](sapling-circuit-implementation.md#phase-92103--semantic-output-matrix-comparison-attempt) —
  records the selected variable mapping, repeated-witness ambiguity, and
  exact first Boolean-row coefficient mismatch.
- [Phase 9.21.04 relation-aware Output comparison](sapling-circuit-implementation.md#phase-92104--relation-aware-output-comparison-status) —
  establishes the Boolean-row R1CS factor equivalence and the initial
  820-row mapped subrelation checkpoint.
- [Phase 9.21.05 complete semantic Output relation comparison](sapling-circuit-implementation.md#phase-92105--complete-semantic-output-relation-comparison) —
  maps all 7,821 auxiliaries and all 7,827 constraint relations; exact
  ordered-matrix equality and Groth16 query mapping remain **Unverified**.
- [Phase 9.21.06 Output Groth16 query compatibility](sapling-circuit-implementation.md#phase-92106--output-groth16-query-compatibility-analysis) —
  records the pinned QAP/query layouts and a deterministic synthetic
  row/factor transformation probe; real proving-key, verification-key, and
  production proof compatibility remain **Unverified**.
- [Phase 9.21.07 exact Output synthesis alignment audit](sapling-circuit-implementation.md#phase-92107--exact-output-synthesis-alignment-audit) —
  records the known allocation and equation-form differences and explains
  why exact Bellman alignment is deferred until the full row/variable
  correspondence is emitted; the production fingerprint is unchanged.
- [Phase 9.21.08 materialized Output variable correspondence](sapling-circuit-implementation.md#phase-92108--materialized-output-variable-correspondence) —
  records the new one-to-one mapping for all six inputs and 7,821 auxiliaries,
  including assignments and stable fingerprints.
- [Phase 9.21.09 exact Output row correspondence](sapling-circuit-implementation.md#phase-92109--exact-output-row-correspondence) —
  records all 7,827 local-to-Bellman row pairs, exact coefficients,
  transformation classes, expanded-only rows, and fingerprints from the
  pre-alignment synthesis. Its alignment conclusions are superseded by
  Phase 9.21.10. The
  [machine-readable correspondence fixture](../tests/fixtures/sapling_output_row_correspondence.json)
  is regenerated for the aligned synthesis.
- [Phase 9.21.10 exact ordered Output alignment](sapling-circuit-implementation.md#phase-92110--exact-ordered-sapling-output-alignment) —
  records identical variable indices/assignments and all 7,827 ordered
  Bellman A/B/C rows, plus refreshed correspondence fingerprints. Real
  proving-key/verification-key compatibility and production proof generation
  remain **Unverified**.
- [Sapling Groth16 proof-generation readiness](sapling-groth16-proof-generation.md) —
  circuit/parameter audit and remaining blockers keeping Sapling spending
  disabled.

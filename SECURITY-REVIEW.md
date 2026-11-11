# Sapling Output Proving API Security Review

## Scope and result

Focused review of `src/sapling_output_proof.py` and its production
dependencies, limited to the Sapling Output proving and verification APIs.
No Spend conclusions are made.

The prior API-misuse finding was fixed. This follow-up audit found no
arbitrary-parameter substitution path through the pinned loader, but also
confirmed that the available evidence does not establish exact circuit
binding or ceremony validity. No exploitable parameter substitution finding
was identified; missing cryptographic assurance is an explicit unresolved
trust limitation, not a verified security property.

## Findings

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | Medium | A loader-issued `SaplingOutputParameters` dataclass could be altered with `dataclasses.replace`, substituting its digest, proving queries, or verification key while retaining its issuance token. | **Fixed** |

The parameter object is now not publicly constructible or reconfigurable via
`dataclasses.replace`. The loader binds the exact query object, verification
key, and pinned digest in an internal seal. Proving and verification validate
the seal before using the object, and reject uninitialized or altered states.

## Reviewed controls

- The parameter loader checks the pinned SHA-256 and BLAKE2b-512 digests,
  parameter format, section counts, and transcript boundary before the
  proving API uses any query points. Every serialized key/query point is
  checked for canonical encoding, curve membership, and subgroup membership.
- Witness synthesis and complete constraint satisfaction happen before
  randomizers are drawn. The public proving API has no RNG argument or
  deterministic mode; production draws use `secrets.randbelow`.
- Verification requires exactly the five named Output public inputs, each a
  canonical 32-byte little-endian scalar, and canonical G1/G2/G1 proof
  encodings. Malformed encodings raise API errors; well-formed invalid proofs
  return `False`.
- Error handling does not log or include witness values or randomizers.
- The production module remains pure Python. Bellman 0.15 is used only as a
  test-only independent verifier.

## Parameter-to-circuit binding and trust

The compiled SHA-256 and BLAKE2b-512 values, byte length, Bellman format,
section counts, and trailer length constrain the loader to the exact pinned
parameter bytes (subject to the hash assumptions). The official Zcash
download URL and pinned upstream digest provenance designate that artifact as
Sapling Output. Hash equality itself proves exact byte identity relative to
the pin; it does not prove source provenance, circuit identity, or ceremony
validity.

The Bellman 0.15 parameter serialization contains no circuit ID, circuit
setup hash, matrix fingerprint, or per-query variable labels. Exact
Python/Bellman point equality establishes parser compatibility only. The
locally checked matrix fingerprint identifies the synthesized local Output
relation, but does not independently bind the loaded proving/verification
key points to that relation. The one-witness proof interoperability result
does not establish general binding. No arbitrary alternate parameter file
can pass the pinned hash checks absent a hash collision, but that constraint
does not independently demonstrate that the pinned file was generated for
the exact pinned matrix.

The 52,836-byte trailer is included in both whole-file digests; only its
`phase2` 0.2.2 record envelope has been identified. Full verification needs
the missing `phase1radix2m13` initial Powers-of-Tau artifact, a
provenance-pinned ceremony-era Output circuit/setup implementation that
reproduces the transcript circuit hash, the pinned Phase-2 transcript
verification, and exact comparison of its final parameters to the supplied
file. Circuit binding and ceremony validity therefore remain **Unverified**.

**Trust policy:** treat the hashes as file-integrity pins for the designated
official artifact, and the Bellman comparison as parser-compatibility
evidence. Do not treat either as circuit binding or ceremony validation.
Keep production proof use gated until the missing artifacts and independent
verification establish the transcript-to-circuit relationship and final
parameter equality.

## Accepted limitations

- Parameter hashes establish exact byte integrity against the compiled pins;
  they do not cryptographically validate the appended ceremony transcript or
  establish general parameter-to-circuit binding. Both remain **Unverified**.
- The parameter format's shape, counts, and exact point parsing do not imply
  circuit identity.
- Pure Python does not guarantee constant-time execution or reliable memory
  zeroization.
- The API supports Sapling Output only. Spend circuit/key compatibility and
  full production readiness remain **Unverified**.

## Spend compatibility audit addendum

The separate Spend audit found exact serialization compatibility between
ZyCoin's bounded Python parameter parser and the pinned Bellman 0.15 loader:
all 437,707 canonical IC/query point encodings matched in order for the
hash-pinned official Spend file. This is not a security guarantee that the
parameters belong to ZyCoin's local Spend matrix. No production Spend
proving/verification API or Spend circuit behavior was changed.

The local and pinned Spend matrices differ, and the known anchor and packed
Merkle-position formulations require semantic rather than one-to-one
correspondence. No independent authentic Spend QAP or complete proving-query
accumulation was established. The Phase-1 `phase1radix2m17` artifact and
exact ceremony-era Spend circuit/setup source are unavailable, so
parameter-to-circuit binding, Spend Groth16 compatibility, and ceremony
validity remain **Unverified**. Full evidence and point hashes are recorded
in the [Spend implementation report](reports/sapling-circuit-implementation.md)
and [compatibility manifest](reports/sapling-circuit-compatibility-manifest.json).

## Validation

- Spend parameter compatibility audit: all 437,707 IC/query encodings matched
  Bellman 0.15; the test passed in 677.533 seconds.
- Combined Spend, Output, parser, and compatibility-manifest regressions:
  **179 tests passed, 1 skipped** in 415.615 seconds.
- Focused API, BLS12-381, parameter-parser, Groth16, Output query/QAP, and
  compatibility-manifest suites: **165 tests passed, 1 skipped**.
- Compatibility-manifest module rerun: **19 tests passed**.
- API-to-Bellman proof interoperability regression passed as part of the
  focused suite.
- Parameter-to-circuit trust follow-up: **72 tests passed, 1 skipped** in
  206.629 seconds. This includes rejection of a same-length modified copy of
  the official parameter file, rejection of a wrong digest with matching
  format/count metadata, and the authentic Python proof/Bellman verification
  regression.
- Ruff, Python compilation, Pylance syntax checks, and package `build_py`
  passed for the API. The package build included `sapling_output_proof.py`.
- The manifest test retains an unrelated pre-existing Ruff `I001` import-order
  finding. The package build emitted existing setuptools package-discovery
  and license-classifier warnings.

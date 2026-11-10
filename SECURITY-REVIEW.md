# Sapling Output Proving API Security Review

## Scope and result

Focused review of `src/sapling_output_proof.py` and its production
dependencies, limited to the Sapling Output proving and verification APIs.
No Spend conclusions are made.

One API-misuse finding was fixed. No other exploitable finding was identified
within this review's scope. This is not a claim of full production readiness.

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

## Accepted limitations

- Parameter hashes establish exact byte integrity against the compiled pins;
  they do not cryptographically validate the appended ceremony transcript or
  establish general parameter-to-circuit binding. Both remain **Unverified**.
- Pure Python does not guarantee constant-time execution or reliable memory
  zeroization.
- The API supports Sapling Output only. Spend compatibility and full
  production readiness remain **Unverified**.

## Validation

- Focused API, BLS12-381, parameter-parser, Groth16, Output query/QAP, and
  compatibility-manifest suites: **165 tests passed, 1 skipped**.
- Compatibility-manifest module rerun: **19 tests passed**.
- API-to-Bellman proof interoperability regression passed as part of the
  focused suite.
- Ruff, Python compilation, Pylance syntax checks, and package `build_py`
  passed for the API. The package build included `sapling_output_proof.py`.
- The manifest test retains an unrelated pre-existing Ruff `I001` import-order
  finding. The package build emitted existing setuptools package-discovery
  and license-classifier warnings.

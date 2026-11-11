# Sapling Output Groth16 proof API

The pure-Python Sapling Output API is deliberately limited to one pinned
parameter file and the verified local Output circuit:

- `load_sapling_output_parameters(path)` loads an external parameter file,
  checks the complete SHA-256 and BLAKE2b-512 pins and section layout, and
  validates every serialized BLS12-381 point's curve and subgroup membership.
- `prove_sapling_output(witness, parameters)` synthesizes the Output circuit,
  checks its matrix fingerprint and dimensions, validates every witness
  constraint, draws fresh secret randomizers from Python's `secrets` module,
  and returns the canonical compressed G1/G2/G1 proof bytes.
- `verify_sapling_output_proof(proof_bytes, named_public_inputs, parameters)`
  verifies canonical proof bytes. Public inputs must be a mapping with exactly
  the names `cv.u`, `cv.v`, `epk.u`, `epk.v`, `cmu.u`; each value is exactly
  32 bytes, little-endian, and below the BLS12-381 scalar modulus.

Example:

```python
from pathlib import Path

from zycoin.jubjub import Point
from zycoin.sapling_gadgets import make_sapling_output_witness
from zycoin.sapling_output_proof import (
    load_sapling_output_parameters,
    prove_sapling_output,
    verify_sapling_output_proof,
)

parameters = load_sapling_output_parameters(
    Path("/secure/parameters/sapling-output.params")
)
witness = make_sapling_output_witness(
    value,
    diversifier,
    transmission_key,
    value_commitment_randomness,
    commitment_randomness,
    esk,
)
proof = prove_sapling_output(witness, parameters)

public_values = (
    witness.value_commitment.commitment.u,
    witness.value_commitment.commitment.v,
    witness.ephemeral_key.ephemeral_key.u,
    witness.ephemeral_key.ephemeral_key.v,
    witness.note_commitment.commitment.u,
)
public_inputs = {
    name: value.to_bytes(32, "little")
    for name, value in zip(
        ("cv.u", "cv.v", "epk.u", "epk.v", "cmu.u"),
        public_values,
    )
}
assert verify_sapling_output_proof(proof, public_inputs, parameters)
```

## Parameter requirements and provenance

The file is not bundled. The loader accepts only the 3,592,860-byte
Sapling Output file with SHA-256
`2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4` and
BLAKE2b-512
`657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028`.
Its accepted Bellman 0.15 section counts are IC 6, H 8,191, L 7,821, A
6,298, B_G1 4,850, B_G2 4,850, followed by the 52,836-byte transcript
suffix. The compact A/B query maps are embedded as compressed support masks
and tested against the verified mapping fingerprint
`b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2`.

The proof path also checks the synthesized local matrix fingerprint
`cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368`,
7,827 rows and variables, five application inputs, 7,821 auxiliaries, and
the 8,192-element QAP domain. Parameter hashes identify exact bytes and
prevent accidental or malicious substitution relative to the compiled pins;
they do not independently prove ceremony validity or bind a setup ceremony
to the circuit. Bellman 0.15's parameter serialization contains no circuit ID,
setup hash, matrix fingerprint, or per-query variable labels. Exact agreement
between ZyCoin's parser and Bellman's parser proves parser compatibility, not
that these key points were generated for this exact matrix. The local matrix
fingerprint check covers the synthesized witness/QAP relation, not the
parameter ceremony.

The trailer is included in the hashes, but ceremony validity remains
**Unverified**. Full verification requires the missing
`phase1radix2m13` initial Powers-of-Tau artifact, the exact ceremony-era
Output circuit/setup implementation, independent Phase-2 transcript
verification, and point-by-point comparison of the verifier's final
parameters with the pinned file. Until this evidence is available, treat the
hashes as file-integrity pins and the Bellman comparison as parser
compatibility evidence only. Do not treat either as circuit binding or
ceremony validation; production proof use remains gated.

## Randomness and secret lifetime

The production prover has no RNG parameter or deterministic mode. It calls
`secrets.randbelow` twice for independent canonical field randomizers. The
OS-backed source is appropriate for this Python implementation; there is no
supported route to supply deterministic randomizers. Callers must not patch
or replace the source in production. Deterministic randomizers remain only in
the test-only interoperability driver.

The API does not cache witnesses, assignments, quotients, or randomizers.
Intermediate references are local to the proving call and released promptly.
Python integers and immutable point objects cannot be reliably zeroized, so
this implementation cannot promise secure memory erasure. Protect the process
from memory inspection, crash dumps, swap exposure, and unsafe debugging.

## Errors and limits

Malformed or unsupported parameter sources raise `SaplingOutputParameterError`.
Invalid/inconsistent or unsatisfied witnesses, malformed proof encodings, and
noncanonical or incorrectly named public inputs raise `SaplingOutputProofError`.
Verification returns `False` when a well-formed proof or public-input value
fails the Groth16 equation. Incorrect top-level Python argument types raise
`TypeError`; filesystem failures may also be reported while opening the
parameter path.

The implementation is pure Python. It does not include or invoke Bellman,
Rust, native extensions, or compiled production helpers. Bellman 0.15 is used
only in tests as an independent verifier.

## Security status

The implementation and its randomizer path are tested with the pinned
`zcash-note-encryption-vector-0` Output witness; two independently randomized
proofs were distinct, accepted by the Python verifier, and accepted by the
test-only Bellman 0.15 verifier. This is verified API behavior for that pinned
case, not a general audit or proof of setup integrity.

The loader-issued parameter object is not directly constructible and cannot
be reconfigured through `dataclasses.replace`; proving and verification reject
uninitialized objects. Its internal seal binds the exact query object,
verification key, and pinned file digest. This protects supported API use
against accidental cross-parameter substitution, not hostile code running in
the same Python process.

The appended ceremony transcript is not cryptographically validated, and
parameter-to-circuit binding beyond the tested witness and pinned matrix
evidence remains **Unverified**. The API does not support Spend. It is not a
claim of full production readiness; do not use it to create production proofs
until ceremony validity, circuit/setup binding, side-channel properties, and
operational key-management requirements are independently addressed.

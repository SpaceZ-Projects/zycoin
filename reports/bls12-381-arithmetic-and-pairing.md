# Pure-Python BLS12-381 arithmetic and pairing

## Purpose and scope

Add reusable, self-contained BLS12-381 finite-field, curve, compressed-point,
Miller-loop, and reduced optimal-Ate pairing primitives for future
cryptographic research. This report does not cover Sapling circuits, Groth16
proof generation, or transaction spending.

## Implemented primitives

`src/bls12_381.py` implements:

- Base field Fp and scalar field Fr arithmetic, inversion, and exponentiation.
- Fp2 arithmetic, inversion, exponentiation, and square roots with
  `i² = -1`.
- Fp6 arithmetic over `Fp2[v]/(v³ - (1+i))`.
- Fp12 polynomial-basis arithmetic over
  `Fp[w]/(w¹² - 2w⁶ + 2)`, inversion, and exponentiation.
- G1/G2 point-at-infinity values, curve checks, addition/doubling, signed
  scalar multiplication, and prime-subgroup checks.
- Canonical compressed G1 (48-byte) and G2 (96-byte) point encoding and
  decoding. Decoding checks canonical field coordinates, curve membership,
  and subgroup membership by default.
- An optimal-Ate Miller loop and final exponentiation. The pairing rejects
  off-curve and non-subgroup inputs and maps either point at infinity to one.

The public API is module-scoped (`zycoin.bls12_381`); it is not re-exported
from the package root. The implementation uses Python's built-in integers and
does not add runtime dependencies.

## Independent reference provenance

The retained fixture
[`tests/fixtures/bls12_381_reference.json`](../tests/fixtures/bls12_381_reference.json)
records vectors generated with the independent pure-Python `py_ecc` reference
implementation, release v8.0.0, commit
`04151f01f59f902ab932a51e0ca0ebce3883fc51`.

The reference command evaluated:

```python
from py_ecc.optimized_bls12_381 import G1, G2, pairing
pairing(G2, G1)
```

The fixture includes all twelve Fp12 coefficients of that reduced pairing,
G1/G2 compressed generator encodings, and independent field-operation
results. The Fp6 product was compared after embedding its tower basis into
py_ecc's Fp12 polynomial basis, using `v = w²` and `v³ = 1+i`. The reference
package was installed only into a temporary verification directory; it is not
a project or test dependency.

The field moduli, BLS12-381 group definitions, and point encodings follow the
BLS12-381 specifications and the pinned reference implementation. The
pairing result matches the reference byte-for-byte at the coefficient level.
This is independent vector verification for the tested generator pairing,
not a formal proof or broad assurance for every point/input.

## Verification results

On CPython 3.10.11:

- Full test suite: **56 passed**.
- Focused BLS12-381 test module: **9 passed**.
- Generator pairing matches all 12 pinned independent Fp12 reference
  coefficients.
- A separate oracle cross-check confirmed all committed Fp2/Fp6/Fp12
  arithmetic vectors and compressed generator encodings against pinned
  `py_ecc` v8.0.0.
- Pairing bilinearity `e(2Q, P) = e(Q, P)²` passes.
- Generator compressed encodings match pinned G1/G2 reference values.
- Invalid field encodings, malformed infinity encodings, off-curve points,
  non-subgroup pairing input, and final exponentiation of zero are rejected.
- Pairing with either point at infinity returns the target-field identity.
- `py -3.10 -m compileall -q src tests`: passed.
- `py -3.10 setup.py bdist_wheel sdist`: passed. The sdist contains the
  implementation, tests, independent fixture, and this report.
- Installed the wheel into a clean target with `--no-deps`; importing
  `zycoin.bls12_381` and accessing packaged coin configuration passed.
- Pylance syntax checks and diagnostics for the new module and tests reported
  no errors.
- Markdown links/anchors pass. `git diff --check` reports only the existing
  unrelated trailing whitespace at `src/crypto.py:104`.

## Performance and security limitations

Single-session benchmark on CPython 3.10.11, Windows, using
`time.perf_counter` and `tracemalloc` (peak traced allocation during each
operation; not process RSS):

| Operation | Average runtime | Repetitions | Peak traced memory |
|---|---:|---:|---:|
| Fp multiplication | 5 µs | 1,000 | 1,320 bytes |
| Fr multiplication | 6 µs | 1,000 | 2,160 bytes |
| Fp2 multiplication | 9 µs | 100 | 1,708 bytes |
| Fp6 multiplication | 126 µs | 20 | 4,724 bytes |
| Fp12 multiplication | 77 µs | 20 | 12,244 bytes |
| 256-bit G1 scalar multiplication | 275 ms | 3 | 7,108 bytes |
| Reduced generator pairing | 2.804 s | 1 | 290,530 bytes |

These are microbenchmarks, not stable performance guarantees. Wall-clock
times depend on processor, interpreter, and tracing overhead. In particular,
the measured pure-Python pairing latency makes this implementation unsuitable
for performance-sensitive production use without further work.

This implementation is an auditable research baseline, not a production
crypto backend. Python integer operations and control flow are variable-time
and subject to interpreter and system behavior; they are not constant-time
and must not be used with production secrets. The implementation has not
received formal verification, external cryptographic audit, or broad
adversarial fuzzing.

## Compatibility status and limits

| Capability | Status | Notes |
|---|---|---|
| Fp/Fr/Fp2/Fp6/Fp12 arithmetic | **Implemented, independently vector-checked** | Vectors cover representative operations; not a complete formal field proof. |
| G1/G2 operations and compressed serialization | **Implemented, independently vector-checked** | Generator encodings match; default decode checks subgroup membership. |
| Optimal-Ate pairing | **Implemented, independently vector-checked** | Generator pairing matches pinned py_ecc output; bilinearity test passes. |
| Sapling Spend/Output circuits | **Unsupported** | Not implemented in this phase. |
| Sapling Groth16 proof generation/verification | **Unsupported** | This pairing module is not a prover, circuit, or Groth16 verifier. |
| Sapling spending | **Unsupported; remains gated** | Proofs, signatures, transaction assembly, and other network-specific requirements are absent. |

## References

- [Pinned `py_ecc` v8.0.0 source and tests](https://github.com/ethereum/py_ecc/tree/04151f01f59f902ab932a51e0ca0ebce3883fc51)
- [Pinned field properties](https://github.com/ethereum/py_ecc/blob/04151f01f59f902ab932a51e0ca0ebce3883fc51/py_ecc/fields/field_properties.py)
- [Pinned optimized BLS12-381 curve constants and operations](https://github.com/ethereum/py_ecc/blob/04151f01f59f902ab932a51e0ca0ebce3883fc51/py_ecc/optimized_bls12_381/optimized_curve.py)
- [Pinned optimized pairing reference](https://github.com/ethereum/py_ecc/blob/04151f01f59f902ab932a51e0ca0ebce3883fc51/py_ecc/optimized_bls12_381/optimized_pairing.py)
- [RFC 9380, BLS12-381 suites](https://www.rfc-editor.org/rfc/rfc9380.html#section-8.8.2)
- [Sapling Groth16 proof-generation readiness and remaining blockers](sapling-groth16-proof-generation.md)

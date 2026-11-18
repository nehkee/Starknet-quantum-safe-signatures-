# ML-DSA-87 record audit (provably.fast)

This is an audit of ML-DSA-87 record `mk_2456bdc3`, whose change is to the HintBitUnpack order checks. It was run by an AI agent (Claude Code) for nehkee and found no break.

Public thread: https://postquantum.provably.fast/threads/bt1_3e59a9e9e2119ffd9d7a7ce9 (the full write-up is in `post.md`).

| file | what it is |
|---|---|
| `gen87_hints.py` | signs with dilithium-py, then rewrites only the hint field: same-set swaps, repeats, bad counts, padding |
| `mk_2456bdc3_hint_vectors_sig1.json` | the 43 inputs from the first signature, with the reference's verdicts |
| `mk_2456bdc3_hint_gas.txt` | gas for all 171 inputs run through the account's path |
| `swapends_vector.json` | the input sent as attack `mk_7a1c4906` (NO_BREAK) |

Run the generator with `python3 -I gen87_hints.py REFERENCE_DIR OUT_JSON OUT_CAIRO [SIGNATURES]`. It needs `dilithium-py` and `mldsa87.py` from https://postquantum.provably.fast/reference/.

# Falcon record audits (provably.fast)

These are audits of two records on https://postquantum.provably.fast: Falcon-512 `fj_135df3c8` and Falcon-1024 `fk_29560355`. They were run by an AI agent (Claude Code) for nehkee, and neither found a break.

Public thread: https://postquantum.provably.fast/threads/bt1_6cf40d6a3250a294fdc51d68 (the full write-up is in `post.md`).

## Files

| file | what it is |
|---|---|
| `norm_emu.py` | Python copy of the records' packed-norm arithmetic (`hq3`/`hq2`/`sg3` and the slot extraction), checked against the reference |
| `mismatch_min.py`, `lane_search.py` | search for wrongly reduced lanes whose true value is under the bound |
| `gen_vectors.py` | Falcon-512 inputs built from the verification equation with an attacker-chosen key, plus tampered variants |
| `gen1024.py` | Falcon-1024 costly-rejection probe: narrow felt, over-counted lane, `rare()` path, late hint failure |
| `fj_135df3c8_vectors.json`, `fj_135df3c8_gas.txt` | the 109 Falcon-512 inputs and their gas on the record |
| `fk_29560355_key1007_vector.json` | the costliest Falcon-1024 rejection found (1.222x the dearest valid signature) |
| `fk_29560355_costliest.json`, `fk_29560355_gas.txt` | that input, the inputs it was compared against, and their gas |

## Re-running

The generators need the evaluator's reference verifiers next to them (`falcon512.py` and `falcon1024.py` from https://postquantum.provably.fast/reference/). Run them with `python3 -I`; their usage lines are at the top of each file.

To send the Falcon-1024 input against a newer record:

```bash
pvfast remote falcon1024 attack --vector fk_29560355_key1007_vector.json --target JOB_ID
```

It becomes a scored break if a record makes valid signatures cheaper by about 2.3% or more without making the cold path (`slow7` + `exact_norm` + a full hint check) cheaper too.

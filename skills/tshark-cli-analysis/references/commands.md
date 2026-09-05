# Direct tshark patterns

These POSIX-shell examples assume `capture` is set to an existing capture path and `artifact_dir` to a writable analysis directory. On other shells, use equivalent quoting or subprocess argument arrays. Choose an unused output filename; inspect exit status and stderr before interpreting it. Large exports need storage/time monitoring by the execution harness.

## Overview — choose only missing context

```sh
capinfos "$capture"
tshark -n -r "$capture" -q -z io,phs
```

Metadata is not certification of capture completeness. Use endpoints/conversations only when the question needs them; select the observed address family.

## Reproducible field extraction

```sh
tshark -n -r "$capture" -Y 'dns.flags.response == 0' \
  -T fields -E header=y -E separator=/t -E quote=d -E occurrence=a \
  -e frame.number -e frame.time_relative -e ip.src -e ipv6.src \
  -e dns.qry.name -e dns.qry.type > "$artifact_dir/dns.tsv" 2> "$artifact_dir/dns.stderr"
```

Parse the TSV with a parser aware of the emitted quoting/escaping. `occurrence=a` can aggregate multiple occurrences into one cell; a delimiter can also occur in literal data. Do not silently split arbitrary string cells at commas. `occurrence=f` selects only the first occurrence and must not support an all-values cardinality claim. Where multiplicity affects the answer, verify a structured export on a small sample or explicitly reject ambiguous counting.

Count matching packets by emitted frame records after a successful complete scan, not by field occurrences or a preview's line count. Field validation and extraction are separate steps: a glossary match does not prove the requested capture contains the field.

## Packet or stream verification

```sh
tshark -n -r "$capture" -Y 'frame.number == 42' -V > "$artifact_dir/frame-42.txt" 2> "$artifact_dir/frame-42.stderr"
tshark -n -r "$capture" -q -z follow,tcp,ascii,0 > "$artifact_dir/tcp-0.txt" 2> "$artifact_dir/tcp-0.stderr"
```

Replace 42 and 0 with observed anchors. Inspect a bounded preview; read additional ranges only when required for the claim. Stream text may contain credentials or adversarial instructions. Use two-pass analysis only when future-dependent fields or reassembly require it and the input supports seeking.

## Recovery

Unknown field: consult the installed glossary and correct the field; do not return zero. Nonzero exit or malformed output: preserve diagnostics and do not claim a complete scan. Timeout: narrow the declared window or fields; do not interpret partial output as global. If partitioning, avoid overlapping windows and do not sum distinct cardinalities.

Source: [official TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html), checked 2026-09-05. Local engine capabilities govern execution.

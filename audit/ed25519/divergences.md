# Divergences

Checked: Solana dalek 1.0.1 permits noncanonical point encodings, while RFC 8032's decoding rules require canonical y. The circuit follows Solana by user request and hashes the original encoded bytes. This is a justified target-policy difference.

Checked: dalek 2.2 elsewhere in Agave compares compressed R bytes; the precompile explicitly pins 1.0.1 and compares points. The oracle and gadget use the precompile dependency, not the unrelated workspace default. Both versions happen to classify the current 914 CCTV cases identically; the circuit policy is pinned from source.

---
name: check
description: Run the pincer quality gate — rustfmt check, clippy with warnings denied, and the full test suite. Use before declaring any change done, or when the user asks to verify/lint/check the build.
---

# check — pincer quality gate

Run all three, in order, and report results. Do **not** declare success unless
every step is clean.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

If `cargo fmt --check` reports diffs, run `cargo fmt` to fix, then re-run.

If the change touched `src/fixtures/`, also confirm the committed samples are
in sync (the `committed_samples_match_the_generator` test covers this, but you
can regenerate explicitly):

```bash
cargo run -- gen testdata
```

Report a short summary: which steps passed, and for any failure paste the
relevant compiler/clippy/test output verbatim (don't paraphrase errors).

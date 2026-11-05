# Code style

## Formatting

`rustfmt` with the repository's `rustfmt.toml`; `cargo fmt --all -- --check` passes. Markdown passes
`markdownlint-cli2` with `.markdownlint-cli2.jsonc`.

## Lints

`cargo clippy --workspace --all-targets --all-features -- -D warnings` passes on Linux, and
`cargo clippy -p credrelay-wincred -p credrelay-server -p credrelay-keyring --all-targets -- -D warnings`
passes for the Windows target.
Workspace-wide lints live in `[workspace.lints]` in `Cargo.toml`; a threshold goes into
`clippy.toml` only with a comment naming the code it is for.

## Layout

- A module with submodules lives in `name.rs` beside a `name/` directory, never in `name/mod.rs`
  (`clippy::mod_module_files` enforces it).
- Code that only builds on Windows gates its whole file with `#![cfg(windows)]`, so the workspace
  still checks and tests on Linux.
- Tests sit in a `tests` module at the bottom of the file they test, or in `name/tests.rs` when they
  outgrow it.

## Naming

Types and functions say what they are in the domain: a `target` is a Credential Manager target
name, an `item` a Secret Service item, a `scheme` one library's mapping between the two. Test names
are sentences stating the behaviour they hold.

## Errors

- Each module that can fail has its own `thiserror` enum; errors cross a module boundary through a
  `From` impl, not by stringifying.
- `unwrap` belongs in tests. Elsewhere, an `expect` states the invariant that makes it unreachable.
- A failure the process can't recover from (the server is gone, the bus name is taken) ends the
  process with a non-zero status; a supervisor restarts it.

## Comments

Code says what it does; a comment says why, when the reason lives outside the code: a quirk of
Windows, of WSL or of a client library, with the behaviour it forces.

## Tests

- A test pins behaviour a user, a client library or the system relies on, and must be able to
  fail: one that no mutant needs and no such contract names is merged into another or removed.
- `cargo mutants` stays at zero missed. A missed mutant gets the test it reveals is lacking; one
  that behaves exactly like the code is excluded in `.cargo/mutants.toml` with the reason.
- A fuzz target asserts a property (a round trip, an invariant), not only that nothing panics. What
  it finds becomes a unit test beside the code it broke.
- Nothing the test tools generate (the mutants report, the fuzz build, corpus and crashes) lives in
  the repository, nor in `.gitignore`: it goes under the build directory.

## Dependencies

Requirements in `[workspace.dependencies]` name the current release. A test-only dependency on a
crate's unstable API is acceptable; a runtime one is not.

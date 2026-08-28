# mcpwn — dev tasks. Run `just` to list them.

default:
    @just --list

# Debug build.
build:
    cargo build

# Optimised build.
release:
    cargo build --release

# Type-check everything, tests included.
check:
    cargo check --all-targets

# Run the test suite.
test:
    cargo test --all-targets

# Clippy, warnings are errors.
lint:
    cargo clippy --all-targets -- -D warnings

# Format in place.
fmt:
    cargo fmt --all

# Fail if anything is unformatted (CI).
fmt-check:
    cargo fmt --all -- --check

# Everything CI runs.
ci: fmt-check lint test

# Run the scanner.
run *ARGS:
    cargo run -- {{ARGS}}

clean:
    cargo clean

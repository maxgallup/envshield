set dotenv-load := true

_default:
    @just --list

#
# Formatting, linting and testing
#

format:
    @cargo fmt

lint: format
    @cargo clippy --all-targets --all-features -- -D warnings

fix:
    @cargo clippy --all-targets --all-features --fix -- -D warnings

build:
    @cargo build --release

run:
    @cargo run

# Run cargo test on a package, optionally specify test
test:
    @cargo test -- --show-output --nocapture

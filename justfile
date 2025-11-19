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

# Run cargo test on a package, optionally specify test
test package test_name="":
    @cargo test -p {{ package }} {{ test_name }} -- --show-output --nocapture

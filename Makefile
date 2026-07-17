# Makefile for firefly-static-parser

.PHONY: build clean run test

build:
	cargo build --release --bin firefly-static-parser

build-exe:
	cargo build --release --target x86_64-pc-windows-gnu

clean:
	cargo clean

run:
	cargo run --release --bin firefly-static-parser

test:
	cargo test --release

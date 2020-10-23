RUSTV = stable

build:
	cargo build --all

test-all:	test_native_tls_multiplex
	cargo test --all


test_native_tls_multiplex:
	cd crates/socket; cargo test --features native_tls test_multiplexing_native_tls


install-fmt:
	rustup component add rustfmt --toolchain $(RUSTV)

check-fmt:
	cargo +$(RUSTV) fmt -- --check

install-clippy:
	rustup component add clippy --toolchain $(RUSTV)

check-clippy:	install-clippy
	cargo +$(RUSTV) clippy --all-targets --all-features -- -D warnings


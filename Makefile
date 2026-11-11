.PHONY: native web check

native:
	cargo build --locked --release -p confidex -p cfdex -p confidexsyncd

web:
	python3 builders/wasm/build.py

check:
	cargo fmt --all --check
	cargo test --locked --workspace
	python3 -m unittest discover -s builders -p 'test_*.py'
	node --test apps/confidex/web/*.test.mjs

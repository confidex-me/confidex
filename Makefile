.PHONY: native web extension check

native:
	cargo build --locked --release -p confidex -p cfdex -p confidexsyncd

web:
	python3 builders/wasm/build.py

extension:
	python3 builders/wasm/build_extension.py

check:
	cargo fmt --all --check
	cargo test --locked --workspace
	python3 -m unittest discover -s builders -p 'test_*.py'
	node --test apps/confidex/web/*.test.mjs

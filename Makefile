.PHONY: native web check

native:
	cargo build --locked --release -p confidex -p cfdex -p confidexsyncd

web:
	sh apps/confidex/web/build.sh dist/wasm
	rm -rf dist/web
	mkdir -p dist/web
	node apps/confidex/web/build-static.mjs dist/wasm dist/web
	cp LICENSE dist/web/LICENSE
	node tools/check-web.mjs dist/web

check:
	cargo fmt --all --check
	cargo test --locked --workspace
	python3 -m unittest discover -s tools -p 'test_*.py'
	node --test apps/confidex/web/*.test.mjs

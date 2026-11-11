#!/bin/sh
set -eu
# The image codec has a separate worker and memory budget.
app_output=${1:?Usage: build.sh output-directory}
app_target=${CARGO_TARGET_DIR:-target}
app_bindgen=${WASM_BINDGEN:-wasm-bindgen}
app_opt=${WASM_OPT:-wasm-opt}
[ "$("$app_bindgen" --version)" = "wasm-bindgen 0.2.130" ] || { echo "Install wasm-bindgen 0.2.130" >&2; exit 1; }
case "$("$app_opt" --version)" in
  "wasm-opt version 133"|"wasm-opt version 133 (version_133)") ;;
  *) echo "Install Binaryen 133" >&2; exit 1 ;;
esac
mkdir -p "$app_output"

bindgen_and_optimize() {
  "$app_bindgen" "$app_target/wasm32-unknown-unknown/wasm-release/$1.wasm" \
    --target web --out-dir "$app_output" --out-name "$2"
  module="$app_output/${2}_bg.wasm"
  before=$(wc -c < "$module" | tr -d '[:space:]')
  "$app_opt" "$module" -Oz --strip-debug -o "$module.tmp"
  mv "$module.tmp" "$module"
  after=$(wc -c < "$module" | tr -d '[:space:]')
  printf '%s %s -> %s bytes\n' "$2" "$before" "$after"
}

cargo rustc --locked --profile wasm-release -p confidex-image-codec --lib --target wasm32-unknown-unknown \
  -- -C link-arg=--max-memory=2147483648
bindgen_and_optimize confidex_image_codec image_codec
cargo rustc --locked --profile wasm-release -p confidex --lib --target wasm32-unknown-unknown \
  -- -C link-arg=--max-memory=268435456
bindgen_and_optimize confidex app

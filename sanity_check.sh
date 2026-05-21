echo "Starting Sanity Check - Phase 1"
cargo check
if [ $? -ne 0 ]; then
  echo "CRITICAL_BUILD_FAILURE: Environment build failed or no Cargo project found."
fi

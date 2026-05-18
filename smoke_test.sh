echo "Starting Smoke Test - Phase 1: Environment Bootstrapping"
cargo check
if [ $? -ne 0 ]; then
  echo "CRITICAL_INFRASTRUCTURE_FAILURE: Environment build failed or no Cargo project found."
fi

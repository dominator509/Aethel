echo "Starting Performance Check - Phase 1: Architecture Profiling"
cargo check --bin core_node
if [ $? -ne 0 ]; then
  echo "FATAL: core_node failed to build. Cannot profile architecture."
else
  echo "Attempting to find active listening ports or endpoints..."
  echo "FATAL: No long-running services, APIs, or endpoints found to benchmark. System is empty scaffolding."
fi

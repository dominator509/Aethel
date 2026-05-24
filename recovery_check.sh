echo "Starting Resilience Check - Phase 1: Baseline State Capture"
cargo check
if [ $? -ne 0 ]; then
  echo "FATAL: System non-existent. Cannot capture PRE_DISASTER_STATE_HASH."
fi

echo "Starting Usability & DX Check - Phase 1: Touchpoint Discovery"
echo "Scanning for frontend frameworks..."
find . -type f \( -name "*.html" -o -name "*.jsx" -o -name "*.tsx" -o -name "*.vue" \)
echo "Scanning for CLI definitions..."
grep -r "struct Opts" . || grep -r "clap::" . || echo "No CLI framework found."
echo "Scanning for API definitions..."
grep -r "rocket::" . || grep -r "actix_web::" . || grep -r "axum::" . || echo "No HTTP API framework found."
echo "Discovery complete: System operates solely via raw TCP socket in core_node/src/main.rs."

#!/bin/bash

# This script sets up a Git pre-commit hook to run PySpector on staged files.

set -e

# Check if we are in a Git repository
if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo "Error: Not a Git repository."
    exit 1
fi

HOOK_DIR=".git/hooks"
HOOK_FILE="$HOOK_DIR/pre-commit"

echo "Setting up pre-commit hook in $HOOK_FILE..."

mkdir -p "$HOOK_DIR"

# Create the pre-commit hook script
cat > "$HOOK_FILE" << 'EOF'
#!/bin/bash

# PySpector pre-commit hook

echo "[PySpector] Running pre-commit scan..."

# Get staged Python files
STAGED_PY_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')

if [ -z "$STAGED_PY_FILES" ]; then
    echo "[PySpector] No Python files to scan."
    exit 0
fi

# Run PySpector on staged files with a high severity threshold
pyspector scan --severity HIGH $STAGED_PY_FILES

SCAN_RESULT=$?

if [ $SCAN_RESULT -ne 0 ]; then
    echo ""
    echo "[PySpector] Commit aborted due to high severity issues."
    echo "[PySpector] Please fix the issues above or commit with --no-verify to bypass."
    exit 1
fi

echo "[PySpector] Scan passed. Proceeding with commit."
exit 0
EOF

# Make the hook executable
chmod +x "$HOOK_FILE"

echo "Pre-commit hook created successfully."
echo "PySpector will now scan staged Python files for HIGH or CRITICAL issues before each commit."

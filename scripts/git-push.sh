#!/usr/bin/env bash
# One-command GitHub push helper for Permission Fence (Linux / macOS / Git Bash)
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: ./scripts/git-push.sh <https://github.com/username/permission-fence.git> [branch]"
    exit 1
fi

REPO_URL="$1"
BRANCH="${2:-main}"

if git remote | grep -q "^origin$"; then
    git remote set-url origin "$REPO_URL"
else
    git remote add origin "$REPO_URL"
fi

git branch -M "$BRANCH"
echo "Pushing Permission Fence commits to $REPO_URL ($BRANCH)..."
git push -u origin "$BRANCH"
echo "Successfully pushed to GitHub!"

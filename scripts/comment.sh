#!/usr/bin/env bash
# Create or update ONE sticky PR comment with the sast-check report.
# Needs: GH_TOKEN (pull-requests: write), REPO (owner/name), PR (number). Never fails the job.
set -uo pipefail
report="$1"
marker="<!-- sast-check -->"
[ -s "$report" ] || { echo "no report to post"; exit 0; }
body="$(printf '%s\n%s' "$marker" "$(head -c 60000 "$report")")"

id=$(gh api "repos/$REPO/issues/$PR/comments" --paginate \
       --jq ".[] | select(.body | startswith(\"$marker\")) | .id" 2>/dev/null | head -n1)
# Update our sticky comment; if that fails (e.g. someone else's comment carries the marker), post a new one.
if [ -n "$id" ] && gh api -X PATCH "repos/$REPO/issues/comments/$id" -f body="$body" >/dev/null 2>&1; then
  exit 0
fi
gh api -X POST "repos/$REPO/issues/$PR/comments" -f body="$body" >/dev/null \
  || echo "::warning::could not post PR comment (token may lack pull-requests: write)"
exit 0

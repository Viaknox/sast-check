#!/usr/bin/env bash
# Create or update ONE sticky PR comment with the sast-check report.
# Needs: GH_TOKEN (pull-requests: write), REPO (owner/name), PR (number). Never fails the job.
set -uo pipefail
report="$1"
marker="<!-- sast-check -->"
[ -s "$report" ] || { echo "no report to post"; exit 0; }
body="$(printf '%s\n%s' "$marker" "$(head -c 60000 "$report")")"

# Anyone can post a comment carrying the marker, so try every candidate (only our own is editable)
# and fall back to a new comment only when none of them is ours.
ids=$(gh api "repos/$REPO/issues/$PR/comments" --paginate \
        --jq ".[] | select(.body | startswith(\"$marker\")) | .id" 2>/dev/null)
for id in $ids; do
  if gh api -X PATCH "repos/$REPO/issues/comments/$id" -f body="$body" >/dev/null 2>&1; then
    exit 0
  fi
done
gh api -X POST "repos/$REPO/issues/$PR/comments" -f body="$body" >/dev/null \
  || echo "::warning::could not post PR comment (token may lack pull-requests: write)"
exit 0

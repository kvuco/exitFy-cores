#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OWNER/REPOSITORY OUTPUT_JSON" >&2
  exit 2
fi

repository="$1"
output="$2"
temporary="${output}.partial"
page_file="${output}.page"
filtered_file="${output}.filtered"
merged_file="${output}.merged"

cleanup() {
  rm -f "$temporary" "$page_file" "$filtered_file" "$merged_file"
}
trap cleanup EXIT

printf '[]\n' > "$temporary"
complete=false
for page in $(seq 1 100); do
  fetched=false
  for attempt in $(seq 1 5); do
    if gh api "repos/$repository/releases?per_page=100&page=$page" > "$page_file" \
        && jq -e 'type == "array"' "$page_file" >/dev/null; then
      fetched=true
      break
    fi
    rm -f "$page_file"
    sleep "$attempt"
  done
  if [[ "$fetched" != true ]]; then
    echo "Unable to fetch a valid GitHub Release page $page for $repository" >&2
    exit 1
  fi

  page_size="$(jq 'length' "$page_file")"
  jq '[.[] | {tag_name, draft, prerelease,
        assets: [.assets[] | {id, name}]}]' "$page_file" > "$filtered_file"
  jq -s '.[0] + .[1]' "$temporary" "$filtered_file" > "$merged_file"
  mv "$merged_file" "$temporary"
  if [[ "$page_size" -lt 100 ]]; then
    complete=true
    break
  fi
done

if [[ "$complete" != true ]]; then
  echo "GitHub Release pagination exceeded 100 pages for $repository" >&2
  exit 1
fi
mv "$temporary" "$output"
trap - EXIT
rm -f "$page_file" "$filtered_file" "$merged_file"

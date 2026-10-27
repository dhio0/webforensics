#!/usr/bin/env bash
# collect.sh: read-only evidence collector for webforensics (manifest format v1).
#
# Usage: collect.sh -w WEBROOT -o OUTDIR [-l LOG_FILE_OR_DIR]...
#
# Writes to OUTDIR (never inside WEBROOT):
#   manifest.tsv  stat + sha256 for every regular file and symlink under WEBROOT
#   webroot.tar   copy of WEBROOT (permissions and numeric owners preserved)
#   logs/         copies of the given log files (cp -p)
#   SHA256SUMS    hashes of everything above
#
# Requires bash and GNU coreutils (stat -c, sha256sum, od), find, sort -z, tar.
# Reading a file can update its atime (depends on mount options), so each file is
# stat'ed before it is hashed. Format spec: docs/evidence-format.md.
set -euo pipefail
export LC_ALL=C

COLLECTOR_VERSION="0.1.0"

usage() {
  echo "usage: $0 -w WEBROOT -o OUTDIR [-l LOG_FILE_OR_DIR]..." >&2
  exit 2
}

webroot=""
outdir=""
logs=()
while getopts "w:o:l:h" opt; do
  case "$opt" in
    w) webroot="$OPTARG" ;;
    o) outdir="$OPTARG" ;;
    l) logs+=("$OPTARG") ;;
    *) usage ;;
  esac
done
[[ -n "$webroot" && -n "$outdir" ]] || usage
[[ -d "$webroot" ]] || { echo "webroot not found: $webroot" >&2; exit 1; }

webroot="$(cd "$webroot" && pwd -P)"
mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd -P)"
case "$outdir/" in
  "$webroot"/*) echo "OUTDIR must not be inside WEBROOT" >&2; exit 1 ;;
esac
manifest="$outdir/manifest.tsv"
[[ ! -e "$manifest" ]] || { echo "refusing to overwrite $manifest" >&2; exit 1; }

# Hex-encode a path so tabs, newlines and invalid UTF-8 can't break the format.
hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }

birth_supported=0
if [[ "$(stat -c %W "$webroot" 2>/dev/null || echo -)" =~ ^[1-9][0-9]*$ ]]; then
  birth_supported=1
fi

write_rows() {
  cd "$webroot"
  find . -xdev \( -type f -o -type l \) -print0 | sort -z | while IFS= read -r -d '' f; do
    st="$(stat -c '%s %a %u %i %X %Y %Z %W' -- "$f")" || continue
    read -r size mode uid inode atime mtime ctime btime <<< "$st"
    if [[ -L "$f" ]]; then
      type=l
      digest="$(printf '%s' "$(readlink -- "$f")" | sha256sum | cut -d' ' -f1)"
    else
      type=f
      digest="$(sha256sum < "$f" | cut -d' ' -f1)" || digest="-"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(hex "${f#./}")" "$type" "$size" "$mode" "$uid" "$inode" \
      "$atime" "$mtime" "$ctime" "$btime" "$digest"
  done
}

{
  echo "#webforensics-manifest v1"
  echo "#collector=collect.sh $COLLECTOR_VERSION"
  echo "#hostname=$(hostname 2>/dev/null || echo unknown)"
  echo "#webroot=$webroot"
  echo "#collected_at=$(date -u +%s)"
  echo "#utc_offset=$(date +%z)"
  echo "#birth_time_supported=$birth_supported"
  echo "#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256"
  (write_rows)
} > "$manifest"

tar --numeric-owner -cpf "$outdir/webroot.tar" -C "$webroot" . \
  || echo "warning: tar reported problems (files changed while reading?)" >&2

mkdir -p "$outdir/logs"
for src in ${logs[@]+"${logs[@]}"}; do
  if [[ -d "$src" ]]; then
    find "$src" -maxdepth 1 -type f -exec cp -p -- {} "$outdir/logs/" \;
  elif [[ -f "$src" ]]; then
    cp -p -- "$src" "$outdir/logs/"
  else
    echo "warning: log not found: $src" >&2
  fi
done

(cd "$outdir" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
  | xargs -0 -r sha256sum > SHA256SUMS)

rows="$(grep -vc '^#' "$manifest" || true)"
echo "collected $rows entries from $webroot into $outdir" >&2

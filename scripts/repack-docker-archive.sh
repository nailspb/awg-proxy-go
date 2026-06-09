#!/bin/sh
# Конвертирует buildx-экспорт (OCI-раскладка blobs/sha256/...) в классический
# docker-save архив (<id>/layer.tar + repositories), который понимает RouterOS.
# Использование: repack-docker-archive.sh <src.tar> <out.tar>
set -e

SRC="$1"
OUT="$2"
[ -n "$SRC" ] && [ -n "$OUT" ] || { echo "usage: $0 <src.tar> <out.tar>" >&2; exit 2; }

# абсолютные пути (tar запускается из другого каталога)
case "$SRC" in /*) ;; *) SRC="$PWD/$SRC";; esac
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT";; esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src" "$work/out"
tar -xf "$SRC" -C "$work/src"

man="$work/src/manifest.json"
[ -f "$man" ] || { echo "manifest.json not found in $SRC" >&2; exit 1; }

# digest конфига и список digest слоёв из manifest.json
cfg=$(grep -o '"Config":"[^"]*"' "$man" | head -1 | sed 's#.*blobs/sha256/##;s/"//')
layers=$(grep -o '"Layers":\[[^]]*\]' "$man" | grep -o 'blobs/sha256/[0-9a-f]\{64\}' | sed 's#blobs/sha256/##')
tags=$(grep -o '"RepoTags":\[[^]]*\]' "$man" | head -1 | sed 's/"RepoTags"://')

cp "$work/src/blobs/sha256/$cfg" "$work/out/$cfg.json"

prev=""
layer_paths=""
layer_dirs=""
for l in $layers; do
  mkdir -p "$work/out/$l"
  cp "$work/src/blobs/sha256/$l" "$work/out/$l/layer.tar"
  echo "1.0" > "$work/out/$l/VERSION"
  if [ -z "$prev" ]; then
    printf '{"id":"%s"}\n' "$l" > "$work/out/$l/json"
  else
    printf '{"id":"%s","parent":"%s"}\n' "$l" "$prev" > "$work/out/$l/json"
  fi
  prev="$l"
  layer_paths="$layer_paths\"$l/layer.tar\","
  layer_dirs="$layer_dirs $l"
done
layer_paths=$(echo "$layer_paths" | sed 's/,$//')

printf '[{"Config":"%s.json","RepoTags":%s,"Layers":[%s]}]\n' \
  "$cfg" "$tags" "$layer_paths" > "$work/out/manifest.json"

# repositories: тег -> id верхнего слоя
tag=$(echo "$tags" | grep -o '"[^"]*"' | head -1 | sed 's/"//g')
repo=${tag%:*}
ver=${tag##*:}
printf '{"%s":{"%s":"%s"}}\n' "$repo" "$ver" "$prev" > "$work/out/repositories"

# несжатый tar без ./-префикса
( cd "$work/out" && tar -cf "$OUT" manifest.json repositories "$cfg.json" $layer_dirs )
echo "repacked -> $OUT"

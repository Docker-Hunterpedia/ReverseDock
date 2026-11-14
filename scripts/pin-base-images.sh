#!/usr/bin/env bash
# Pin the base images of the Dockerfiles by digest: image:tag -> image:tag@sha256:<digest>.
#
#   scripts/pin-base-images.sh             rewrite Dockerfile and Dockerfile.release (and any other
#                                          Dockerfile* named on the command line) in place
#   scripts/pin-base-images.sh --check     rewrite nothing; exit 1 when a FROM line has no digest
#                                          or when its digest is not the one its tag resolves to now
#   scripts/pin-base-images.sh --verify    like --check, but only that a digest is present (offline)
#
# The digest is read from the image's registry over the OCI distribution API (a HEAD request on
# the manifest; for a multi-platform image that is the digest of the image index, which is what
# `docker pull` resolves per platform). No Docker daemon is needed: curl and sed only.
#
# FROM lines must be literal (`FROM image:tag`): a line that uses a build argument (${...}) is
# refused, because Dependabot cannot read it either. Stage names (`FROM build AS x`) and `scratch`
# are skipped. Dependabot's docker ecosystem rewrites tag and digest together afterwards
# (.github/dependabot.yml); this script is for the first pin, for a new image and for a manual check.
set -euo pipefail

mode=rewrite
files=()
for arg in "$@"; do
  case "$arg" in
    --check) mode=check ;;
    --verify) mode=verify ;;
    -h | --help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) files+=("$arg") ;;
  esac
done
cd "$(dirname "$0")/.."
if [ "${#files[@]}" -eq 0 ]; then
  mapfile -t files < <(git ls-files 'Dockerfile*' '**/Dockerfile*' | sort -u)
fi

accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

# resolve IMAGE TAG -> prints sha256:<digest>
resolve() {
  local image="$1" tag="$2" host path first headers status token challenge realm service scope
  first="${image%%/*}"
  if [ "$first" != "$image" ] && { [[ "$first" == *.* ]] || [[ "$first" == *:* ]] || [ "$first" = localhost ]; }; then
    host="$first"
    path="${image#*/}"
  else
    host="registry-1.docker.io"
    path="$image"
    case "$path" in */*) ;; *) path="library/$path" ;; esac
  fi
  headers="$(mktemp)"
  trap 'rm -f "$headers"' RETURN
  status="$(curl -sS -m 30 -o /dev/null -D "$headers" -w '%{http_code}' -I -H "Accept: $accept" "https://$host/v2/$path/manifests/$tag")"
  if [ "$status" = 401 ]; then
    # Anonymous bearer token, as the registry's WWW-Authenticate header describes.
    challenge="$(grep -i '^www-authenticate:' "$headers" | head -n1 | tr -d '\r')"
    realm="$(sed -n 's/.*realm="\([^"]*\)".*/\1/p' <<<"$challenge")"
    service="$(sed -n 's/.*service="\([^"]*\)".*/\1/p' <<<"$challenge")"
    scope="$(sed -n 's/.*scope="\([^"]*\)".*/\1/p' <<<"$challenge")"
    [ -n "$scope" ] || scope="repository:$path:pull"
    token="$(curl -sS -m 30 -G "$realm" --data-urlencode "service=$service" --data-urlencode "scope=$scope" |
      sed -n 's/.*"token" *: *"\([^"]*\)".*/\1/p')"
    [ -n "$token" ] || { echo "no anonymous token from $realm for $image" >&2; return 1; }
    status="$(curl -sS -m 30 -o /dev/null -D "$headers" -w '%{http_code}' -I -H "Accept: $accept" -H "Authorization: Bearer $token" "https://$host/v2/$path/manifests/$tag")"
  fi
  [ "$status" = 200 ] || { echo "$image:$tag: the registry answered HTTP $status" >&2; return 1; }
  grep -i '^docker-content-digest:' "$headers" | head -n1 | tr -d '\r' | sed 's/^[^:]*: *//'
}

status=0
for file in "${files[@]}"; do
  tmp="$(mktemp)"
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(--platform=[^[:space:]]+[[:space:]]+)?([^[:space:]]+)(.*)$ ]]; then
      platform="${BASH_REMATCH[1]}"
      ref="${BASH_REMATCH[2]}"
      rest="${BASH_REMATCH[3]}"
      case "$ref" in
        scratch) printf '%s\n' "$line" >>"$tmp"; continue ;;
        *'$'*) echo "$file: '$ref' uses a build argument; write the tag out so it can be pinned and updated" >&2; status=1; printf '%s\n' "$line" >>"$tmp"; continue ;;
      esac
      # A stage name (FROM build AS x) is a word with no ':' or '/' that an earlier `AS` defined.
      if grep -qiE "^[[:space:]]*FROM[[:space:]].*[[:space:]]AS[[:space:]]+${ref//./\\.}([[:space:]]|$)" "$tmp"; then
        printf '%s\n' "$line" >>"$tmp"; continue
      fi
      pinned=""
      name_tag="$ref"
      case "$ref" in *@sha256:*) pinned="${ref#*@}"; name_tag="${ref%%@*}" ;; esac
      last="${name_tag##*/}"
      case "$last" in
        *:*) image="${name_tag%:*}"; tag="${name_tag##*:}" ;;
        *) echo "$file: '$ref' has no tag; write the tag you mean (for example :1.2.3), then pin it" >&2; status=1; printf '%s\n' "$line" >>"$tmp"; continue ;;
      esac
      if [ "$mode" = verify ]; then
        [ -n "$pinned" ] || { echo "$file: $image:$tag is not pinned by digest" >&2; status=1; }
        printf '%s\n' "$line" >>"$tmp"; continue
      fi
      digest="$(resolve "$image" "$tag")" || { status=1; printf '%s\n' "$line" >>"$tmp"; continue; }
      if [ "$mode" = check ]; then
        if [ -z "$pinned" ]; then echo "$file: $image:$tag is not pinned by digest (it resolves to $digest)" >&2; status=1
        elif [ "$pinned" != "$digest" ]; then echo "$file: $image:$tag is pinned to $pinned but resolves to $digest now" >&2; status=1; fi
        printf '%s\n' "$line" >>"$tmp"; continue
      fi
      echo "$file: $image:$tag -> $digest" >&2
      printf 'FROM %s%s:%s@%s%s\n' "$platform" "$image" "$tag" "$digest" "$rest" >>"$tmp"
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$file"
  if [ "$mode" = rewrite ] && ! cmp -s "$tmp" "$file"; then cat "$tmp" >"$file"; fi
  rm -f "$tmp"
done
exit "$status"

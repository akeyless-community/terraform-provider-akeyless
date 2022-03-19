#!/bin/bash

NAT='0|[1-9][0-9]*'
ALPHANUM='[0-9]*[A-Za-z-][0-9A-Za-z-]*'
IDENT="$NAT|$ALPHANUM"
FIELD='[0-9A-Za-z-]+'
  
SEMVER_REGEX="\
^[vV]?\
($NAT)\\.($NAT)\\.($NAT)\
(\\-(${IDENT})(\\.(${IDENT}))*)?\
(\\+${FIELD}(\\.${FIELD})*)?$"

function die() {
  echo $*
  exit 1
}

function validate_semver {
  local version=$1
  
  echo "Validating semver for version $version"
  if [[ ! "$version" =~ $SEMVER_REGEX ]]; then
    die "not a valid semver version!"
  fi
}

function tag_exists() {
  tag=$1
  
  echo "Validating if version tag $tag already exists"
  exists=$(git tag -l "${tag}" | grep -e "${tag}")
  if [[ -n "${exists}" ]]; then
    die "Version tag ${tag} is already exists! please insert currect version"
  fi
}
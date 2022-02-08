#!/bin/bash

dir_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
source "${dir_path}/common.sh"

version=$(cat "${GITHUB_WORKSPACE}/version" | sed -n '/v[0-9]\{1,\}.[0-9]\{1,\}.[0-9]\{1,\}/p') 

[[ -z "$version" ]] && die "Failed to retrieve version. Please check if the version is correct and follows semantic versioning"

validate_semver "$version"
tag_exists "$version"

echo "Version validation succeeded"
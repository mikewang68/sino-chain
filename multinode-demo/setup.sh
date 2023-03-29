#!/bin/bash
#
here=$(dirname "$0")
source "$here"/common.sh

script_dir="$(readlink -f "$(dirname "$0")")"
echo $script_dir

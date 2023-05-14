#!/bin/bash
#

set -e
script_dir="$(readlink -f "$(dirname "$0")")"
echo $script_dir
if [[ "$script_dir" =~ /scripts$ ]]; then
  cd "$script_dir/.."
else
  cd "$script_dir"
fi

dataDir=$PWD/config/"$(basename "$0" .sh)"
ledgerDir=$PWD/config/ledger
echo $dataDir
echo $ledgerDir
//123456789


//wwwwwwwwwwww

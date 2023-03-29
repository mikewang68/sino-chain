#!/bin/bash
#
#

netDir=$(
    cd "$(dirname "${BASH_SOURCE[0]}")" ||exit
    echo "$PWD"
)

echo $netDir

#!/usr/bin/env bash
#
# Start a validator
#
here=$(dirname "$0")
# shellcheck source=multinode-demo/common.sh
# source "$here"/common.sh

airdrops_enabled=1
node_sor=500 # 500 SOR: number of SOR to airdrop the node for transaction fees and vote account rent exemption (ignored if airdrops_enabled=0)
label=1

ledgerDir=$PWD/../config/validator$label/ledger
dataDir=$PWD/../config/validator$label

identity=$dataDir/identity.json
vote_account=$dataDir/vote-account.json
authorized_withdrawer=$dataDir/authorized-withdrawer.json

no_restart=0
mkdir -p "$ledgerDir"

[[ -r "$identity" ]] || sino-keygen new --no-passphrase -so "$identity"
[[ -r "$vote_account" ]] || sino-keygen new --no-passphrase -so "$vote_account"
[[ -r "$authorized_withdrawer" ]] || sino-keygen new --no-passphrase -so "$authorized_withdrawer"

# setup_validator_accounts "$node_sor"

rpc_faucet_address=http://127.0.0.1:8899
sino airdrop $node_sor $vote_account --url "$rpc_faucet_address"

abort() {
    set +e
    kill "$validator"
    wait "$validator"
}
trap abort INT TERM EXIT

args=(
    --max-genesis-archive-unpacked-size 1073741824
    --identity "$identity"
    --vote-account "$vote_account"
    --ledger "$ledgerDir"
    # --gossip-port 8001
    --full-rpc-api
    # --rpc-port 8899
    --rpc-faucet-address 127.0.0.1:9900
    --log "$dataDir"/a.log
    --enable-rpc-transaction-history
    --enable-cpi-and-log-storage
    # --init-complete-file "$dataDir"/init-completed
    --snapshot-compression none
    --accounts-db-caching-enabled
    --snapshot-interval-slots 100
    --require-tower
    --no-wait-for-vote-to-start-leader
    --no-os-network-limits-test
    --account-index program-id
    --account-index spl-token-owner
    --account-index spl-token-mint
    --account-index velas-accounts-storages
    --account-index velas-accounts-owners
    --account-index velas-accounts-operationals
    # --evm-state-archive "$ledgerDir"/archive-evm
    --gossip-host 127.0.0.1
    --allow-private-addr
    --entrypoint 127.0.0.1:8001
)
# shellcheck disable=SC2086
sino-validator "${args[@]}" $SOLANA_RUN_SH_VALIDATOR_ARGS &
validator=$!

wait "$validator"

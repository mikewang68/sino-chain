# sino-chain

## Building

### 0. Use install.sh to install Sino-chain

You can use install.sh to install Sino-chain :

```shell
./install.sh
```

Or you can follow the steps to install.

### 1. install rustc, cargo and rustfmt.

```shell
$ curl https://sh.rustup.rs -sSf | sh
$ source $HOME/.cargo/env
$ rustup component add rustfmt
```

Please sure you are always using the latest stable rust version by running:

```shell
$ rustup update
```

On Linux systems you may need to install libssl-dev, pkg-config, zlib1g-dev, etc. On Ubuntu:

```shell
$ sudo apt-get update
$ sudo apt-get install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang make cmake protobuf-compiler
```

On Mac M1s, make sure you set up your terminal & homebrew [to use](https://5balloons.info/correct-way-to-install-and-use-homebrew-on-m1-macs/) Rosetta. You can install it with:

```shell
$ softwareupdate --install-rosetta
```

### **2. Download the source code.**

```shell
$ git clone https://github.com/mikewang68/sino-chain.git
$ cd sino-chain
```

### **3. Build.**

```shell
$ cargo build
```

### **4. Run a minimal local cluster.**

```shell
$ ./run.sh
```

## Testing

#### **Run the test suite:**

```shell
$ cargo test --no-fail-fast
```

#### EVM integration

Info about EVM integration is at our [docs](https://www.baidu.com).

#### Starting a local testnet

Start your own Development network locally, instructions are in the [online docs](https://www.baidu.com).

#### Accessing the remote testnet and mainnet

- `testnet` - xxx.
- `mainnet` - xxx.

## Benchmarking

### Alter the block mining time

To alter the block mining time by changing the `.sh` file at `./scripts/run.sh`.

```shell
else
    $script_dir/../fetch-spl.sh
    if [[ -r spl-genesis-args.sh ]]; then
        SPL_GENESIS_ARGS=$(cat spl-genesis-args.sh)
    fi

    # shellcheck disable=SC2086
    sino-genesis \
    --hashes-per-tick 30000 \
    --faucet-wens 500000000000000000 \
    --bootstrap-validator \
    "$validator_identity" \
    "$validator_vote_account" \
    "$validator_stake_account" \
    --ledger "$ledgerDir" \
    --cluster-type "$SOLANA_RUN_SH_CLUSTER_TYPE" \
    $SPL_GENESIS_ARGS \
    --max-genesis-archive-unpacked-size=300000000 \
    $SOLANA_RUN_SH_GENESIS_ARGS 
    # --evm-root="0x7b343e0165c8f354ac7b1e7e7889389f42927ccb9d0330b3036fb749e12795ba" \
    # --evm-state-file="../state.json" \
    # --evm-chain-id 111
fi
```
Change `--hashes-per-tick` to alter the block mining time. 

30000 $\approx$ 3000ms $\approx$ 3s

Also need to add `--no-poh-seed-test` at:
```shell
args=(
    --identity "$dataDir"/validator-identity.json
    --vote-account "$dataDir"/validator-vote-account.json
    --ledger "$ledgerDir"
    --gossip-port 8001
    --full-rpc-api
    --rpc-port 8899
    --rpc-faucet-address 192.168.101.101:9900
    --log -
    --enable-rpc-transaction-history
    --enable-cpi-and-log-storage
    --init-complete-file "$dataDir"/init-completed
    --snapshot-compression none
    --accounts-db-caching-enabled
    --snapshot-interval-slots 100
    --require-tower
    --no-wait-for-vote-to-start-leader
    --no-os-network-limits-test
    --account-index program-id
    --account-index spl-token-owner
    --account-index spl-token-mint
    --account-index sino-accounts-storages
    --account-index sino-accounts-owners
    --account-index sino-accounts-operationals
    --evm-state-archive "$ledgerDir"/archive-evm
    --gossip-host 192.168.101.101
    --allow-private-addr
    --no-poh-speed-test
)
```

## Release Process
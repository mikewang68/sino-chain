FILE_PATH=~/.local/share/sino

cd target/debug
echo "copying files to $FILE_PATH"
cp sino evm-bridge sino-faucet sino-gossip sino-genesis sino-keygen test-validator sino-validator cargo-build-bpf cargo-test-bpf $FILE_PATH

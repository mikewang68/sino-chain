curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup component add rustfmt

rustup update

type=`uname  -a`
if [[ $type =~ "Darwin" ]];then
    softwareupdate --install-rosetta
else
    sudo apt-get update
    sudo apt-get install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang make cmake protobuf-compiler
fi


git clone https://github.com/mikewang68/sino-chain.git
cd sino-chain

FILE_PATH=~/.local/share/sino

if [ -d "$FILE_PATH" ]; then
    echo "$FILE_PATH is a directory."
else 
    echo "$FILE_PATH is not a directory, creating..."
    mkdir -p "$FILE_PATH"
fi


evm_bridge=sino-chain/target/debug/evm-bridge
faucet=sino-chain/target/debug/sino-faucet
gossip=sino-chain/target/debug/sino-gossip
sino_genesis=sino-chain/target/debug/sino-genesis
sino_keygen=sino-chain/target/debug/sino-keygen
test_validator=sino-chain/target/debug/test-validator
validator=sino-chain/target/debug/sino-validator

if [ -f "$evm_bridge" -a -f "$faucet" -a -f "$gossip" -a -f "$sino_genesis" -a -f "$sino_keygen" -a -f "$test_validator" -a -f "$validator" ]; then
    echo "Build has been completed"
else
    cd sino-chain
    cargo build --release
fi

# cd target/debug
cd target/release

echo "copying files to $FILE_PATH"
cp sino evm-bridge sino-faucet sino-gossip sino-genesis sino-keygen test-validator sino-validator $FILE_PATH

cd ~
zsh=.zshrc
bash=.bashrc
if [ -f "$zsh" ]; then
    echo "export PATH=~/.local/share/sino:\$PATH\" >> .zshrc
fi

if [ -f "$bash" ]; then
    echo "export PATH=~/.local/share/sino:\$PATH\" >> .bashrc
fi

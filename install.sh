echo Installing rust-lang...
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup component add rustfmt

rustup update
# echo Changing the version of rust to 1.73
# rustup default 1.73

type=`uname  -a`
if [[ $type =~ "Darwin" ]];then
    echo Install apple dependance
    softwareupdate --install-rosetta
else
    echo Install linux dependence
    sudo apt-get update
    sudo apt-get install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang make cmake protobuf-compiler
fi


# git clone https://github.com/mikewang68/sino-chain.git

FILE_PATH=~/.local/share/sino

if [ -d "$FILE_PATH" ]; then
    echo "$FILE_PATH is a directory."
else 
    echo "$FILE_PATH is not a directory, creating..."
    mkdir -p "$FILE_PATH"
fi


evm_bridge=target/debug/evm-bridge
faucet=target/debug/sino-faucet
gossip=target/debug/sino-gossip
sino_genesis=target/debug/sino-genesis
sino_keygen=target/debug/sino-keygen
test_validator=target/debug/test-validator
validator=target/debug/sino-validator

if [ -f "$evm_bridge" -a -f "$faucet" -a -f "$gossip" -a -f "$sino_genesis" -a -f "$sino_keygen" -a -f "$test_validator" -a -f "$validator" ]; then
    echo "Build has been completed"
else
    cargo build
fi

cd target/debug
echo "copying files to $FILE_PATH"
cp sino evm-bridge sino-faucet sino-gossip sino-genesis sino-keygen test-validator sino-validator $FILE_PATH

cd ~
zsh=.zshrc
bash=.bashrc
path="export PATH=\"~/.local/share/sino:\$PATH\""
if [ -f "$zsh" ]; then
    echo writting $path to .zshrc...
    echo "$path" >> .zshrc
fi

if [ -f "$bash" ]; then
    echo writting $path to .bashrc...
    echo "$path" >> .bashrc
fi

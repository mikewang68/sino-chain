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
$ cd velas-chain
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

## Release Process
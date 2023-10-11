# DAFT Proof-of-Concept

This repository contains the proof-of-concept of DAFT.
The source code is fully available and the experiments can be replayed.

## Installation

The source code have been fully written in *Rust*.
Hence, before to run any script, we recommand you to install *rustup*,
the Rust installation toolchain, as follow:
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh # Linux
```

Once installed, the following command will compile, execute and store the benchmark result
in the already existing `communication_size.csv` and `execution_time.csv` files. 
```sh
cargo bench --bench csv
```

## Running DAFT with Docker

If you prefer to run the experiments in an isolated container, we also
provide the following command using Docker (that should be installed before):
```sh
sudo docker build . -t daft && sudo docker run --rm -it -v $(pwd):/daft daft
```
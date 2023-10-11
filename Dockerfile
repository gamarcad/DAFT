FROM rust:1.72

WORKDIR /daft

CMD cargo bench --bench csv


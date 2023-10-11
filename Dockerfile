FROM rust:1.72

VOLUME . /data

WORKDIR /data

CMD cargo test


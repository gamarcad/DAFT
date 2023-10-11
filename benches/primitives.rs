mod ac17;
mod abe;
mod daft;

use ac17::{ac17_setup, ac17_key_gen, ac17_encryption, ac17_decryption};
use abe::{daft_abe_setup, daft_abe_key_gen, daft_abe_encryption, daft_abe_decryption};

use criterion::{criterion_group, criterion_main, Criterion};






criterion_group!(
    name = primitives;
    config = Criterion::default();
    targets = 
        ac17_setup, ac17_encryption, ac17_key_gen, ac17_decryption,
        daft_abe_setup, daft_abe_key_gen, daft_abe_encryption, daft_abe_decryption,
        
);


criterion_main!(primitives);
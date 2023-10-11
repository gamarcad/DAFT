mod ac17;
mod abe;
mod daft;
use daft::daft_benchmarks_into_csv;

use criterion::{criterion_group, criterion_main, Criterion};

criterion_group!(
    name = csv;
    config = Criterion::default();
    targets = daft_benchmarks_into_csv 
        
);

criterion_main!(csv);
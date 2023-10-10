

use criterion::{Criterion, black_box, BenchmarkId, criterion_group, criterion_main};

use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use ascon_hash::AsconHash;
use tiger::{Tiger, Tiger2};
use whirlpool::Whirlpool;
use belt_hash::BeltHash;
use mk256::mk256;


pub fn bench_all(c : &mut Criterion ) {
    static MB: usize = 1000000;
    static START : usize = 50;
    static END : usize = 150;
    static STEP : usize = 50;

    let mut group = c.benchmark_group( "hash" );
    group.sample_size(10);
    for size in ( START..END ).step_by(STEP) {

        // benchmark of mk256 
        group.bench_with_input(BenchmarkId::new( "mk256", size), &size, |b, &size| {
            // initiate the file 
            let data = vec![0; size * MB];
            b.iter(|| {
                let result = mk256(&data);
                black_box(result);
            });   
        });

        
        // benchmark of existing constant-sized output hash function
        macro_rules! bench_hash {
            (  $lib:ident, $hash:ident ) => {
                let name = format!("{}::{}", stringify!($lib),  stringify!($hash) );
                group.bench_with_input(BenchmarkId::new( name, size), &size, |b, &size| {
                    // initiate the file 
                    let data = vec![0; size * MB];
                    b.iter(|| {
                        let mut cipher = $hash::new();
                        let result = cipher.update(&data);
                        black_box((result));
                    });   
                });
               
            };
        }

        // sha1
        bench_hash!( sha1, Sha1 );

        // sha2
        bench_hash!( sha2, Sha224 );
        bench_hash!( sha2, Sha256 );
        bench_hash!( sha2, Sha384 );
        bench_hash!( sha2, Sha512 );

        // sha3
        bench_hash!( sha3, Sha3_224 );
        bench_hash!( sha3, Sha3_256 );
        bench_hash!( sha3, Sha3_384 );
        bench_hash!( sha3, Sha3_512 );


        // ascon_hash
        bench_hash!( ascon_hash, AsconHash );

        // tiger
        bench_hash!( tiger, Tiger );
        bench_hash!( tiger, Tiger2 );

        // whirlpool
        bench_hash!( whirlpool, Whirlpool );


        // belt
        bench_hash!( belt_hash, BeltHash );
      
    }
    
    group.finish();
}






criterion_group!(
    name = bench;
    config = Criterion::default();
    targets = bench_all
        
);


criterion_main!(bench); 
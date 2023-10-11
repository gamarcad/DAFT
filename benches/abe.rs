use criterion::{Criterion, black_box};

use daft::abe::{abe_setup, abe_encrypt, abe_decrypt, Plaintext};

#[allow(dead_code)]
pub fn daft_abe_setup(c : &mut Criterion) {
    c.bench_function("daft-abe-setup", |b| {

        b.iter(|| {
            let (pk, msk) =  abe_setup();
            black_box((pk, msk));
        });
    });
}

#[allow(dead_code)]
pub fn daft_abe_key_gen(c : &mut Criterion) {
    c.bench_function("daft-abe-key-gen", |b| {
        let (_, msk) = abe_setup();
        

        b.iter(|| {
            let attr = vec!["A".to_string()];
            let sk = msk.gen_secret_key(attr); 
            black_box(sk);
        });
    });
}

#[allow(dead_code)]
pub fn daft_abe_encryption(c : &mut Criterion) {
    c.bench_function("daft-abe-encryption", |b| {
        let (pk, _) = abe_setup();
        let policy = String::from(r#""A" and "B""#);
        let plaintext : Plaintext = Plaintext::from(vec![1, 2]);
        

        b.iter(|| {
            let _ct = abe_encrypt(&pk, &policy, &plaintext);
            black_box(_ct.is_ok());
        });
    });
}

#[allow(dead_code)]
pub fn daft_abe_decryption(c : &mut Criterion) {
    c.bench_function("daft-abe-decryption", |b| {
        let (pk, msk) = abe_setup();
        let policy = String::from(r#""A" or "B""#);
        let plaintext : Plaintext = Plaintext::from(vec![1, 2]);
        let ct = abe_encrypt(&pk, &policy, &plaintext).unwrap();
        let attr = vec!["A".to_string()];
        let sk = msk.gen_secret_key(attr); 
        

        b.iter(|| {
            let _ct = abe_decrypt(&sk, &pk, &ct);
            black_box(_ct.is_ok());
        });
    });
}

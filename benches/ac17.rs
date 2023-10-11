use criterion::{Criterion, black_box};
use rabe::schemes::ac17::{setup, cp_encrypt, cp_decrypt, cp_keygen};
use rabe::utils::policy::pest::PolicyLanguage;



#[allow(dead_code)]
pub fn ac17_setup(c : &mut Criterion) {
    c.bench_function("ac17-setup", |b| {

        b.iter(|| {
            let (pk, msk) =  setup();
            black_box((pk, msk));
        });
    });
}

#[allow(dead_code)]
pub fn ac17_key_gen(c : &mut Criterion) {
    c.bench_function("ac17-key_gen", |b| {
        let (_, msk) = setup();
        let attr = vec!["A".to_string()];

        b.iter(|| {
            let _sk = cp_keygen(&msk, &attr);
            black_box(_sk.is_ok());
        });
    });
}



#[allow(dead_code)]
pub fn ac17_encryption(c : &mut Criterion) {
    c.bench_function("ac17-cp_encryption", |b| {
        let (pk, _) = setup();
        let policy = String::from(r#""A" and "B""#);
        let plaintext : [u8; 2] = [1, 2];
        

        b.iter(|| {
            let _ct = cp_encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy);
            black_box(_ct.is_ok());
        });
    });
}

#[allow(dead_code)]
pub fn ac17_decryption(c : &mut Criterion) {
    c.bench_function("ac17-cp_decryption", |b| {
        let (pk, msk) = setup();
        let policy = String::from(r#""A" or "B""#);
        let plaintext : [u8; 2] = [1, 2];
        let ct = cp_encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();
        let attr = vec!["A".to_string()];
        let sk = cp_keygen(&msk, &attr).unwrap(); 
        

        b.iter(|| {
            let _ct = cp_decrypt(&sk, &ct);
            black_box(_ct.is_ok());
        });
    });
}

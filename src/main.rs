pub mod abe;
pub mod daft;


use abe::*;
use std::time::Instant;
use crate::abe::abe_setup;


fn main() { 
    pretty_env_logger::init();

    for size in (50..500).step_by(50) {

        // generate the keys and policies
        let start = Instant::now();
        let (pk, msk) = abe_setup();
        let policy = String::from(r#""A" and "B""#);
        let sk = msk.gen_secret_key(vec!["A".to_string(), "B".to_string()]);
        println!("{}: keys and policy generation: {}", size, start.elapsed().as_millis());
        println!("Embedded attribute: {:?}", sk.attr());

        // encryption the message
        let start = Instant::now();
        let plaintext = Plaintext::from(vec![0; size * 1000000]);
        println!("{}: plaintext generation: {}", size, start.elapsed().as_millis());
        
        let start = Instant::now();
        let result = abe_encrypt(&pk, &policy, &plaintext);
        println!("{}: encryption: {}", size, start.elapsed().as_millis());
        assert!(result.is_ok());
        let ciphertext = result.unwrap();

        // computes the decryption
        let start = Instant::now();
        let recovered_plaintext = abe_decrypt(&sk, &pk, &ciphertext);
        println!("{}: decryption: {}", size, start.elapsed().as_millis());
        if recovered_plaintext.is_ok() {
            //println!("Recovered plaintext: {:?}", recovered_plaintext);
        }
        
        assert!(recovered_plaintext.is_ok());
    }

}


pub mod abe;
pub mod daft;


use abe::*;
use std::process::exit;
use rand::{thread_rng, RngCore};
use rabe::schemes::ac17::{setup, cp_encrypt_rng, cp_decrypt, cp_keygen};
use rabe::utils::policy::pest::PolicyLanguage;

use std::time::{Duration, Instant};

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

fn test() {
     // create the ABE scheme for the first time.
    // We will try to control the randomness here
    let (mpk, msk) = setup();
    let policy = String::from(r#""A" and "B""#);
    let plaintext : [u8; 2] = [1, 2];
    let mut rng = thread_rng();
    let ct = cp_encrypt_rng(
        &mpk, 
        &policy, 
        &plaintext, 
        PolicyLanguage::HumanPolicy,
        rng
    );
    match ct {
        Ok(ref ct) => {println!("Encryption done: {:?}",ct)}
        Err(error) => {
            println!("Encryption error: {error}"); 
            exit(1);
        }
    }

    // generate the master secret key
    let x : Vec<String> = vec!["A", "B"].iter().map(|s| s.to_string()).collect();
    let sk_x = cp_keygen(&msk, &x);
    match sk_x {
        Ok(_) => {println!("Decryption key generated correctly")}
        Err(error) => {
            println!("Decryption key generation error: {error}"); 
            exit(1);
        }
    }



    // decrypt the ciphertext
    let message = cp_decrypt( &sk_x.unwrap(), &ct.unwrap());
    println!("{:?}", message)
    
}


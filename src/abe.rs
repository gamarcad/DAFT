//! 
//! Implementation of an IND-CCA2 Atttribute-based Encryption (ABE) scheme.
//! 
//! The implementation starts from an IND-CPA ABE scheme, on which we apply the
//! Fujiski-Okamoto transformation, using an hash function and a symmetric encryption.
//! 
//! We have chosen SHA-256 as an hash function, and AES-256-CTR for the symmetric encryption.


use std::{fmt::Display, time::Instant};
use log::debug;
use rabe::{schemes::ac17::{Ac17PublicKey, Ac17MasterKey, Ac17CpSecretKey, Ac17CpCiphertext}, utils::policy::pest::PolicyLanguage};
use rabe::schemes::ac17::{setup, cp_encrypt_rng, cp_decrypt, cp_keygen};
use rand::{Rng, thread_rng};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest, Sha512_256};
use std::fmt;
use rand_chacha::ChaCha8Rng;
use rand::prelude::*;
use openssl::symm::{Cipher,encrypt, decrypt};
use mk256::mk256;
use bincode::{serialize};


/// 
/// Representation of errors that may happened
/// during the encryption and the decryption.
/// 
/// The error contains a description field `detail` giving more information 
/// on the error.
/// 
#[derive(Debug)]
pub enum AttributeEncryptionError {
    EncryptionError { detail : String },
    DecryptionError { detail : String }
}


/// Implements the plaintext of the scheme.
/// 
/// 
/// A plaintext is represented as a bytes vector.
#[derive(Debug)]
pub struct Plaintext {
    plaintext : Vec<u8>
}

impl Plaintext {
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }
}


impl From<Vec<u8>> for Plaintext {
    fn from(value: Vec<u8>) -> Self {
        Self {
            plaintext: value
        }
    }
}

impl From<&str> for Plaintext {
    fn from(value: &str) -> Self {
        Self {
            plaintext: String::from(value).into_bytes()
        }
    }
}

impl From<String> for Plaintext {
    fn from(value: String) -> Self {
        Self {
            plaintext: value.into_bytes()
        }
    }
}


impl From<&[u8]> for Plaintext {
    fn from(value: &[u8]) -> Self {
        Self {
            plaintext: Vec::from(value)
        }
    }
}

impl PartialEq for Plaintext {
    fn eq(&self, other: &Self) -> bool {
        self.plaintext == other.plaintext
    }
}


impl Display for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8(self.plaintext.clone()).unwrap())
    }
}


///
/// Representation of our ciphertext.
/// 
/// The ciphertext is composed of three attributes, two for the transformation purpose,
/// and another containing the access policy.
#[derive(Serialize, Deserialize, Debug)]
pub struct Ciphertext {
    e : Ac17CpCiphertext,
    c : Vec<u8>,
    y : String,
    hash_c : [u8; 32]
}

impl Ciphertext {
    pub fn len(&self) -> usize {
        let encoded_e = serialize(&self.e).unwrap();
        encoded_e.len() + self.c.len()
    }

    pub fn hash_without_trusted_hash_c(&self) -> [u8; 32] {
        let hash_c = mk256(&self.c);
        self.hash(hash_c)
    }

    pub fn hash_with_trusted_hash_c(&self) -> [u8; 32] {
        self.hash(self.hash_c)
    }

    fn  hash(&self, hash_c : [u8; 32]) -> [u8; 32] {
        let encoded_e =  serialize(&self.e).unwrap();
        let mut cipher = Sha512_256::new();
        cipher.update( &hash_c );
        cipher.update( &encoded_e );
        cipher.finalize().into()
    }
}

/// Wrapper on the 
/// attribute-based encryption public key.
pub struct PublicKey {
    pk : Ac17PublicKey
}

/// Wrapper on the 
/// attribute-based encryption master secret key.
pub struct MasterSecretKey {
    msk : Ac17MasterKey
}


impl MasterSecretKey {
    /// Provides a decryption key associated to the provided attribute.
    /// 
    /// ```
    /// use daft::abe::abe_setup;
    /// 
    /// let (pk, msk) = abe_setup();
    /// let attr = vec!["A".to_string(), "B".to_string()];
    /// let sk = msk.gen_secret_key( attr );
    /// ```
    pub fn gen_secret_key( &self, x : Vec<String> ) -> SecretKey {
        let sk = cp_keygen(&self.msk, &x);
        SecretKey { x, sk: sk.unwrap() }
    }

    
}



/// Wrapper on the
/// attribute-based encryption secret key.
pub struct SecretKey {
    x : Vec<String>,
    sk : Ac17CpSecretKey
}



pub fn abe_setup() -> (PublicKey, MasterSecretKey) {
    let (pk, msk) = setup();
    (
        PublicKey { pk },
        MasterSecretKey { msk }
    )
}


const MESSAGE_LENGTH  : usize = 32;

pub fn abe_encrypt(
    pk : &PublicKey,
    policy: &String,
    plaintext: &Plaintext
) -> Result<Ciphertext, AttributeEncryptionError>  
{
    // generate the thead
    let mut rng = thread_rng();

    // Randomly chosen a message of s byte.
    let mut sigma = [0u8; MESSAGE_LENGTH];
    sigma = sigma.map(|x| rng.gen::<u8>() );

    abe_encrypt_with_iv(pk, policy, plaintext, sigma)
}


pub fn abe_encrypt_with_iv( 
    pk : &PublicKey,
    policy: &String,
    plaintext: &Plaintext,
    sigma : [u8; 32]
) -> Result<Ciphertext, AttributeEncryptionError>
{
   
   let size = plaintext.len();

    // Computes the hash of sigma
    let start = Instant::now();
    let mut hasher = Sha512_256::new();
    hasher.update(&sigma);
    let a : [u8; 32] = hasher.finalize().into();
    debug!("\t{}: encryption:  a: {}", size, start.elapsed().as_millis());

    // compute the symmetric encryption of the plaintext
    let start = Instant::now();
    let cipher : Cipher = Cipher::aes_256_ctr();
    debug!("\t{}: encryption:  cipher init: {}", size, start.elapsed().as_millis());

    let start = Instant::now();
    let c = {
        let ciphertext = encrypt( cipher,  &a, None, &plaintext.plaintext);
        match ciphertext {
            Ok(ciphertext) => ciphertext,
            Err(encryption_error) => {
                return Err(AttributeEncryptionError::EncryptionError { 
                    detail: format!("Symmetric Encryption Error: {:?}", encryption_error)
                });
            } 
        }  
    };
    debug!("\t{}: encryption:  symmetric: {}", size, start.elapsed().as_millis());
    

    // compute the hash of the concatenation of sigma and the generated ciphertext
    let mut hasher = Sha512_256::new();
    let start = Instant::now();
    let hash_c = mk256(&c);
    hasher.update(&sigma);
    hasher.update(&hash_c);
    debug!("\t{}: encryption:  h: {}", size, start.elapsed().as_millis());
    let h : [u8; 32] = hasher.finalize().into();
  

    // compute the encryption of sigma with the given access policy, using h as a random
    let start = Instant::now();
    let crypto_rng  = ChaCha8Rng::from_seed(h);
    let e = cp_encrypt_rng(
        &pk.pk, 
        policy, 
        &sigma, 
        PolicyLanguage::HumanPolicy, 
        crypto_rng
    );
    debug!("\t{}: encryption:  abe: {}", size, start.elapsed().as_millis());

    if e.is_err() {
        return Err(AttributeEncryptionError::EncryptionError { 
            detail: format!("{:?}", e)
        });
    }

    Ok(Ciphertext {
        e: e.unwrap(),
        c: c,
        y: policy.clone(),
        hash_c
    })


}


macro_rules! decryption_error {
    ( $error:expr ) => {
        return Err(AttributeEncryptionError::DecryptionError {
            detail: String::from($error)
        }) 
    }
}

pub fn abe_decrypt( sk : &SecretKey, pk : &PublicKey, ciphertext: &Ciphertext ) -> Result<Plaintext, AttributeEncryptionError>{
    // we start by providing computing the decryption of the ABE ciphertext
    let sigma = cp_decrypt(&sk.sk, &ciphertext.e);
    if sigma.is_err() {
        decryption_error!("Invalid attribute");
    }
    let sigma = sigma.unwrap();
    debug!("sigma = {:?}", sigma);

    // compute the hash of a
    let mut hasher = Sha512_256::new();
    hasher.update(&sigma);
    let a : [u8; 32] = hasher.finalize().into();
    debug!("a = {:?}", a);

    // compute the hash of 
    let mut hasher = Sha512_256::new();
    let hash_c = mk256(&ciphertext.c);
    hasher.update(&sigma);
    hasher.update(&hash_c);
    let h : [u8; 32] = hasher.finalize().into();
    debug!("h = {:?}", h);

    // check that the ABE ciphertext is a valid encryption
    let crypto_rng  = ChaCha8Rng::from_seed(h);
    let e = cp_encrypt_rng(
        &pk.pk, 
        &ciphertext.y, 
        &sigma,
        PolicyLanguage::HumanPolicy, 
        crypto_rng
    );

    if e.is_err() {
        decryption_error!(format!("Error during ciphertext reproduction: {:?}", e));
    }
    if ! e.unwrap().eq(&ciphertext.e) {
        decryption_error!("Not recognized ciphertext");
    }


    // compute the symmetric decryption of the ciphertext
    let cipher : Cipher = Cipher::aes_256_ctr();
    let plaintext = {
        let plaintext = decrypt( cipher,  &a, None, ciphertext.c.as_slice());
        match plaintext {
            Ok(plaintext) => plaintext,
            Err(_) => {
                decryption_error!("Invalid decryption");
            } 
        }  
    };

    Ok(Plaintext::from(plaintext))
    

    
}






#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use crate::abe::{abe_decrypt, abe_encrypt_with_iv};

    use super::{Plaintext, abe_setup, abe_encrypt};

    #[test]
    pub fn replayable_encryption() {
        // generate the keys and policies
        let (pk, _) = abe_setup();
        let policy = String::from(r#""A" and "B""#);
        let plaintext = Plaintext::from(String::from("Hi !"));
        let mut rng = thread_rng();

        // Randomly chosen a message of s byte.
        let mut sigma = [0u8; 32];
        for index in 0..32 {
            sigma[index] = rng.gen();
        }

        // encryption the message a first time
        let result = abe_encrypt_with_iv(&pk, &policy, &plaintext, sigma);
        assert!(result.is_ok());
        let ct1 = result.unwrap();

        // encryption the message a second time
        let result = abe_encrypt_with_iv(&pk, &policy, &plaintext, sigma);
        assert!(result.is_ok());
        let ct2 = result.unwrap();

        assert_eq!(ct1.c, ct2.c);
        assert_eq!(ct1.e, ct2.e);
        assert_eq!(ct1.y, ct2.y)


    }

    #[test]
    pub fn plaintext_creation() {
        // initial plaintext creation
        let message = "Hi !";
        let pt1 = Plaintext::from(String::from(message));

        assert_eq!(true, pt1.eq(&Plaintext::from(String::from(message))));
        assert_eq!(false, pt1.eq(&Plaintext::from(String::from("Hello !"))));
    }

    #[test]
    pub fn key_generation() {
        abe_setup();
    }

    #[test]
    pub fn correctness() {
        // generate the keys and policies
        let (pk, msk) = abe_setup();
        let policy = String::from(r#""A" and "B""#);
        let sk = msk.gen_secret_key(vec!["A".to_string(), "B".to_string()]);

        // encryption the message
        let plaintext = Plaintext::from(String::from("Hi !"));
        let result = abe_encrypt(&pk, &policy, &plaintext);
        assert!(result.is_ok());
        let ciphertext = result.unwrap();

        // computes the decryption
        let recovered_plaintext = abe_decrypt(&sk, &pk, &ciphertext);
        assert!(recovered_plaintext.is_ok());
    }
} 
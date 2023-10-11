//!
//! This file contains the high-level code to handle the file sending
//! and the receiving. 
//! 
//! 

pub mod daft {
    use crate::abe::{PublicKey, MasterSecretKey, SecretKey, abe_encrypt, Plaintext, Ciphertext, abe_decrypt};
    use crate::abe::abe_setup;
    use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
    use ed25519_dalek::Signature;
    use rand::rngs::OsRng;


    // Type of the returned link.
    pub type Link = [u8;32];



    #[derive(Debug)]
    pub enum DAFTError {
        EncryptionError(String),
        VerificationError,
    }

    macro_rules! verification_failure {
        () => {
            return Err(DAFTError::VerificationError);
        };
    }

    
    /// Generate and returns the public and master secret keys.
    pub fn authority_key_gen() -> (PublicKey, MasterSecretKey) {
        abe_setup()
    }

    /// Generates and returns the sender key pair. 
    pub fn sender_key_gen() -> (VerifyingKey, SigningKey) {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    /// Prepare the file to be sent. Returns
    /// the link, the signature and the ciphertext.
    /// 
    /// # Arguments
    /// 
    /// * `signing_key` - Sender signing key.
    /// * `public_key` - The administration public key.
    /// * `access_policy` - Ciphertext access policy.
    /// * `data` - The plaintext file to be encrypted.
    /// 
    /// # Example
    /// 
    /// ```
    /// use daft::abe::Plaintext;
    /// use daft::daft::daft::{sender_key_gen, authority_key_gen, prepare_sending};
    /// 
    /// let (_, signing_key ) = sender_key_gen();
    /// let (apk, _) = authority_key_gen();
    /// let plaintext = Plaintext::from("Hello !");
    /// let access_policy =  String::from(r#""A" or "B""#);
    /// let response = prepare_sending(
    ///     &signing_key, 
    ///     &apk, 
    ///     access_policy, 
    ///     &plaintext
    /// );
    /// ```
    pub fn prepare_sending( 
        signing_key : &SigningKey, 
        public_key : &PublicKey, 
        access_policy : String, 
        data : &Plaintext
    ) ->  Result<(Link, Signature, Ciphertext), DAFTError>
    {
        // encrypt the file
        let encrypted_file = {
            let encryption_result = abe_encrypt(
                public_key, 
                &access_policy, 
                data
            );

            match encryption_result {
                Ok(encrypted_file) => encrypted_file,
                Err(enncryption_error) => {
                    return Err(DAFTError::EncryptionError(
                        format!("{:?}", enncryption_error)
                    ));
                }
                
            }
        };

        // compute and sign the hash
        let hash : [u8; 32] = encrypted_file.hash_with_trusted_hash_c();        
        let signature = signing_key.sign(&hash);

        Ok((hash, signature, encrypted_file))

    }


    /// Decrypts and verifies the received file.
    /// 
    /// # Arguments
    /// 
    /// - `verifying_key` - Verification key of the sender.
    /// - `secret_key` - The secret decryption key.
    /// - `public_key` - The administration public key.
    /// - `signature` - Link signature.
    /// - `hash` - The link.
    /// - `encrypted_file` - The encrypted file that should be decrypted.
    pub fn authenticate_received_file( 
        verification_key : &VerifyingKey,
        secret_key : &SecretKey,
        encryption_key : &PublicKey,
        signature : &Signature,
        hash : &Link,
        encrypted_file : &Ciphertext
    ) -> Result<Plaintext, DAFTError> {
        
        // check that the hash corresponds to the file
        let computed_hash : [u8; 32] = encrypted_file.hash_without_trusted_hash_c();
        if ! computed_hash.eq(hash) {
            verification_failure!();
        }


        // check the signature 
        let verified_signature = verification_key.verify(hash, signature);
        if verified_signature.is_err() {
            verification_failure!();
        } 

        // decrypt the file
        let decrypted_file : Plaintext = {
            let plaintext = abe_decrypt(
                secret_key, 
                encryption_key, 
                &encrypted_file
            );
            if plaintext.is_err() {
                println!("Plaintext decryption error: {:?}", plaintext);
                verification_failure!();
            }

            plaintext.unwrap()
        };
        
        Ok(decrypted_file)
       
    }
}

#[cfg(test)]
mod tests {
    use crate::{abe::{abe_setup, Plaintext}, daft::daft::authenticate_received_file};

    use super::daft::{sender_key_gen, prepare_sending};


    #[test]
    pub fn correctness() {
        let (verification_key, signing_key ) = sender_key_gen();
        let (apk, ask) = abe_setup();
        
        // plaintext encryption
        let plaintext = Plaintext::from("Hi !");
        let access_policy =  String::from(r#""A" or "B""#);
        let response = prepare_sending(
            &signing_key, 
            &apk, 
            access_policy, 
            &plaintext
        );
        println!("{:?}", response);
        assert!(response.is_ok());

        // generate the secret key for the receiver
        let attr = vec!["A".to_string()];
        let sk = ask.gen_secret_key(attr);

        // ciphertext decryption
        let (link, signature, ciphertext) = response.unwrap();
        let plaintext_response = authenticate_received_file(
            &verification_key, 
            &sk, 
            &apk, 
            &signature, 
            &link, 
            &ciphertext
        );
        assert!(plaintext_response.is_ok());

        // check that the recovered_plaintext matchs the initial plaintext
        let recovered_plaintext = plaintext_response.unwrap();
        assert_eq!( plaintext, recovered_plaintext );
        
    }

}
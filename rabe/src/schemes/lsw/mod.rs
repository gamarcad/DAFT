//! `LSW` scheme by Allison Lewko, Amit Sahai and Brent Waters.
//!
//! * Developped by Allison Lewko, Amit Sahai and Brent Waters, "Revocation Systems with Very Small Private Keys"
//! * Published in Security and Privacy, 2010. SP'10. IEEE Symposium on. IEEE
//! * Available from <http://eprint.iacr.org/2008/309.pdf>
//! * Type: encryption (key-policy attribute-based)
//! * Setting: bilinear groups (asymmetric)
//! * Authors: Georg Bramm
//! * Date:	04/2018
//!
//! # Examples
//!
//! ```
//!use rabe::schemes::lsw::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//!let (pk, msk) = setup();
//!let plaintext = String::from("our plaintext!").into_bytes();
//!let policy = String::from(r#""X" or "B""#);
//!let ct_kp: KpAbeCiphertext = encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
//!let sk: KpAbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
//!assert_eq!(decrypt(&sk, &ct_kp).unwrap(), plaintext);
//! ```
use rabe_bn::{Group, Fr, G1, G2, Gt, pairing};
use std::ops::Neg;
use utils::{
    tools::*,
    secretsharing::{gen_shares_policy, calc_coefficients, calc_pruned},
    aes::*,
    hash::{sha3_hash_fr, sha3_hash}
};
use rand::Rng;
use utils::policy::pest::{PolicyLanguage, parse};
use crate::error::RabeError;
#[cfg(not(feature = "borsh"))]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

/// A LSW Public Key (PK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct KpAbePublicKey {
    _g_g1: G1,
    _g_g2: G2,
    _g_g1_b: G1,
    _g_g1_b2: G1,
    _h_g1_b: G1,
    _e_gg_alpha: Gt,
}

/// A LSW Master Key (MSK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct KpAbeMasterKey {
    _alpha1: Fr,
    _alpha2: Fr,
    _beta: Fr,
    _h_g1: G1,
    _h_g2: G2,
}

/// A LSW Secret User Key (SK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct KpAbeSecretKey {
    _policy: (String, PolicyLanguage),
    _dj: Vec<(String, G1, G2, G1, G1, G1)>,
}

/// A LSW Ciphertext (CT)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct KpAbeCiphertext {
    _e1: Gt,
    _e2: G2,
    _ej: Vec<(String, G1, G1, G1)>,
    _ct: Vec<u8>,
}

/// The setup algorithm of LSW KP-ABE. Generates a new KpAbePublicKey and a new KpAbeMasterKey.
pub fn setup() -> (KpAbePublicKey, KpAbeMasterKey) {
    // random number generator
    let mut _rng = rand::thread_rng();
    // generate random alpha1, alpha2 and b
    let _alpha1:Fr = _rng.gen();
    let _alpha2:Fr = _rng.gen();
    let _beta:Fr = _rng.gen();
    let _alpha = _alpha1 * _alpha2;
    let _g_g1:G1 = _rng.gen();
    let _g_g2:G2 = _rng.gen();
    let _h_g1:G1 = _rng.gen();
    let _h_g2:G2 = _rng.gen();
    let _g_g1_b = _g_g1 * _beta;
    let _g_g1_b2 = _g_g1_b * _beta;
    let _h_g1_b = _h_g1 * _beta;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g_g1, _g_g2).pow(_alpha);
    // return PK and MSK
    return (
        KpAbePublicKey { _g_g1, _g_g2, _g_g1_b, _g_g1_b2, _h_g1_b, _e_gg_alpha},
        KpAbeMasterKey {_alpha1, _alpha2, _beta, _h_g1, _h_g2}
    );
}

/// The key generation algorithm of LSW KP-ABE.
/// Generates a KpAbeSecretKey using a KpAbePublicKey, a KpAbeMasterKey and a policy given as JSON String.
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_msk` - A Master Key (MSK), generated by the function setup()
///	* `_policy` - An access policy given as JSON String
///
pub fn keygen(
    _pk: &KpAbePublicKey,
    _msk: &KpAbeMasterKey,
    _policy: &String,
    _language: PolicyLanguage,
) -> Result<KpAbeSecretKey, RabeError> {
    // random number generator
    let mut _rng = rand::thread_rng();
    match parse(_policy, _language) {
        Ok(pol) => {
            let _shares = gen_shares_policy(_msk._alpha1, &pol, None).unwrap();
            let mut _d: Vec<(String, G1, G2, G1, G1, G1)> = Vec::new();
            for (_share_str, _share_value) in _shares.into_iter() {
                let _r:Fr = _rng.gen();
                if is_negative(&_share_str) {
                    let _share_hash = sha3_hash_fr(&_share_str).expect("could not hash _share_str");
                    _d.push((
                        _share_str.to_string(),
                        G1::zero(),
                        G2::zero(),
                        (_pk._g_g1 * _share_value) + (_pk._g_g1_b2 * _r),
                        _pk._g_g1_b * (_share_hash * _r) + (_msk._h_g1 * _r),
                        _pk._g_g1 * _r.neg(),
                    ));
                } else {
                    let _share_hash = sha3_hash(_pk._g_g1, &_share_str).expect("could not hash _share_str");
                    _d.push((
                        _share_str.to_string(),
                        (_pk._g_g1 * (_msk._alpha2 * _share_value))
                            + (_share_hash * _r),
                        _pk._g_g2 * _r,
                        G1::zero(),
                        G1::zero(),
                        G1::zero(),
                    ));
                }
            }
            return Ok(KpAbeSecretKey {
                _policy: (_policy.clone(), _language),
                _dj: _d,
            });
        },
        Err(e) => Err(e)
    }
}

/// The encrypt algorithm of LSW KP-ABE. Generates a new KpAbeCiphertext using an KpAbePublicKey, a set of attributes given as String Vector and some plaintext data given as [u8].
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_attributes` - A set of attributes given as String Vector
///	* `_plaintext` - plaintext data given as a Vector of u8
///
pub fn encrypt(
    _pk: &KpAbePublicKey,
    _attributes: &Vec<String>,
    _plaintext: &[u8],
) -> Option<KpAbeCiphertext> {
    if _attributes.is_empty() || _plaintext.is_empty() {
        return None;
    } else {
        // random number generator
        let mut _rng = rand::thread_rng();
        // attribute vector
        let mut _ej: Vec<(String, G1, G1, G1)> = Vec::new();
        // random secret
        let _s:Fr = _rng.gen();
        // sx vector
        let mut _sx: Vec<Fr> = Vec::new();
        _sx.push(_s);
        for (_i, _attr) in _attributes.iter().enumerate() {
            _sx.push(_rng.gen());
            _sx[0] = _sx[0] - _sx[_i];
        }
        for (_i, _attr) in _attributes.into_iter().enumerate() {
            _ej.push((
                _attr.to_string(),
                sha3_hash(_pk._g_g1, &_attr).expect("could not hash _attr") * _s,
                _pk._g_g1_b * _sx[_i],
                (_pk._g_g1_b2 * (_sx[_i] * sha3_hash_fr(&_attr).expect("could not hash _attr"))) + (_pk._h_g1_b * _sx[_i]),
            ));
        }
        // random message
        let _msg: Gt = _rng.gen();
        let _e1 = _pk._e_gg_alpha.pow(_s) * _msg;
        let _e2 = _pk._g_g2 * _s;
        let _ct = encrypt_symmetric(_msg, &_plaintext.to_vec()).unwrap();
        //Encrypt plaintext using derived key from secret
        Some(KpAbeCiphertext {_e1, _e2, _ej, _ct})
    }
}

/// The decrypt algorithm of LSW KP-ABE. Reconstructs the original plaintext data as Vec<u8>, given a KpAbeCiphertext with a matching KpAbeSecretKey.
///
/// # Arguments
///
///	* `_sk` - A Secret Key (SK), generated by the function keygen()
///	* `_ct` - A LSW KP-ABE Ciphertext
///
pub fn decrypt(_sk: &KpAbeSecretKey, _ct: &KpAbeCiphertext) -> Result<Vec<u8>, RabeError> {
    let _attrs_str = _ct
        ._ej
        .iter()
        .map(|values| values.clone().0.to_string())
        .collect::<Vec<_>>();
    match parse(_sk._policy.0.as_ref(), _sk._policy.1) {
        Ok(pol) => {
            let _pruned = calc_pruned(&_attrs_str, &pol, None);
            return match _pruned {
                Err(e) => Err(e),
                Ok(_p) => {
                    let (_match, _list) = _p;
                    if _match {
                        let mut _prod_t = Gt::one();
                        let mut _z_y = Gt::one();
                        let _coeffs: Vec<(String, Fr)> = calc_coefficients(&pol, Some(Fr::one()), None).unwrap();
                        for _attr_str in _list.iter() {
                            let _sk_attr = _sk
                                ._dj
                                .iter()
                                .filter(|_attr| _attr.0 == _attr_str.to_string())
                                .nth(0)
                                .unwrap();
                            let _ct_attr = _ct
                                ._ej
                                .iter()
                                .filter(|_attr| _attr.0 == _attr_str.to_string())
                                .nth(0)
                                .unwrap();
                            let _coeff_attr = _coeffs
                                .iter()
                                .filter(|_attr| _attr.0 == _attr_str.to_string())
                                .nth(0)
                                .unwrap();
                            if is_negative(&_attr_str) {
                                // TODO !!
                                /*let _sum_e4 = G2::zero();
                                let _sum_e5 = G2::zero();
                                _prod_t = _prod_t *
                                    (pairing(sk._d_i[_i].3, ct._e2) *
                                         (pairing(sk._d_i[_i].4, _sum_e4) * pairing(sk._d_i[_i].5, _sum_e5))
                                             .inverse());
                                */
                            } else {
                                _z_y = pairing(_sk_attr.1, _ct._e2)
                                    * pairing(_ct_attr.1, _sk_attr.2).inverse();
                            }
                            _prod_t = _prod_t * _z_y.pow(_coeff_attr.1);
                        }
                        let _msg = _ct._e1 * _prod_t.inverse();
                        // Decrypt plaintext using derived secret from cp-abe scheme
                        decrypt_symmetric(_msg, &_ct._ct)
                    } else {
                        Err(RabeError::new("Error in lsw/decrypt: attributes do not match policy."))
                    }
                }
            }
        },
        Err(e)=> Err(e)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn and() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        att_matching.push(String::from("C"));
        // our plaintext
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children": [{"name": "C"}, {"name": "B"}]}"#);
        // kp-abe ciphertext
        let ct_kp_matching: KpAbeCiphertext = encrypt(&pk, &att_matching, &plaintext).unwrap();
        // a kp-abe SK key
        let sk: KpAbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with matching sk
        assert_eq!(decrypt(&sk, &ct_kp_matching).unwrap(), plaintext);
    }

    #[test]
    fn or() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        att_matching.push(String::from("C"));
        // our plaintext
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "X"}, {"name": "B"}]}"#);
        // kp-abe ciphertext
        let ct_kp_matching: KpAbeCiphertext = encrypt(&pk, &att_matching, &plaintext).unwrap();
        // a kp-abe SK key
        let sk: KpAbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with matching sk
        assert_eq!(decrypt(&sk, &ct_kp_matching).unwrap(), plaintext);
    }

    #[test]
    fn or_and() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("Y"));
        att_matching.push(String::from("Z"));
        // our plaintext
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let policy =
            String::from(r#"{"name": "or", "children": [{"name": "X"}, {"name": "and", "children": [{"name": "Y"}, {"name": "Z"}]}]}"#);
        // kp-abe ciphertext
        let ct_kp_matching: KpAbeCiphertext = encrypt(&pk, &att_matching, &plaintext).unwrap();
        // a kp-abe SK key
        let sk: KpAbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with matching sk
        assert_eq!(decrypt(&sk, &ct_kp_matching).unwrap(), plaintext);
    }

    #[test]
    fn not() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        // our plaintext
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "X"}, {"name": "Y"}]}"#);
        // kp-abe ciphertext
        let ct_kp_matching: KpAbeCiphertext = encrypt(&pk, &att_matching, &plaintext).unwrap();
        // a kp-abe SK key
        let sk: KpAbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with matching sk
        let res = decrypt(&sk, &ct_kp_matching);
        assert_eq!(res.is_ok(), false);
    }
}

use sha2::Sha256;
use rand::{TryRngCore};
use aes_gcm::aead::{Aead};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::{Hkdf};

use crate::errors::{Crypto as CryptoError};

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let info = generate_random_vector(0).as_slice().to_owned();
    let mut output = vec![0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &password.as_bytes());
    match hk.expand(info.as_slice(), &mut output) {
        Ok(_) => Ok(output),
        Err(e) => Err(CryptoError::KeyDeriveFailed)
    }
}

pub fn encrypt_chunk(input: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let derived_key = derive_key(passphrase, salt)?;
    match Aes256Gcm::new_from_slice(derived_key.as_slice()) {
        Ok(cipher) => {
            match cipher.encrypt(&Nonce::from_slice(nonce), input) {
                Ok(encrypted) => Ok(encrypted),
                Err(_) => Err(CryptoError::EncryptFailed)
            }
        },
        Err(e) => Err(CryptoError::CipherInitializationFailed)
    }
}

pub fn decrypt_chunk(input: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let derived_key = derive_key(passphrase, salt)?;

    let cipher= Aes256Gcm::new_from_slice(&derived_key)
        .expect("could not generate cipher");
    match cipher.decrypt(&Nonce::from_slice(nonce), input.as_ref()) {
        Ok(decrypted) => Ok(decrypted),
        Err(e) => Err(CryptoError::DecryptFailed)
    }
}

#[cfg(feature = "test_utils")]
pub fn byte_vector_to_string(bytes_vector: &Vec<u8>) -> String {
    let mut output = String::with_capacity(bytes_vector.len());
    for &b in bytes_vector {
        output.push_str(format!("{}", b as char).as_str());
    }

    output
}
pub fn generate_random_vector(size: usize) -> Vec<u8> {
    let mut array = vec![0u8; size];
    let mut rng = rand::rng();
    match rng.try_fill_bytes(&mut array) {
        Ok(_) => array.to_vec(),
        Err(e) => {
            panic!("could not generate random vector of size {} : {:?}", size, e);
        }
    }
}

#[cfg(test)]
pub mod test {

    use crate::crypto::{decrypt_chunk, derive_key, encrypt_chunk};
    use crate::test_common as common;

    #[test]
    fn test_derive_key() {

        let initial = derive_key(
            common::PASSWORD.into(), common::SALT
        ).unwrap();

        for _ in 0..100 {
            let derived = derive_key(
                common::PASSWORD.into(), common::SALT
            ).unwrap();
            assert_eq!(initial, derived);
        }
        println!("Password and salt were derived 100 times and they always returned the same result!")
    }

    #[test]
    fn test_encryption() {
        let encrypted = encrypt_chunk(
            common::CHUNK.as_bytes(),
            common::PASSWORD,
            common::SALT,
            common::NONCE
        ).unwrap();

        assert_eq!(common::EXPECTED_ENCRYPTED, encrypted.as_slice());
        println!("Encrypted chunk with the same nonce, password and salt returned expected result!")
    }

    #[test]
    fn test_decryption() {
        let decrypted = decrypt_chunk(
            common::EXPECTED_ENCRYPTED,
            common::PASSWORD,
            common::SALT,
            common::NONCE
        ).unwrap();

        assert_eq!(common::CHUNK.as_bytes(), decrypted.as_slice());
        println!("Decryption successful!")
    }
}
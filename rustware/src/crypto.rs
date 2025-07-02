use sha2::Sha256;
use rand::{TryRngCore};
use aes_gcm::aead::{Aead};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::{Hkdf};
use crate::errors::{Crypto as CryptoError, Error};

/// Takes a password and a salt to derive a key. This is mostly used
/// when encrypting/decrypting files. Produces a deterministic value -
/// meaning the output will always be the same if you use the same password
/// and salt. The password can be as long as you want, but the salt must be
/// 12 bytes. It will always output a 32 byte long vector.
///
/// This function uses HKDF - HMAC sha256.
/// Intended to be used with Aes256Gcm
///
/// # Errors
///
/// * This function can return errors when expanding the derived key into
///     a vector (when returning)
///
/// # Examples
/// ```no_run
///  use rustware::crypto::derive_key;
///
///  let password = "Sup3rS3cr37P4ssw0rd";
///  let salt: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
///  println!(
///     "Password : {}, Salt : {:?} , Derived : {:?}",
///     password, salt, derive_key(password, salt).unwrap()
///  );
/// ```
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, Error> {
    let info = generate_random_vector(0).as_slice().to_owned();
    let mut output = vec![0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &password.as_bytes());
    match hk.expand(info.as_slice(), &mut output) {
        Ok(_) => Ok(output),
        Err(_) => Err(CryptoError::KeyDeriveFailed.into())
    }
}

/// This function does the reverse of encrypt_chunk. If you take encrypted bytes and
/// supply the right passphrase, salt and nonce, the output will be the original data
///
/// # Errors
///     * derive_key error (could not derive key from passphrase and salt)
///     * Decryption failiure (either due to a decryption error or because
///         the cipher could not be initialized properly
///
/// # Examples
/// ```
/// use rustware::crypto;
/// use rustware::crypto::{decrypt_chunk, encrypt_chunk};
///
/// let data = "Secret nuclear codes : 12345".as_bytes();
/// let salt: &[u8] = &[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255];
/// let password = "Brute_Force_this_sucka!!";
/// let nonce: &[u8] = &[1, 1, 1, 1,1, 1,1, 1,1, 1,1, 1];
///
/// let encrypted_data = encrypt_chunk(data, password, salt, nonce).unwrap();
/// let decrypted_data = decrypt_chunk(encrypted_data.as_slice(), password, salt, nonce).unwrap();
///
/// println!("Encrypted : {:?}", encrypted_data);
/// println!("Decrypted : {:?}", decrypted_data);
/// ```
pub fn decrypt_chunk(input: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
    let derived_key = derive_key(passphrase, salt)?;

    let cipher= Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|_| CryptoError::KeyDeriveFailed)?;
    match cipher.decrypt(&Nonce::from_slice(nonce), input.as_ref()) {
        Ok(decrypted) => Ok(decrypted),
        Err(_) => Err(CryptoError::DecryptFailed.into())
    }
}

/// This function takes a chunk (array of bytes) and encrypts it using a
/// passphrase (password) and a salt (randomly generated ideally).
///
/// Derives a key using the password and salt and then encrypts the chunk
/// using Aes256Gcm. Returns the encrypted data (or an error).
///
/// We also include a nonce, which is a unique salt for every chunk.
/// The nonce is kind of like an identifier for the chunk that also
/// affects the output of encryption. Helps us make sure data is even
/// more unique and unreadable.
///
/// # Errors
/// Many steps of chunk encryption can go wrong :
///
/// * key derivation error (when generating HMAC sha256 encryption key)
/// * encryption error (either due to an unexpected IO error or an invalid
///     encryption key)
/// * Cipher initialization failure
///
/// # Examples
///
/// ```no_run
/// use rustware::crypto;
/// use rustware::crypto::encrypt_chunk;
///
/// let data = "Secret nuclear codes : 12345".as_bytes();
/// let salt: &[u8] = &[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255];
/// let password = "Brute_Force_this_sucka!!";
/// let nonce: &[u8] = &[1, 1, 1, 1,1, 1,1, 1,1, 1,1, 1];
///
/// println!("Encrypted : {:?}", encrypt_chunk(data, password, salt, nonce)?);
/// ```
pub fn encrypt_chunk(input: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
    let derived_key = derive_key(passphrase, salt)?;
    match Aes256Gcm::new_from_slice(derived_key.as_slice()) {
        Ok(cipher) => {
            match cipher.encrypt(&Nonce::from_slice(nonce), input) {
                Ok(encrypted) => Ok(encrypted),
                Err(_) => Err(CryptoError::EncryptFailed.into())
            }
        },
        Err(_) => Err(CryptoError::CipherInitializationFailed.into())
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

/// This method uses secure rng in order to generate salts and nonces.
///
/// # Errors
///     * Infaliable - should never happen. If it does, something's really wrong
///         (thus why we panic)
///
/// # Examples
/// ```no_run
///     use rustware::crypto::generate_random_vector;
///
/// let my_vec = generate_random_vector(12);
/// println!("Random vector : {:?}", my_vec);
/// ```
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
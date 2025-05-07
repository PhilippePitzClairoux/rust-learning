use sha2::Sha256;
use rand::{TryRngCore};
use aes_gcm::aead::{Aead};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::generic_array::GenericArray;
use hkdf::Hkdf;

pub enum CryptoErrors {
    CannotDeriveKey,
    CannotFormCipher,
    CannotEncryptChunk,
    CannotDecryptChunk,
}

pub fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    let info = generate_random_vector(0).as_slice().to_owned();
    let mut output = vec![0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &password.as_bytes());
    hk.expand(info.as_slice(), &mut output)
        .expect("cannot generate key");

    output
}

pub fn encrypt_chunk(input: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let derived_key = derive_key(passphrase, salt);
    let cipher = Aes256Gcm::new_from_slice(derived_key.as_slice())
        .expect("cannot create Aes256Gcm");

    match cipher.encrypt(&Nonce::from_slice(nonce), input.as_ref()) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            panic!("could not encrypt data: {:?}", e);
        }
    }
}

pub fn decrypt_chunk(input: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let derived_key = derive_key(passphrase, salt);
    let key = GenericArray::from_slice(&derived_key);

    let cipher= Aes256Gcm::new(key);
    match cipher.decrypt(&Nonce::from_slice(nonce), input.as_ref()) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            panic!("could not encrypt data: {:?}", e);
        }
    }
}

pub fn print_random_bytes(bytes_vector: &Vec<u8>) -> String {
    let mut output = vec![0u8];
    for &b in bytes_vector {
        if let Ok(_b) = std::str::from_utf8(&[b]) {
            output.push(b);
        } else {
            output.extend(format!("\\x{:02x}", b).as_bytes());
        }
    }

    String::from_utf8(output).unwrap()
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
mod test {
    use crate::crypto::{decrypt_chunk, derive_key, encrypt_chunk};
    const SALT: &[u8] = &[1,2,3,4,5,6,7,8,9,10,11,12];
    const PASSWORD: &str = "Very_Secure_Password!!!";
    const EXPECTED_ENCRYPTED: &[u8] = &[64, 250, 40, 219, 82, 175, 140, 7, 239, 112, 119, 36, 125, 10, 218, 84, 150, 154, 216, 64, 161, 147, 23];
    const NONCE: &[u8] = &[12,11,10,9,8,7,6,5,4,3,2,1];
    const CHUNK: &str = "yikes!!";

    #[test]
    fn test_derive_key() {

        let initial = derive_key(PASSWORD.into(), SALT);

        for _ in 0..100 {
            assert_eq!(initial, derive_key(PASSWORD.into(), SALT));
        }
        println!("Password and salt were derived 100 times and they always returned the same result!")
    }

    #[test]
    fn test_encryption() {
        assert_eq!(EXPECTED_ENCRYPTED, encrypt_chunk(CHUNK.as_bytes(), PASSWORD, SALT, NONCE));
        println!("Encrypted chunk with the same nonce, password and salt returned expected result!")
    }

    #[test]
    fn test_decryption() {
        assert_eq!(CHUNK.as_bytes(), decrypt_chunk(EXPECTED_ENCRYPTED, PASSWORD, SALT, NONCE));
        println!("Decryption successful!")
    }
}
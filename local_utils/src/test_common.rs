pub const SALT: &[u8] = &[1,2,3,4,5,6,7,8,9,10,11,12];
pub const PASSWORD: &str = "Very_Secure_Password!!!";
pub const EXPECTED_ENCRYPTED: &[u8] = &[64, 250, 40, 219, 82, 175, 140, 7, 239, 112, 119, 36, 125, 10, 218, 84, 150, 154, 216, 64, 161, 147, 23];
pub const NONCE: &[u8] = &[12,11,10,9,8,7,6,5,4,3,2,1];
pub const CHUNK: &str = "yikes!!";
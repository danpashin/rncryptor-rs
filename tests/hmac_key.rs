
extern crate rncryptor;
extern crate hex;

use rncryptor::v3::types::*;

fn decode_hex(hex: &str) -> Vec<u8> {
    hex::decode(hex.replace(' ', "")).unwrap()
}

#[test]
fn can_generate_hmac_key() {
    let salt = Salt(Vec::from("deadbeef"));
    let password = "secret";
    let expected = HMACKey::from(decode_hex("8bb1feac 483aeb48 7805b2f0 b565b601 \
                                  0493e05b 148049a2 7fd9569d bc07b558"));
    let actual = HMACKey::new(&salt, password.as_bytes());

    assert_eq!(actual, expected)
}

#![feature(test)]
extern crate test;
extern crate hex;
extern crate rncryptor;

use rncryptor::v3::encryptor::Encryptor;
use rncryptor::v3;
use rncryptor::v3::types::*;
use test::Bencher;

#[bench]
fn bench_decryption(b: &mut Bencher) {
    let encryption_salt = Salt(hex::decode("0203040506070001").unwrap());
    let hmac_salt = Salt(hex::decode("0304050607080102").unwrap());
    let iv = IV::from(hex::decode("0405060708090a0b0c0d0e0f00010203").unwrap());
    let plain_text = (0..).take(1_000_000).collect::<Vec<_>>();
    let e = Encryptor::from_password("thepassword", encryption_salt, hmac_salt, iv)
        .and_then(|e| e.encrypt(&plain_text));
    match e {
        Err(_) => panic!("bench_encryption init failed."),
        Ok(encrypted) => b.iter(|| v3::decrypt("secret", &encrypted)),
    }
}

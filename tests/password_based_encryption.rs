use rncryptor::v3::{
    encryptor::Encryptor,
    types::{Salt, IV},
};

struct TestVector {
    password: &'static str,
    encryption_salt: &'static str,
    hmac_salt: &'static str,
    iv: &'static str,
    plain_text: &'static str,
    cipher_text: &'static str,
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex::decode(hex.replace(' ', "")).unwrap()
}

fn test_vector(vector: TestVector) {
    let encryption_salt = Salt(decode_hex(vector.encryption_salt));
    let hmac_salt = Salt(decode_hex(vector.hmac_salt));
    let iv = IV::from(decode_hex(vector.iv));
    let plain_text = decode_hex(vector.plain_text);
    let ciphertext = decode_hex(vector.cipher_text);
    let result = Encryptor::from_password(vector.password, encryption_salt, hmac_salt, iv)
        .and_then(|e| e.encrypt(&plain_text));
    match result {
        Err(e) => panic!("{:?}", e),
        Ok(encrypted) => assert_eq!(*encrypted.as_slice(), *ciphertext.as_slice()),
    }
}

#[test]
fn all_fields_empty_or_zero() {
    test_vector(TestVector {
        password: "a",
        encryption_salt: "0000000000000000",
        hmac_salt: "0000000000000000",
        iv: "00000000000000000000000000000000",
        plain_text: "",
        cipher_text: "03010000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 \
                      0000b303 9be31cd7 ece5e754 f5c8da17 00366631 3ae8a89d dcf8e3cb 41fdc130 \
                      b2329dbe 07d6f4d3 2c34e050 c8bd7e93 3b12",
    })
}

#[test]
fn one_byte() {
    test_vector(TestVector {
        password: "thepassword",
        encryption_salt: "0001020304050607",
        hmac_salt: "0102030405060708",
        iv: "02030405060708090a0b0c0d0e0f0001",
        plain_text: "01",
        cipher_text: "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f \
                      0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca \
                      545b7de3 de5b010a cbad0a9a 13857df6 96a8",
    })
}

#[test]
fn exactly_one_block() {
    test_vector(TestVector {
        password: "thepassword",
        encryption_salt: "0102030405060700",
        hmac_salt: "0203040506070801",
        iv: "030405060708090a0b0c0d0e0f000102",
        plain_text: "0123456789abcdef",
        cipher_text: "03010102 03040506 07000203 04050607 08010304 05060708 090a0b0c 0d0e0f00 \
                      01020e43 7fe80930 9c03fd53 a475131e 9a1978b8 eaef576f 60adb8ce 2320849b \
                      a32d7429 00438ba8 97d22210 c76c35c8 49df",
    })
}

#[test]
fn more_than_one_block() {
    test_vector(TestVector {
        password: "thepassword",
        encryption_salt: "0203040506070001",
        hmac_salt: "0304050607080102",
        iv: "0405060708090a0b0c0d0e0f00010203",
        plain_text: "0123456789abcdef 01234567",
        cipher_text: "03010203 04050607 00010304 05060708 01020405 06070809 0a0b0c0d 0e0f0001 \
                      0203e01b bda5df2c a8adace3 8f6c588d 291e03f9 51b78d34 17bc2816 581dc6b7 \
                      67f1a2e5 7597512b 18e1638f 21235fa5 928c",
    })
}

#[test]
fn multibyte_password() {
    test_vector(TestVector {
        password: "中文密码",
        encryption_salt: "0304050607000102",
        hmac_salt: "0405060708010203",
        iv: "05060708090a0b0c0d0e0f0001020304",
        plain_text: "23456789abcdef 0123456701",
        cipher_text: "03010304 05060700 01020405 06070801 02030506 0708090a 0b0c0d0e 0f000102 \
                      03048a9e 08bdec1c 4bfe13e8 1fb85f00 9ab3ddb9 1387e809 c4ad86d9 e8a60145 \
                      57716657 bd317d4b b6a76446 15b3de40 2341",
    })
}

#[test]
fn longer_text_and_password() {
    test_vector(TestVector {
        password: "It was the best of times, it was the worst of times; it was the age of wisdom, \
                   it was the age of foolishness;",
        encryption_salt: "0405060700010203",
        hmac_salt: "0506070801020304",
        iv: "060708090a0b0c0d0e0f000102030405",
        plain_text: "69 74 20 77 61 73 20 74 68 65 20 65 70 6f 63 68 20 6f 66 20 62 65 6c 69 65 \
                     66 2c 20 69 74 20 77 61 73 20 74 68 65 20 65 70 6f 63 68 20 6f 66 20 69 6e \
                     63 72 65 64 75 6c 69 74 79 3b 20 69 74 20 77 61 73 20 74 68 65 20 73 65 61 \
                     73 6f 6e 20 6f 66 20 4c 69 67 68 74 2c 20 69 74 20 77 61 73 20 74 68 65 20 \
                     73 65 61 73 6f 6e 20 6f 66 20 44 61 72 6b 6e 65 73 73 3b 20 69 74 20 77 61 \
                     73 20 74 68 65 20 73 70 72 69 6e 67 20 6f 66 20 68 6f 70 65 2c 20 69 74 20 \
                     77 61 73 20 74 68 65 20 77 69 6e 74 65 72 20 6f 66 20 64 65 73 70 61 69 72 \
                     3b 20 77 65 20 68 61 64 20 65 76 65 72 79 74 68 69 6e 67 20 62 65 66 6f 72 \
                     65 20 75 73 2c 20 77 65 20 68 61 64 20 6e 6f 74 68 69 6e 67 20 62 65 66 6f \
                     72 65 20 75 73 3b 20 77 65 20 77 65 72 65 20 61 6c 6c 20 67 6f 69 6e 67 20 \
                     64 69 72 65 63 74 6c 79 20 74 6f 20 48 65 61 76 65 6e 2c 20 77 65 20 77 65 \
                     72 65 20 61 6c 6c 20 67 6f 69 6e 67 20 74 68 65 20 6f 74 68 65 72 20 77 61 \
                     79 2e 0a 0a",
        cipher_text: "03010405 06070001 02030506 07080102 03040607 08090a0b 0c0d0e0f 00010203 \
                      0405d564 c7a99da9 21a6e7c4 078a8264 1d954795 51283167 a2c81f31 ab80c9d7 \
                      d8beb770 111decd3 e3d29bbd f7ebbfc5 f10ac87e 7e55bfb5 a7f487bc d3983570 \
                      5e83b9c0 49c6d695 2be011f8 ddb1a14f c0c92573 8de017e6 2b1d621c cdb75f29 \
                      37d0a1a7 0e44d843 b9c61037 dee2998b 2bbd740b 910232ee a7196116 8838f699 \
                      5b996417 3b34c0bc d311a2c8 7e271630 928bae30 1a8f4703 ac2ae469 9f3c285a \
                      bf1c55ac 324b073a 958ae52e e8c3bd68 f919c09e b1cd2814 2a1996a9 e6cbff5f \
                      4f4e1dba 07d29ff6 6860db98 95a48233 140ca249 419d6304 6448db1b 0f4252a6 \
                      e4edb947 fd0071d1 e52bc156 00622fa5 48a67739 63618150 797a8a80 e592446d \
                      f5926d0b fd32b544 b796f335 9567394f 77e7b171 b2f9bc5f 2caf7a0f ac0da7d0 \
                      4d6a8674 4d6e06d0 2fbe15d0 f580a1d5 bd16ad91 34800361 1358dcb4 ac999095 \
                      5f6cbbbf b185941d 4b4b71ce 7f9ba6ef c1270b78 08838b6c 7b7ef17e 8db919b3 4fac",
    })
}

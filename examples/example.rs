// Resources:
// - https://bitcoin.stackexchange.com/questions/89814/how-does-bip-39-mnemonic-work
// - https://learnmeabitcoin.com/technical/extended-keys
// - https://learnmeabitcoin.com/technical/hd-wallets
// - https://learnmeabitcoin.com/technical/mnemonic
// - https://iancoleman.io/bip39/
// - https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
// - https://bitcoinbriefly.com/ultimate-guide-to-bitcoin-wallets-seeds-private-keys-public-keys-and-addresses/
// - https://rust-lang-nursery.github.io/rust-cookbook/cryptography/encryption.html
// - https://www.liavaag.org/English/SHA-Generator/HMAC/
// - https://bitcointalk.org/index.php?topic=5288888.0
// - https://medium.com/mycrypto/the-journey-from-mnemonic-phrase-to-address-6c5e86e11e14
// - https://academy.bit2me.com/en/que-es-la-master-private-key/
// - https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
// - https://docs.rs/secp256k1/latest/secp256k1/#functions
// - https://bitcoin.stackexchange.com/questions/61660/how-can-extended-public-keys-generate-child-public-keys-without-generating-the-c
// - https://medium.com/@robbiehanson15/the-math-behind-bip-32-child-key-derivation-7d85f61a6681
// - https://andrea.corbellini.name/ecc/interactive/modk-add.html
// - https://en.bitcoin.it/wiki/Secp256k2
// - https://www.rapidtables.com/convert/number/binary-to-hex.html
use std::fmt::UpperHex;
use std::fmt::Write;
use std::num::{NonZeroU32, ParseIntError};
use std::str::FromStr;

use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::util::base58::check_encode_slice;
use create_bitcoin_private_key::bip39::WORDS;
use create_bitcoin_private_key::create_private_key;
use hmac_sha512::HMAC;
use num_bigint::BigInt;
use num_bigint::BigUint;
use rand::prelude::*;
use rand::{random, rngs::StdRng, thread_rng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_chacha::ChaCha8Rng;
use rand_pcg::Pcg64;
use rand_seeder::{Seeder, SipHasher};
use ring::{digest, pbkdf2};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
pub fn convert_hex_to_decimal(hex: String) -> BigUint {
    println!("..{}", hex);
    let hex = "f9cf43a313496a007fe4fc1c4fb996238b4ace646d7ada0c1ffbf37653b991e9";
    // let hex = "7e48c5ab7f43e4d9c17bd9712627dcc76d4df2099af7c8e5";
    // let a: BigInt = 13083591726159223555551223938753535127604258367126228576140903598401097365714201702017529413442114868104244686915389844693808367317716621188940830798420643;
    let z = hex.parse::<BigUint>().unwrap();
    println!("big_num: {}", z);

    // let z = BigUint::from_str(&hex, 16);
    z
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

// Notes
// - A hexidecimal is represetnted by only 4 bits (one byte). We use u8 here because we can't use a
// u4.
// - Check work here: https://iancoleman.io/bip39/
// - https://bitcoin.stackexchange.com/questions/89814/how-does-bip-39-mnemonic-work

// Use this many bits when you want to have 12 words
fn get_128_bits_of_entropy() -> [u8; 32] {
    let mut data = [0u8; 32];
    let byte_array = rand::thread_rng().fill_bytes(&mut data);
    data
}

// Use this many bits when you want to have 24 words
fn get_256_bits_of_entropy() -> [u8; 64] {
    let mut data = [0u8; 64];
    let byte_array = rand::thread_rng().fill_bytes(&mut data);
    data
}

fn get_hex_string_from_entropy_byte_array(entropy_byte_array: &[u8]) -> String {
    // Use that array to then create a length 32 array but with hexidecimal values, since we want
    // each item of the array to represent only 4 bits, which is how many bits a hex represents
    let entropy_array_with_base_16_numbers: Vec<u8> =
        entropy_byte_array.iter().map(|num| num % 16).collect();
    // turn hex byte array into hex string
    let hex_string = entropy_array_with_base_16_numbers
        .iter()
        .map(|byte| format!("{:x}", byte))
        .collect::<String>();
    hex_string
}

fn sha256_entropy_hex_byte_array(hex_byte_array: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    sha256_result.to_vec()
}
fn convert_to_binary_string(num: u8, bits_to_show_count: u64) -> String {
    fn crop_letters(s: &str, pos: usize) -> &str {
        match s.char_indices().skip(pos).next() {
            Some((pos, _)) => &s[pos..],
            None => "",
        }
    }
    fn format_binary_with_4_bits(num: u8) -> String {
        // The 06 pads with zeros to a width of 6. That width includes 0b (length=2)
        format!("{:#06b}", num)
    }
    fn format_binary_with_8_bits(num: u8) -> String {
        // The 10 pads with zeros to a width of 10. That width includes 0b (length=2)
        format!("{:#010b}", num)
    }
    let binary_string_with_prefix = match bits_to_show_count {
        4 => format_binary_with_4_bits(num),
        8 => format_binary_with_8_bits(num),
        _ => panic!(
            "binary_string_without_prefix: bits_to_show_count of {} not supported",
            bits_to_show_count
        ),
    };
    let binary_string_without_prefix = crop_letters(&binary_string_with_prefix, 2);
    binary_string_without_prefix.to_string()
}

fn get_binary_string_for_byte_array(byte_array: &Vec<u8>) -> String {
    let mut binary_string = String::new();
    for i in byte_array {
        let binary_str = convert_to_binary_string(*i, 8);
        binary_string.push_str(binary_str.as_str())
    }
    binary_string
}
fn split_string_with_spaces_for_substrings_with_length(s: &str, length: u64) -> String {
    let string_with_spaces_seperating_substrings =
        s.chars().enumerate().fold(String::new(), |acc, (i, c)| {
            //if i != 0 && i == 11 {
            if i != 0 && (i % length as usize == 0) {
                format!("{} {}", acc, c)
            } else {
                format!("{}{}", acc, c)
            }
        });
    string_with_spaces_seperating_substrings
}

fn split_binary_string_into_framents_of_11_bits(binary_string: &str) -> Vec<String> {
    let entropy_plus_checksum_binary_with_spaces_seperating =
        split_string_with_spaces_for_substrings_with_length(&binary_string, 11);
    let word_binary: Vec<&str> = entropy_plus_checksum_binary_with_spaces_seperating
        .split(" ")
        .collect();
    word_binary.iter().map(|&s| s.to_string()).collect()
}

fn convert_binary_to_int(binary_string: &str) -> isize {
    let bin_idx = binary_string;
    let intval = isize::from_str_radix(bin_idx, 2).unwrap();
    intval
}
fn serialize_child_key(
    key: &String,
    parent_public_key: &String,
    child_chain_code: &String,
    is_public: bool,
) -> String {
    fn create_fingerprint(parent_public_key_hex: String) -> String {
        let hex_byte_array = decode_hex(&parent_public_key_hex).unwrap();
        let mut hasher = Sha256::new();
        // write input message
        hasher.update(&hex_byte_array);
        // read hash digest and consume hasher
        let sha256_result = hasher.finalize();
        let sha256_result_array = sha256_result.to_vec();

        let ripemd160_result = ripemd160::Hash::hash(&sha256_result_array);
        let first_four_bytes = &ripemd160_result[..4];
        println!("{}", first_four_bytes.len());
        let first_four_hex = encode_hex(&first_four_bytes);
        first_four_hex
    }

    fn hash256(hex: &String) -> String {
        let hex_byte_array = decode_hex(&hex).unwrap();
        let mut hasher = Sha256::new();
        // write input message
        hasher.update(&hex_byte_array);
        // read hash digest and consume hasher
        let sha256_result = hasher.finalize();
        let sha256_result_array = sha256_result.to_vec();

        let hex_byte_array_2 = sha256_result_array;
        let mut hasher_2 = Sha256::new();
        // write input message
        hasher_2.update(&hex_byte_array_2);
        // read hash digest and consume hasher
        let sha256_result_2 = hasher_2.finalize();
        let sha256_result_array_2 = sha256_result_2.to_vec();
        encode_hex(&sha256_result_array_2)
    }
    fn checksum(hex: &String) -> String {
        let hash = hash256(&hex);
        let hash_byte_array = decode_hex(&hash).unwrap();
        let first_four_bytes = &hash_byte_array[0..=3];
        encode_hex(first_four_bytes)
    }

    fn base58_encode(hex_byte_array: Vec<u8>) -> String {
        let encoded = bitcoin::util::base58::encode_slice(&hex_byte_array);
        encoded
    }

    let version = if is_public { "0488b21e" } else { "0488ade4" };
    let key = if is_public {
        format!("{}", key)
    } else {
        format!("{}{}", "00", key)
    };

    let depth = "01";
    let parent_fingerprint = create_fingerprint(parent_public_key.to_string());
    println!("parent_fingerprint: {}", parent_fingerprint);
    let child_number = "00000000";
    let chain_code = child_chain_code;
    // let key = format!("{}{}", "00", private_key);
    let serialized = format!(
        "{}{}{}{}{}{}",
        version, depth, parent_fingerprint, child_number, chain_code, key
    );
    let serialized_bytes = decode_hex(&serialized).unwrap();
    println!("serialized: {}", serialized);
    let checksum = checksum(&serialized);
    println!("checksum: {}", checksum);
    let checksum_bytes = decode_hex(&checksum).unwrap();
    let serialized_with_checksum = format!("{}{}", serialized, checksum);
    let serialized_with_checksum_bytes = concat_u8(&serialized_bytes, &checksum_bytes);
    let base58_encoded_serialized_with_checksum = base58_encode(serialized_with_checksum_bytes);
    base58_encoded_serialized_with_checksum
    // checksum: 7a2a2640
    // serialized: 0488ade401018c12590000000005aae71d7c080474efaab01fa79e96f4c6cfe243237780b0df4bc36106228e310039f329fedba2a68e2a804fcd9aeea4104ace9080212a52ce8b52c1fb89850c72
}
fn get_child_extended_public_key(
    parent_chain_code: &[u8],
    parent_public_key: &String,
    parent_private_key: &[u8],
) -> (String, String) {
    println!("--------------------------------------");
    let parent_chain_code = parent_chain_code;
    let key = parent_chain_code;
    println!("MASTER CHAIN CODE: {:?}", encode_hex(key));
    let index: u32 = 0;
    let index_as_bytes = index.to_be_bytes();
    println!("BRO: {:?}", index_as_bytes);
    let parent_public_key_hex = parent_public_key.clone();
    let parent_public_key_as_bytes = decode_hex(&parent_public_key).unwrap();
    println!("PARENT Public KEY: {:?}", parent_public_key_hex);
    let parent_public_key_with_index_as_bytes =
        concat_u8(&parent_public_key_as_bytes, &index_as_bytes);
    println!(
        "data: {:?}",
        encode_hex(&parent_public_key_with_index_as_bytes)
    );

    let h = HMAC::mac(parent_public_key_with_index_as_bytes, key);
    println!("len: {:?}", h.len());
    println!("hmac: {:?}", encode_hex(&h));
    println!("hmac: {:?}", h.len());
    let left = &h[0..=31];
    let right = &h[32..];
    println!("left: {:?}", encode_hex(left));
    println!("right: {:?}", encode_hex(right));
    // let child_private_key = convert_hex_to_decimal(encode_hex(left)) as isize + convert_binary_to_int(&encode_hex(master_private_key));
    // let left_binary = get_binary_string_for_byte_array(&left.to_vec());
    // println!("left binary: {}", left_binary);
    // let master_private_key_binary = get_binary_string_for_byte_array(&master_private_key.to_vec());
    // println!("master_private_key_binary: {}", master_private_key_binary);
    // let right_binary = get_binary_string_for_byte_array(&right.to_vec());
    let sk = secp256k1::SecretKey::from_slice(left).expect("statistically impossible to hit");
    let parent_private_secret_key = SecretKey::from_str(&encode_hex(parent_private_key)).unwrap();

    let tweaked = sk
        .add_tweak(&parent_private_secret_key.into())
        .expect("statistically impossible to hit");

    // Source: "ckd_pub" function here: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
    let secp = Secp256k1::new();
    let sk = secp256k1::SecretKey::from_str(&encode_hex(left)).unwrap();
    println!("PARENT PUBLIC KEY!!: {}", parent_public_key_hex);
    let pk = secp256k1::PublicKey::from_str(&parent_public_key_hex)
        .expect("statistically impossible to hit");
    let tweaked = pk.add_exp_tweak(&secp, &sk.into()).unwrap();

    let child_public_key: String = tweaked.to_string();
    let child_chain_code: String = encode_hex(right);
    // let child_public_key = get_uncompressed_public_key_from_private_key(&child_private_key);

    println!("child public key!!: {}", child_public_key);
    println!("chain code!!: {}", child_chain_code);

    // child_public_key: 030204d3503024160e8303c0042930ea92a9d671de9aa139c1867353f6b6664e60
    // child_chain_code: 05aae71d7c080474efaab01fa79e96f4c6cfe243237780b0df4bc36106228e31
    return (child_public_key, child_chain_code);
}

fn main() {
    // 1) Use some cryptographically secure entropy generator to generate 128 bits of entropy.
    // Create array of length 32 and fill with a random u8;
    let entropy = get_128_bits_of_entropy();

    //let hex_string = "a4b836c41875815e8b153bc89091f1d85dd1ae47287289f5a50ff23cf41b8d21";
    //let hex_string = "da490f7254f80aa2f7e8dcb3c63a8404";
    let entropy_hex_string = get_hex_string_from_entropy_byte_array(&entropy);
    // let entropy_hex_string = "731180c4b776f6b961da802ff55b153f".to_string();
    let entropy_hex_byte_array = decode_hex(&entropy_hex_string).unwrap();

    // 2) Calculate the SHA256 of the entropy.
    let sha256_result = sha256_entropy_hex_byte_array(&entropy_hex_byte_array);
    // 3) Append the first entropy_length/32 bits of the SHA256 of the entropy at the end of the entropy. For example, in our case we will append the first 4 bits of the SHA256(entropy) to the entropy since our entropy is 128 bits.
    let entropy_hex_binary_string = get_binary_string_for_byte_array(&entropy_hex_byte_array);
    let bits_to_append_count = (&entropy_hex_binary_string.len()) / 32;
    let sha256_result_binary_string = get_binary_string_for_byte_array(&sha256_result);
    let checksum_binary_string = &sha256_result_binary_string[0..bits_to_append_count];

    // 4) Each word of the mnemonic represents 11 bits. Hence, if you check the wordlist you will find 2048 unique words. Now, divide the entropy + checksum into parts of 11 bits each.
    let entropy_plus_checksum_binary =
        format!("{}{}", entropy_hex_binary_string, checksum_binary_string);

    let word_binary = split_binary_string_into_framents_of_11_bits(&entropy_plus_checksum_binary);

    let words: Vec<String> = word_binary
        .iter()
        .map(|word_binary_string| {
            let word_num = convert_binary_to_int(word_binary_string);
            WORDS.get(word_num as usize).unwrap().to_string()
        })
        .collect();
    println!("{:?}", words);

    let mnemonic_sentence = words.join(" ");
    println!("{:?}", mnemonic_sentence);

    // ===== CREATE A PRIVATE KEY (512 bit seed) ==========================
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    let n_iter = NonZeroU32::new(2048).unwrap();
    let rng = thread_rng();
    // let rng = SystemRandom::new();

    // Optional passphase
    let passphrase = "woowee";
    let salt = format!("{}{}", "mnemonic", passphrase);
    let mut salt_as_bytes = salt.as_bytes().to_owned();
    // rand::thread_rng().fill_bytes(&mut salt);

    let password = mnemonic_sentence.clone();
    let mut password_as_bytes = password.as_bytes().to_owned();
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt_as_bytes,
        password.as_bytes(),
        &mut pbkdf2_hash,
    );
    println!("salt: {:?}", encode_hex(&salt_as_bytes));
    println!("PBKDF2 hash: {:?}", encode_hex(&pbkdf2_hash));

    let bip39_seed = encode_hex(&pbkdf2_hash);

    // DELETE
    // let bip39_seed = "21b70b9f412d3344188e48c9ddcbcd22b0a59d696e591414d39ae24fb6443398690edb17bac0e61391ba33904b1a095770add5bb4b3c3e0c967611ddcf769386".to_string();
    let bip39_seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af".to_string();
    let pbkdf2_hash = decode_hex(&bip39_seed).unwrap();

    println!("bip39 seed: {:?}", bip39_seed);
    // println!("Salt: {}", HEXUPPER.encode(&salt));
    // println!("PBKDF2 hash: {}", HEXUPPER.encode(&pbkdf2_hash));

    let wrong_password = "Definitely not the correct password";

    let should_fail = pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt.as_bytes(),
        wrong_password.as_bytes(),
        &pbkdf2_hash,
    );
    println!("should fail: {:?}", should_fail);

    // =============================
    let key = "Bitcoin seed";
    let h = HMAC::mac(pbkdf2_hash.to_vec(), key.as_bytes());
    println!("len: {:?}", h.len());
    println!("hmac: {:?}", encode_hex(&h));
    println!("hmac: {:?}", h.len());
    let left = &h[0..=31];
    let master_private_key = left;
    let master_private_key_hex = encode_hex(master_private_key);
    let right = &h[32..];
    let master_chain_code = right;
    println!("left: {:?}", encode_hex(left));
    println!("right: {:?}", encode_hex(right));
    println!("master_private_key: {:?}", encode_hex(master_private_key));
    println!("master_chain_code: {:?}", encode_hex(master_chain_code));
    // How do I get master public key:
    // https://learnmeabitcoin.com/technical/extended-keys
    // https://learnmeabitcoin.com/technical/hd-wallets
    fn get_uncompressed_public_key_from_private_key(private_key: &str) -> String {
        // Create 512 bit public key
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_str(private_key).unwrap();
        // We're getting the OLDER uncompressed version of the public key:
        //    Source: https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
        let public_key_uncompressed = secret_key.public_key(&secp).serialize();
        encode_hex(&public_key_uncompressed)
    }
    let master_public_key = get_uncompressed_public_key_from_private_key(&master_private_key_hex);
    println!("master_public_key: {:?}", master_public_key);

    // ============================= Normal Child extended private key ====================
    println!("--------------------------------------");
    //
    let key = master_chain_code;
    let index: i32 = 0;
    let index_as_bytes = index.to_be_bytes();
    println!("BRO: {:?}", index_as_bytes);
    let master_public_key_as_bytes = master_public_key.as_bytes();
    let master_public_key_as_bytes = decode_hex(&master_public_key).unwrap();
    let master_public_key_with_index_as_bytes =
        concat_u8(&master_public_key_as_bytes, &index_as_bytes);
    let h = HMAC::mac(master_public_key_with_index_as_bytes, key);
    println!("len: {:?}", h.len());
    println!("hmac: {:?}", encode_hex(&h));
    println!("hmac: {:?}", h.len());
    let left = &h[0..=31];
    let right = &h[32..];
    // let child_private_key = convert_hex_to_decimal(encode_hex(left)) as isize + convert_binary_to_int(&encode_hex(master_private_key));
    // let left_binary = get_binary_string_for_byte_array(&left.to_vec());
    // println!("left binary: {}", left_binary);
    // let master_private_key_binary = get_binary_string_for_byte_array(&master_private_key.to_vec());
    // println!("master_private_key_binary: {}", master_private_key_binary);
    // let right_binary = get_binary_string_for_byte_array(&right.to_vec());
    //  Source: 'ckd_priv" function here: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
    let sk = secp256k1::SecretKey::from_slice(left).expect("statistically impossible to hit");
    // let secp = Secp256k1::new();
    let master_private_secret_key = SecretKey::from_str(&encode_hex(master_private_key)).unwrap();

    let tweaked = sk
        .add_tweak(&master_private_secret_key.into())
        .expect("statistically impossible to hit");
    let child_private_key: String = tweaked.display_secret().to_string();
    let child_public_key = get_uncompressed_public_key_from_private_key(&child_private_key);

    println!("child private key!!: {}", child_private_key);
    println!("child chain code!!: {}", encode_hex(right));
    println!("child public key!!: {}", child_public_key);
    // println!("left: {}", encode_hex(left));
    // println!("master_private_key: {}", encode_hex(master_private_key));
    // println!("{}", convert_hex_to_decimal("af".to_string()))

    // ============================= HARDENED Child extended private key ====================
    println!("--------------------------------------");
    let key = master_chain_code;
    println!("MASTER CHAIN CODE: {:?}", encode_hex(key));
    let index: u32 = 2147483648; // # child index number (must between 2**31 and 2**32-1)
    let index_as_bytes = index.to_be_bytes();
    println!("BRO: {:?}", index_as_bytes);
    let master_private_key_as_bytes = master_private_key;
    println!(
        "PARENT PRIV KEY: {:?}",
        encode_hex(master_private_key_as_bytes)
    );
    let prefix_bytes = decode_hex("00").unwrap();
    let master_private_key_with_index_as_bytes =
        concat_u8(master_private_key_as_bytes, &index_as_bytes);
    let master_private_key_with_index_and_prefix_as_bytes =
        concat_u8(&prefix_bytes, &master_private_key_with_index_as_bytes);
    println!(
        "data: {:?}",
        encode_hex(&master_private_key_with_index_and_prefix_as_bytes)
    );

    let h = HMAC::mac(master_private_key_with_index_and_prefix_as_bytes, key);
    println!("len: {:?}", h.len());
    println!("hmac: {:?}", encode_hex(&h));
    println!("hmac: {:?}", h.len());
    let left = &h[0..=31];
    let right = &h[32..];
    // let child_private_key = convert_hex_to_decimal(encode_hex(left)) as isize + convert_binary_to_int(&encode_hex(master_private_key));
    // let left_binary = get_binary_string_for_byte_array(&left.to_vec());
    // println!("left binary: {}", left_binary);
    // let master_private_key_binary = get_binary_string_for_byte_array(&master_private_key.to_vec());
    // println!("master_private_key_binary: {}", master_private_key_binary);
    // let right_binary = get_binary_string_for_byte_array(&right.to_vec());
    //  Source: 'ckd_priv" function here: https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
    let sk = secp256k1::SecretKey::from_slice(left).expect("statistically impossible to hit");
    // let secp = Secp256k1::new();
    let master_private_secret_key = SecretKey::from_str(&encode_hex(master_private_key)).unwrap();

    let tweaked = sk
        .add_tweak(&master_private_secret_key.into())
        .expect("statistically impossible to hit");
    let hardened_child_private_key: String = tweaked.display_secret().to_string();
    let child_public_key =
        get_uncompressed_public_key_from_private_key(&hardened_child_private_key);

    println!("child private key!!: {}", hardened_child_private_key);
    println!("child chain code!!: {}", encode_hex(right));
    println!("child public key!!: {}", child_public_key);

    // ============================= NORMAL Child extended public key ====================
    let (child_public_key, child_chain_code) =
        get_child_extended_public_key(master_chain_code, &master_public_key, master_private_key);

    // ======================== SERIALIZE KEY ===================================
    let parent_public_key = master_public_key;
    let chain_code = child_chain_code.clone();
    let private_key = child_private_key;
    let public_key = child_public_key;

    let xpub = serialize_child_key(&public_key, &parent_public_key, &chain_code, true);
    let xprv = serialize_child_key(&private_key, &parent_public_key, &chain_code, false);
    println!("xpub: {}", xpub);
    println!("xprv: {}", xprv);
    // xprv9tuogRdb5YTgcL3P8Waj7REqDuQx4sXcodQaWTtEVFEp6yRKh1CjrWfXChnhgHeLDuXxo2auDZegMiVMGGxwxcrb2PmiGyCngLxvLeGsZRq
}

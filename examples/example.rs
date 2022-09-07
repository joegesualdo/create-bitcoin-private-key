use std::num::ParseIntError;

use create_bitcoin_private_key::bip39::WORDS;
use create_bitcoin_private_key::create_private_key;
use rand::prelude::*;
use rand::prelude::*;
use rand::{random, rngs::StdRng, thread_rng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_chacha::ChaCha8Rng;
use rand_pcg::Pcg64;
use rand_seeder::{Seeder, SipHasher};
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
pub fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}

// Notes
// - A hexidecimal is represetnted by only 4 bits (one byte). We use u8 here because we can't use a
// u4.

// CRUDE WAY -----------------------------------------------------------------------------------
fn get_random_8_bit_number() -> u8 {
    let mut rng = rand::thread_rng();
    let random_8_bit_number = rng.gen_range(0..u8::MAX);
    random_8_bit_number
}

// get number between 0 - 15;
fn get_random_base_16_number() -> u8 {
    let mut rng = rand::thread_rng();
    let random_base_16_number: u8 = rng.gen_range(0..=15);
    random_base_16_number
}

// get number between 0 - 15, that will represent a rand hex number between 0 - F;
fn get_random_hexidecimal_number() -> u8 {
    let random_8_bit_number = get_random_8_bit_number();
    let random_base_16_number = get_random_base_16_number();
    random_8_bit_number % (random_base_16_number + 1)
}

fn get_64_random_hexidecimal_bytes() -> Vec<u8> {
    vec![0; 64]
        .iter()
        .map(|_| get_random_hexidecimal_number())
        .collect()
}

fn get_random_256_bit_hexidecimal_string() -> String {
    get_64_random_hexidecimal_bytes()
        .iter()
        .map(|byte| format!("{:x}", byte))
        .collect::<String>()
}
// END CRUDE WAY -----------------------------------------------------------------------------------
//

fn main() {
    // let private_key = create_private_key();
    // println!("{}", private_key);
    // // let secp = Secp256k1::new();
    // let mut rng = rand::thread_rng();
    // let secret_key = SecretKey::new(&mut rng);
    // let private_key = secret_key.display_secret();
    // println!("secret_key: {:#?}", private_key);

    // let entropy: [u8; 16] = rng.gen();
    // println!("entropy: {:#?}", entropy);

    let random_128: u128 = random();
    let random_128_1: u128 = random();
    let random_128_2: u128 = random();
    let random_128_3: u128 = random();
    println!("rand 256 bit: {}", random_128);
    println!("rand 256 bit: {}", random_128_1);
    println!("rand 256 bit: {}", random_128_2);
    println!("rand 256 bit: {}", random_128_3);
    println!("random 8 bit number: {}", get_random_8_bit_number());
    println!("random base 16 number: {}", get_random_base_16_number());
    println!(
        "random hexidecimal number: {}",
        get_random_hexidecimal_number()
    );
    println!("random 64 bytes: {:?}", get_64_random_hexidecimal_bytes());
    println!(
        "random 256 bit hex string: {:?}",
        get_random_256_bit_hexidecimal_string()
    );

    // Seed u8 from integer seed
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(10);
    println!("Random f32: {}", rng.gen::<u8>());

    // Create a random byte array
    let mut data = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut data);
    println!("{:?}", data);

    // Using a fresh seed (direct from the OS)
    let mut rng = ChaCha20Rng::from_entropy();
    println!("{}", rng.gen_range(0..100));

    // create and store a seed. Then use that seed in the generator
    let mut seed: <ChaCha8Rng as SeedableRng>::Seed = Default::default();
    println!("{:?}", seed);
    thread_rng().fill(&mut seed);
    let mut rng = ChaCha8Rng::from_seed(seed);
    println!("{}", rng.gen_range(0..100));

    //  String or hashable data as seed
    // In one line:
    let mut rng: Pcg64 = Seeder::from("stripy zebra").make_rng();
    println!("{:?}", rng.gen::<u8>());

    // If we want to be more explicit, first we create a SipRng:
    let hasher = SipHasher::from("a sailboat");
    let mut hasher_rng = hasher.into_rng();
    // (Note: hasher_rng is a full RNG and can be used directly.)

    // Now, we use hasher_rng to create a seed:
    let mut seed: <Pcg64 as SeedableRng>::Seed = Default::default();
    println!("seed:{:?}", seed);
    hasher_rng.fill(&mut seed);

    // And create our RNG from that seed:
    let mut rng = Pcg64::from_seed(seed);
    println!("{:?}", rng.gen::<u8>());

    let mut data1 = [0u8; 64];
    println!("{:?}", rng.fill_bytes(&mut data1));

    // 1) Use some cryptographically secure entropy generator to generate 128 bits of entropy.
    // Create array of length 32 and fill with a random u8;
    let mut data = [0u8; 32];
    let byte_array = rand::thread_rng().fill_bytes(&mut data);
    // Use that array to then create a length 32 array but with hexidecimal values, since we want
    // each item of the array to represent only 4 bits, which is how many bits a hex represents
    let entropy_array_with_base_16_numbers: Vec<u8> = data.iter().map(|num| num % 16).collect();
    // turn hex byte array into hex string

    let hex_string = entropy_array_with_base_16_numbers
        .iter()
        .map(|byte| format!("{:x}", byte))
        .collect::<String>();
    // let hex_string = "a5d4ce235231f3e19613747b760c247bc836001b5574415fe371f2118861a115";
    println!("hex_string {:?}", hex_string);

    let entropy_hex_byte_array = decode_hex(&hex_string).unwrap();
    println!("entropy_hex_byte_array {:?}", entropy_hex_byte_array);

    // 2) Calculate the SHA256 of the entropy.
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(&entropy_hex_byte_array);
    // read hash digest and consume hasher
    let sha256_result = hasher.finalize();
    println!("sha256_result {:?}", sha256_result);
    // 3) Append the first entropy_length/32 bits of the SHA256 of the entropy at the end of the entropy. For example, in our case we will append the first 4 bits of the SHA256(entropy) to the entropy since our entropy is 128 bits.
    let bits_to_append_count = (&entropy_hex_byte_array.len() * 4) / 32;
    println!("bits_to_append_count: {:?}", bits_to_append_count);
    let first_item = sha256_result[0];
    println!("first_item: {:?}", first_item);
    let first_item_as_binary_string = convert_to_binary_string(first_item, true);
    let first_four_bits_binary_string = &first_item_as_binary_string[0..4];
    println!(
        "first_item_as_binary_string: {:?}",
        first_item_as_binary_string
    );
    println!(
        "first_four_bits_binary_string: {:?}",
        first_four_bits_binary_string
    );
    // 4) Each word of the mnemonic represents 11 bits. Hence, if you check the wordlist you will find 2048 unique words. Now, divide the entropy + checksum into parts of 11 bits each.
    fn convert_to_binary_string(num: u8, format_with_8_bits: bool) -> String {
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
        let binary_string_with_prefix = if format_with_8_bits {
            format_binary_with_8_bits(num)
        } else {
            format_binary_with_4_bits(num)
        };
        let binary_string_without_prefix = crop_letters(&binary_string_with_prefix, 2);
        binary_string_without_prefix.to_string()
    }
    let mut entropy_hex_binary_string = String::new();
    for i in entropy_hex_byte_array {
        let binary_str = convert_to_binary_string(i, true);
        println!("{}", binary_str);
        entropy_hex_binary_string.push_str(binary_str.as_str())
    }
    println!("entropy_hex_binary_string: {:?}", entropy_hex_binary_string);
    println!(
        "split: {:?}",
        split_string_with_spaces_for_substrings_with_length(&entropy_hex_binary_string, 11)
    );
    let entropy_plus_checksum_binary = format!(
        "{}{}",
        entropy_hex_binary_string, first_four_bits_binary_string
    );
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
    let entropy_plus_checksum_binary_with_spaces_seperating =
        split_string_with_spaces_for_substrings_with_length(&entropy_plus_checksum_binary, 11);
    let word_binary: Vec<&str> = entropy_plus_checksum_binary_with_spaces_seperating
        .split(" ")
        .collect();
    fn convert_binary_to_int(binary_string: &str) -> isize {
        let bin_idx = binary_string;
        let intval = isize::from_str_radix(bin_idx, 2).unwrap();
        intval
    }
    let words: Vec<String> = word_binary
        .iter()
        .map(|word_binary_string| {
            let word_num = convert_binary_to_int(word_binary_string);
            WORDS.get(word_num as usize).unwrap().to_string()
        })
        .collect();
    println!("{:?}", words)
}

pub mod bip39;
// Resource:
// - https://github.com/AleoHQ/wagyu/tree/master/bitcoin
// - https://bitcoin.stackexchange.com/questions/89814/how-does-bip-39-mnemonic-work
// - https://www.freecodecamp.org/news/how-to-generate-your-very-own-bitcoin-private-key-7ad0f4936e6c
use rand::Rng;

pub fn create_256_bit_private_key_custom() -> String {
    // we create an array that will store the byte representation of each of our numbers. We're
    //   going to have 64 numbers, so the length will be 64, where each item represents a 16 byte
    //   number (0 -15).
    let mut byte_array: Vec<u8> = Vec::new();
    // we create an string that will represent our byte_array but as a hexidecimal number
    // let mut s = String::new();
    // loop through 64 times and create a new hex number each time because
    //    we want a number with 64 digits, and each of them will be 4 bytes,
    //    for a number with 256 bytes total.
    for _x in 0..64 {
        // get number between 0 - 255 billion;
        let mut rng = rand::thread_rng();
        let random_int_1 = rng.gen_range(0..255);
        // get number between 1 - 16;
        let random_int_2 = rng.gen_range(1..=16);

        // we dont want a number any larger than 15 (because we want a 4 byte number)
        //    so we have to modulo our first random number by our second. Notice the second
        //    random number can only go as high as 16 and by moduloing our random number by that
        //    we'll never get a number larger than 16
        let random_num = random_int_1 % random_int_2;
        // push our random number onto the byte array
        byte_array.push(random_num);
        // push our random number onto the string
        // let hex = format!("{:x}", b);
        //s.push_str(&hex);
    }

    // convert byte array into a hex string
    let s = byte_array
        .iter()
        .map(|byte| format!("{:x}", byte))
        .collect::<String>();
    s
}

pub fn create_private_key() -> String {
    create_256_bit_private_key_custom()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}

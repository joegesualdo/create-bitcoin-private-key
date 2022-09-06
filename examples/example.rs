use create_bitcoin_private_key::create_private_key;

fn main() {
    let private_key = create_private_key();
    println!("{}", private_key);
}

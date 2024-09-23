use xoracle::{build_trie, crack, xor, xor_strings};

fn main() {
    let a = std::env::args().nth(1).unwrap_or("yes".to_owned());
    let b = std::env::args().nth(2).unwrap_or("the".to_owned());

    let words = include_str!("./en_50k.txt");
    let trie = build_trie(words.lines().flat_map(|x| x.split_whitespace().next()));

    let cipher = xor_strings(&a, &b);
    println!("cipher: {cipher:02x?}");

    let res = crack(&cipher, &trie, trie.inc_search(), trie.inc_search());

    if let Some((a, b)) = res {
        println!("found valid plain text");
        println!("  {}", std::str::from_utf8(&a).unwrap());
        println!("  {}", std::str::from_utf8(&b).unwrap());

        let cipher = xor(a, b);
        println!("cipher: {cipher:02x?}");
    } else {
        println!("couldn't find valid plain text");
    }
}

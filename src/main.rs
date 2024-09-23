use xoracle::{build_trie, crack, xor, xor_strings, Queries};

fn main() {
    let a = std::env::args().nth(1).unwrap_or("yes".to_owned());
    let b = std::env::args().nth(2).unwrap_or("the".to_owned());

    let words = include_str!("./en_50k.txt");
    let trie = build_trie(
        words
            .lines()
            .flat_map(|x| x.split_whitespace().next())
            .filter(|x| x.is_ascii()),
        [],
    );
    let special_chars = "'\" ,.";
    let more_trie = build_trie(
        words
            .lines()
            .filter_map(|x| x.split_whitespace().next())
            .filter(|x| x.is_ascii())
            .flat_map(|x| special_chars.chars().map(move |ch| format!("{ch}{x}"))), // .chain(
        //     words
        //         .lines()
        //         .filter_map(|x| x.split_whitespace().next())
        //         .filter(|x| x.is_ascii())
        //         .flat_map(|x| special_chars.chars().map(move |ch| format!("{x}{ch}"))),
        // )
        special_chars.bytes(),
    );

    let cipher = xor_strings(&a, &b);
    println!("cipher: {cipher:02x?}");

    let res = crack(
        &cipher,
        &more_trie,
        Queries::new(trie.inc_search()),
        Queries::new(trie.inc_search()),
    );

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

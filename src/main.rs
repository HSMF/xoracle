use xoracle::{
    all::build_trie_importance, build_trie, crack, crack_non_rec, xor, xor_strings, Queries,
};

fn main() {
    let a = std::env::args().nth(1).unwrap_or("yes".to_owned());
    let b = std::env::args().nth(2).unwrap_or("the".to_owned());

    let words = include_str!("./en_50k.txt");

    let wordsi = words
        .lines()
        .filter_map(|x| x.split_whitespace().next())
        .filter(|x| x.is_ascii())
        .filter(|x| x.len() > 1 || *x == "a")
        .filter(|x| *x != "th")
        .filter(|x| *x != "ye");

    let trie = build_trie(wordsi.clone());
    let special_chars = "'\" ,.";
    let more_trie = build_trie(
        wordsi.clone(), // .flat_map(|x| special_chars.chars().map(move |ch| format!("{ch}{x}"))), // .chain(
                        //     words
                        //         .lines()
                        //         .filter_map(|x| x.split_whitespace().next())
                        //         .filter(|x| x.is_ascii())
                        //         .flat_map(|x| special_chars.chars().map(move |ch| format!("{x}{ch}"))),
                        // )
    );

    let cipher = xor_strings(&a, &b);
    println!("cipher: {cipher:02x?}");
    println!("  originating from");
    println!("    {a:?}");
    println!("    {b:?}");

    let res = crack(
        &cipher,
        &more_trie,
        Queries::new(trie.inc_search()),
        Queries::new(trie.inc_search()),
    );

    if let Some((a, b)) = res {
        println!("found valid plain text");
        println!("  {:?}", std::str::from_utf8(&a).unwrap());
        println!("  {:?}", std::str::from_utf8(&b).unwrap());

        let cipher = xor(a, b);
        println!("cipher: {cipher:02x?}");
    } else {
        println!("couldn't find valid plain text");
    }

    let trie = build_trie_importance(
        words
            .lines()
            .filter_map(|x| x.split_once(' '))
            .filter_map(|(word, p)| p.parse().ok().map(|p| (word, p)))
            .filter(|(x, _)| x.is_ascii()),
    );

    let ans = crack_non_rec(&cipher, &trie);

    if ans.is_empty() {
        println!("couldn't find valid plain text");
    } else {
        for (a, b) in ans {
            println!("  {:?}", a);
            println!("  {:?}", b);
            println!();
        }
    }
}

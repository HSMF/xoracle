use trie_rs::{inc_search::IncSearch, Trie, TrieBuilder};

pub const fn charset() -> &'static [u8] {
    b"abcdefghijklmnopqrstuvwxyz'\" ,."
}

// struct NextCharSetIter<'a> {
//     charset_idx: usize,
//     inc_search: IncSearch<'a, u8, ()>,
// }
//
// impl<'a> NextCharSetIter<'a> {
//     fn new(inc_search: IncSearch<'a, u8, ()>) -> Self {
//         Self {
//             charset_idx: 0,
//             inc_search,
//         }
//     }
// }

// impl Iterator for NextCharSetIter<'_> {
//     type Item = u8;
//     fn next(&mut self) -> Option<Self::Item> {
//         while self.charset_idx < charset().len() {
//             let key = charset()[self.charset_idx];
//             let item = self.inc_search.peek(&key);
//             self.charset_idx += 1;
//
//             if item.is_some() {
//                 return Some(key);
//             }
//         }
//         None
//     }
// }

pub fn build_trie(words: impl Iterator<Item = impl AsRef<str>>) -> Trie<u8> {
    let mut builder = TrieBuilder::new();
    for word in words {
        builder.push(word.as_ref());
    }

    let special_chars = "'\" ,.";
    for ch in special_chars.bytes() {
        builder.push([ch]);
    }

    builder.build()
}

pub fn xor(a: impl IntoIterator<Item = u8>, b: impl IntoIterator<Item = u8>) -> Vec<u8> {
    // assert_eq!(a.len(), b.len(), "lengths must equal (for now)");
    a.into_iter().zip(b).map(|(a, b)| a ^ b).collect()
}

pub fn xor_strings(a: &str, b: &str) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "lengths must equal (for now)");
    a.bytes().zip(b.bytes()).map(|(a, b)| a ^ b).collect()
}

pub fn crack(
    cipher: &[u8],
    root: &Trie<u8>,
    t1: IncSearch<'_, u8, ()>,
    t2: IncSearch<'_, u8, ()>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut res = crack_inner(cipher, root, t1, t2)?;

    res.0.reverse();
    res.1.reverse();

    Some(res)
}

#[derive(Clone)]
pub struct Queries<'a> {
    inner: Vec<IncSearch<'a, u8, ()>>,
}

impl<'a> Queries<'a> {
    pub fn new(inner: Vec<IncSearch<'a, u8, ()>>) -> Self {
        Self { inner }
    }

    pub fn advance_all(&mut self, q: u8) {
        let inner = std::mem::take(&mut self.inner);
        self.inner = inner
            .into_iter()
            .filter_map(|mut x| if x.query(&q).is_some() { Some(x) } else { None })
            .collect()
    }
}

fn crack_inner(
    cipher: &[u8],
    _root: &Trie<u8>,
    t1: IncSearch<u8, ()>,
    t2: IncSearch<u8, ()>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if cipher.is_empty() {
        return Some(Default::default());
    }

    // let mut choice_set = NextCharSetIter::new(t1.clone());

    charset().iter().find_map(|t1_ch| {
        let mut t1 = t1.clone();
        let t1_ans = t1.query(t1_ch)?;

        // eprintln!("{} {cipher:02x?}", *t1_ch as char);
        if cipher.len() == 1 && !t1_ans.is_match() {
            return None;
        }

        let expected = cipher[0] ^ t1_ch;
        let mut t2 = t2.clone();
        let t2_ans = t2.query(&expected)?;

        if cipher.len() == 1 && !t2_ans.is_match() {
            return None;
        }

        let (mut a, mut b) = crack_inner(&cipher[1..], _root, t1, t2)?;

        a.push(*t1_ch);
        b.push(expected);
        Some((a, b))
    })
}

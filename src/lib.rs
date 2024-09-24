#![allow(clippy::too_many_arguments)]
use std::fs::File;

use itertools::Itertools;
use trie_rs::{
    inc_search::{Answer, IncSearch},
    Trie, TrieBuilder,
};

pub const fn special() -> &'static [u8] {
    b"'\" ,."
}
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

pub fn build_trie(
    words: impl Iterator<Item = impl AsRef<str>>,
    special_chars: impl IntoIterator<Item = u8>,
) -> Trie<u8> {
    let mut builder = TrieBuilder::new();
    for word in words {
        builder.push(word.as_ref());
    }

    for ch in special_chars {
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
    t1: Queries,
    t2: Queries,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut res = crack_inner(
        cipher,
        root,
        t1,
        t2,
        ExpectedNext::Word,
        ExpectedNext::Word,
        Default::default(),
    )?;

    res.0.reverse();
    res.1.reverse();

    Some(res)
}

#[derive(Clone, Debug)]
pub struct Queries<'a> {
    inner: Vec<IncSearch<'a, u8, ()>>,
}

impl<'a> Queries<'a> {
    pub fn new(inner: IncSearch<'a, u8, ()>) -> Self {
        Self { inner: vec![inner] }
    }

    pub fn advance_all(&mut self, q: u8) {
        let inner = std::mem::take(&mut self.inner);
        self.inner = inner
            .into_iter()
            .filter_map(|mut x| if x.query(&q).is_some() { Some(x) } else { None })
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ExpectedNext {
    Word,
    Special,
}

#[derive(Debug, Clone)]
struct NextState<'a> {
    charset_idx: usize,
    q_idx: usize,
    did_produce: [bool; 256],
    q: Queries<'a>,
}

impl<'a> NextState<'a> {
    fn new(q: Queries<'a>) -> Self {
        Self {
            charset_idx: 0,
            q_idx: 0,
            did_produce: [false; 256],
            q,
        }
    }
}

impl<'a> Iterator for NextState<'a> {
    type Item = (u8, Answer, Queries<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.charset_idx < charset().len() {
            let chr = charset()[self.charset_idx];
            while self.q_idx < self.q.inner.len() && !self.did_produce[chr as usize] {
                let Some(ans) = self.q.inner[self.q_idx].peek(&chr) else {
                    self.q_idx += 1;
                    continue;
                };
                let mut q = self.q.clone();

                q.advance_all(chr);

                self.did_produce[chr as usize] = true;
                self.q_idx += 1;
                return Some((chr, ans, q));
            }

            self.q_idx = 0;
            self.charset_idx += 1;
        }

        None
    }
}

#[derive(Clone)]
enum NextStateExpected<'a> {
    Word(Box<NextState<'a>>),
    Special { i: usize, root: &'a Trie<u8> },
    // WordOrSpecial {
    //     i: usize,
    //     root: &'b Trie<u8>,
    //     next: NextState<'a>,
    // },
}

impl<'a> Iterator for NextStateExpected<'a> {
    type Item = (u8, Answer, Queries<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            NextStateExpected::Word(i) => i.next(),
            NextStateExpected::Special { i, root } => {
                if *i >= special().len() {
                    return None;
                }
                let chr = special()[*i];
                *i += 1;
                Some((chr, Answer::PrefixAndMatch, Queries::new(root.inc_search())))
            }
        }
    }
}

fn try_1(
    cipher: &[u8],
    root: &Trie<u8>,
    t1: Queries,
    expected_next1: ExpectedNext,
    ch1: u8,
    ch2: u8,
    it2: NextStateExpected,
    (h1, h2): (String, String),
) -> Option<(Vec<u8>, Vec<u8>)> {
    for (_, ans, t2) in it2.clone().filter(|(ch, _, _)| (*ch == ch2)) {
        if ans.is_prefix() {
            // t2.inner.push(root.inc_search());
            // eprintln!("{h2:?} t2 is prefix");
            if let Some(x) = try_2(
                cipher,
                root,
                t1.clone(),
                t2.clone(),
                expected_next1,
                ExpectedNext::Word,
                ch1,
                ch2,
                (h1.clone(), h2.clone()),
            ) {
                return Some(x);
            }
        };

        if ans.is_match() {
            // t2.inner.push(root.inc_search());
            // eprintln!("{h2:?} t2 is match");
            if let Some(x) = try_2(
                cipher,
                root,
                t1.clone(),
                t2.clone(),
                expected_next1,
                ExpectedNext::Special,
                ch1,
                ch2,
                (h1.clone(), h2.clone()),
            ) {
                return Some(x);
            }
        };

        assert!(ans.is_match() || ans.is_prefix());
    }

    None
}

fn try_2(
    cipher: &[u8],
    root: &Trie<u8>,
    t1: Queries,
    t2: Queries,
    expected_next1: ExpectedNext,
    expected_next2: ExpectedNext,
    ch1: u8,
    ch2: u8,
    (h1, h2): (String, String),
) -> Option<(Vec<u8>, Vec<u8>)> {
    let (mut a, mut b) = crack_inner(
        cipher,
        root,
        t1.clone(),
        t2,
        expected_next1,
        expected_next2,
        (
            format!("{h1}{}", ch1 as char),
            format!("{h2}{}", ch2 as char),
        ),
    )?;

    // eprintln!(
    //     "{:?} {:?}",
    //     std::str::from_utf8(&a.iter().rev().copied().collect::<Vec<_>>()).unwrap(),
    //     std::str::from_utf8(&b.iter().rev().copied().collect::<Vec<_>>()).unwrap()
    // );

    a.push(ch1);
    b.push(ch2);
    Some((a, b))
}

fn crack_inner(
    cipher: &[u8],
    root: &Trie<u8>,
    t1: Queries,
    t2: Queries,
    expected_next1: ExpectedNext,
    expected_next2: ExpectedNext,
    (h1, h2): (String, String),
) -> Option<(Vec<u8>, Vec<u8>)> {
    if cipher.is_empty() {
        return Some(Default::default());
    }

    // let mut choice_set = NextCharSetIter::new(t1.clone());

    let it1 = match expected_next1 {
        ExpectedNext::Word => NextStateExpected::Word(Box::new(NextState::new(t1))),
        ExpectedNext::Special => NextStateExpected::Special { i: 0, root },
    };

    let it2 = match expected_next2 {
        ExpectedNext::Word => NextStateExpected::Word(Box::new(NextState::new(t2))),
        ExpectedNext::Special => NextStateExpected::Special { i: 0, root },
    };

    // let it1 = Box::new(NextState::new(t1.clone()));
    // let it2: Box<dyn Iterator<Item = _>> = Box::new(NextState::new(t2.clone()));

    for (ch1, ans, t1) in it1 {
        let ch2 = cipher[0] ^ ch1;
        // eprintln!(
        //     "'{h1}{}' '{h2}{}' \t\t{} {ch1} {ch2}",
        //     ch1 as char, ch2 as char, cipher[0],
        // );

        if ans.is_prefix() {
            if let Some(x) = try_1(
                &cipher[1..],
                root,
                t1.clone(),
                ExpectedNext::Word,
                ch1,
                ch2,
                it2.clone(),
                (h1.clone(), h2.clone()),
            ) {
                return Some(x);
            }
        }
        if ans.is_match() {
            if let Some(x) = try_1(
                &cipher[1..],
                root,
                t1.clone(),
                ExpectedNext::Special,
                ch1,
                ch2,
                it2.clone(),
                (h1.clone(), h2.clone()),
            ) {
                return Some(x);
            }
        }
        assert!(ans.is_match() || ans.is_prefix());

        // if h1 == "ye" && ch1 == b's' {
        //     for i in it2.clone() {
        //         eprint!("({} {}) \t", i.0 as char, i.1)
        //     }
        //     eprintln!()
        // }

        // for (_, ans, mut t2) in it2.clone().filter(|(ch, _, _)| (*ch == ch2)) {
        //     if ans.is_match() {
        //         t2.inner.push(root.inc_search());
        //         // eprintln!("t2 is match");
        //         if let Some(x) = try_2(
        //             &cipher[1..],
        //             root,
        //             t1.clone(),
        //             t2.clone(),
        //             expected_next1,
        //             ExpectedNext::Special,
        //             ch1,
        //             ch2,
        //             (h1.clone(), h2.clone()),
        //         ) {
        //             return Some(x);
        //         }
        //     };
        //
        //     if ans.is_prefix() {
        //         t2.inner.push(root.inc_search());
        //         // eprintln!("t2 is match");
        //         if let Some(x) = try_2(
        //             &cipher[1..],
        //             root,
        //             t1.clone(),
        //             t2,
        //             expected_next1,
        //             ExpectedNext::Word,
        //             ch1,
        //             ch2,
        //             (h1.clone(), h2.clone()),
        //         ) {
        //             return Some(x);
        //         }
        //     };
        //
        //     assert!(ans.is_match() || ans.is_prefix());
        // }
    }
    // return None;

    // for (a, b) in t1.inner.iter().zip(t2.inner.iter()) {
    //     if let Some(x) = charset().iter().find_map(|t1_ch| {
    //         let mut a = a.clone();
    //         let t1_ans = a.query(t1_ch)?;
    //
    //         let mut t1 = t1.clone();
    //         t1.advance_all(*t1_ch);
    //
    //         // eprintln!("{} {cipher:02x?}", *t1_ch as char);
    //         if cipher.len() == 1 && !t1_ans.is_match() {
    //             return None;
    //         }
    //
    //         let expected_next1 = if t1_ans.is_match() {
    //             t1.inner.push(root.inc_search());
    //             ExpectedNext::SpecialOrWord
    //         } else {
    //             ExpectedNext::Word
    //         };
    //
    //         let expected = cipher[0] ^ t1_ch;
    //
    //         let mut b = b.clone();
    //         let t2_ans = b.query(&expected)?;
    //
    //         let mut t2 = t2.clone();
    //         t2.advance_all(expected);
    //
    //         if cipher.len() == 1 && !t2_ans.is_match() {
    //             return None;
    //         }
    //
    //         let expected_next2 = if t2_ans.is_match() {
    //             t2.inner.push(root.inc_search());
    //             ExpectedNext::SpecialOrWord
    //         } else {
    //             ExpectedNext::Word
    //         };
    //
    //         let (mut a, mut b) =
    //             crack_inner(&cipher[1..], root, t1, t2, expected_next1, expected_next2)?;
    //
    //         a.push(*t1_ch);
    //         b.push(expected);
    //         Some((a, b))
    //     }) {
    //         return Some(x);
    //     }
    // }

    None

    // charset().iter().find_map(|t1_ch| {
    //     let mut t1 = t1.clone();
    //     let t1_ans = t1.query(t1_ch)?;
    //
    //     // eprintln!("{} {cipher:02x?}", *t1_ch as char);
    //     if cipher.len() == 1 && !t1_ans.is_match() {
    //         return None;
    //     }
    //
    //     let expected = cipher[0] ^ t1_ch;
    //     let mut t2 = t2.clone();
    //     let t2_ans = t2.query(&expected)?;
    //
    //     if cipher.len() == 1 && !t2_ans.is_match() {
    //         return None;
    //     }
    //
    //     let (mut a, mut b) = crack_inner(&cipher[1..], _root, t1, t2)?;
    //
    //     a.push(*t1_ch);
    //     b.push(expected);
    //     Some((a, b))
    // })
}

#[derive(Clone)]
struct State<'a, 'b> {
    queries_left: Queries<'a>,
    queries_right: Queries<'a>,
    cipher: &'b [u8],
    left: String,
    right: String,
    expected_next1: ExpectedNext,
    expected_next2: ExpectedNext,
}

impl<'a, 'b> PartialEq for State<'a, 'b> {
    fn eq(&self, other: &Self) -> bool {
        self.left == other.left
            && self.right == other.right
            && self.cipher == other.cipher
            && self.expected_next1 == other.expected_next1
            && self.expected_next2 == other.expected_next2
    }
}

impl PartialOrd for State<'_, '_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for State<'_, '_> {}

impl Ord for State<'_, '_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cipher.len().cmp(&other.cipher.len())
    }
}

fn tasks_of_answer(ans: Answer) -> impl Iterator<Item = ExpectedNext> + Clone {
    ans.is_match()
        .then_some(ExpectedNext::Special)
        .into_iter()
        .chain(ans.is_prefix().then_some(ExpectedNext::Word))
}

pub fn crack_non_rec(cipher: &[u8], root: &Trie<u8>) -> Vec<(String, String)> {
    // make this a binary heap?
    let mut stack = vec![State {
        queries_left: Queries::new(root.inc_search()),
        queries_right: Queries::new(root.inc_search()),
        left: String::with_capacity(cipher.len()),
        right: String::with_capacity(cipher.len()),
        cipher,
        expected_next1: ExpectedNext::Word,
        expected_next2: ExpectedNext::Word,
    }];

    let mut res = vec![];
    let mut seen = 0usize;

    use std::io::Write;
    let mut f = File::create("res").unwrap();

    while let Some(State {
        queries_left,
        queries_right,
        cipher,
        left,
        right,
        expected_next1,
        expected_next2,
    }) = stack.pop()
    {
        seen += 1;

        if seen % 10_000 == 0 {
            eprintln!("seen {seen} states, have {} 'valid' solutions", res.len());
            f.flush().expect("failed to flush (ew)");
        }
        if cipher.is_empty() {
            writeln!(&mut f, "{left} {right}").expect("failed to write");
            res.push((left, right));
            continue;
        }
        let it1 = match expected_next1 {
            ExpectedNext::Word => NextStateExpected::Word(Box::new(NextState::new(queries_left))),
            ExpectedNext::Special => NextStateExpected::Special { i: 0, root },
        };
        let it2 = match expected_next2 {
            ExpectedNext::Word => NextStateExpected::Word(Box::new(NextState::new(queries_right))),
            ExpectedNext::Special => NextStateExpected::Special { i: 0, root },
        };

        for ((ch1, ans1, queries_left), (ch2, ans2, queries_right)) in it1
            .cartesian_product(it2)
            .filter(|&((left, _, _), (right, _, _))| left ^ cipher[0] == right)
        {
            let mut left = left.clone();
            left.push(ch1 as char);
            let mut right = right.clone();
            right.push(ch2 as char);

            let tasks = tasks_of_answer(ans1).cartesian_product(tasks_of_answer(ans2));

            for (expected_next1, expected_next2) in tasks {
                stack.push(State {
                    // yes, this clones one time too much, but do I care?
                    queries_left: queries_left.clone(),
                    queries_right: queries_right.clone(),
                    cipher: &cipher[1..],
                    left: left.clone(),
                    right: right.clone(),
                    expected_next1,
                    expected_next2,
                });
            }
        }
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn next_state_iterator() {
        let trie = build_trie(["yes", "year", "you", "cyan"].iter(), []);

        let mut cy = trie.inc_search();
        cy.query(&b'c');

        let q = Queries {
            inner: vec![trie.inc_search(), cy],
        };

        let mut states = NextState::new(q).map(|x| x.0).collect::<Vec<_>>();
        states.sort();

        assert_eq!(states, [b'c', b'y']);
    }

    #[test]
    fn next_state_iterator_advances_correctly() {
        let trie = build_trie(["yes", "year", "you", "cyan"].iter(), []);

        let mut cy = trie.inc_search();
        cy.query(&b'c');

        let q = Queries {
            inner: vec![trie.inc_search(), cy],
        };

        let (_, ans, new_q) = NextState::new(q)
            .find(|x| x.0 == b'y')
            .expect("y is a valid next char");

        assert!(!ans.is_match());

        let mut states = NextState::new(new_q).map(|x| x.0).collect::<Vec<_>>();
        states.sort();

        assert_eq!(states, [b'a', b'e', b'o']);
    }
}

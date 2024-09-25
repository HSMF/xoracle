use std::{collections::BinaryHeap, fs::File};

use itertools::Itertools;
use trie_rs::{inc_search::Answer, map::Trie};

use crate::{ExpectedNext, NextState, NextStateExpected, Queries};

fn log2(x: u64) -> u64 {
    // u64::BITS as u64 - x.leading_zeros() as u64
    (x as f64).log2() as u64
}

fn sqrt(x: u64) -> u64 {
    // u64::BITS as u64 - x.leading_zeros() as u64
    (x as f64).sqrt() as u64
}

pub fn build_trie_importance<'a>(words: impl Iterator<Item = (&'a str, u64)>) -> Trie<u8, u64> {
    words
        .map(|(word, x)| (word, log2(x) + 2 * (word.len() as u64)))
        .collect()
}

#[derive(Clone)]
struct State<'a, 'b> {
    queries_left: Queries<'a, u64>,
    queries_right: Queries<'a, u64>,
    importance: u64,
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
        self.importance
            .cmp(&other.importance)
            .then(self.cipher.len().cmp(&other.cipher.len()))
    }
}

fn tasks_of_answer(ans: Answer) -> impl Iterator<Item = ExpectedNext> + Clone {
    ans.is_match()
        .then_some(ExpectedNext::Special)
        .into_iter()
        .chain(ans.is_prefix().then_some(ExpectedNext::Word))
}

pub fn crack_non_rec(cipher: &[u8], root: &Trie<u8, u64>) -> Vec<(String, String)> {
    // make this a binary heap?
    let mut heap = BinaryHeap::new();
    heap.push(State {
        importance: 0,
        queries_left: Queries::new(root.inc_search()),
        queries_right: Queries::new(root.inc_search()),
        left: String::with_capacity(cipher.len()),
        right: String::with_capacity(cipher.len()),
        cipher,
        expected_next1: ExpectedNext::Word,
        expected_next2: ExpectedNext::Word,
    });

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
        importance,
    }) = heap.pop()
    {
        seen += 1;

        if seen % 10_000 == 0 {
            eprintln!("seen {seen} states, have {} 'valid' solutions", res.len());
            f.flush().expect("failed to flush (ew)");
        }
        if cipher.is_empty()
            && (expected_next1 == ExpectedNext::Word || expected_next2 == ExpectedNext::Word)
        {
            continue;
        }
        if cipher.is_empty() {
            writeln!(&mut f, "{importance}\t{left}\t{right}").expect("failed to write");
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

        for ((ch1, ans1, val1, queries_left), (ch2, ans2, val2, queries_right)) in it1
            .cartesian_product(it2)
            .filter(|&((left, _, _, _), (right, _, _, _))| left ^ cipher[0] == right)
        {
            let mut left = left.clone();
            left.push(ch1 as char);
            let mut right = right.clone();
            right.push(ch2 as char);

            let importance = importance + val1.unwrap_or(&0) + val2.unwrap_or(&0);

            let tasks = tasks_of_answer(ans1).cartesian_product(tasks_of_answer(ans2));

            for (expected_next1, expected_next2) in tasks {
                heap.push(State {
                    // yes, this clones one time too much, but do I care?
                    queries_left: queries_left.clone(),
                    queries_right: queries_right.clone(),
                    cipher: &cipher[1..],
                    left: left.clone(),
                    right: right.clone(),
                    expected_next1,
                    expected_next2,
                    importance,
                });
            }
        }
    }

    res
}

//! Pronounceable proquint fingerprints for out-of-band key comparison.
//!
//! A proquint encodes 16 bits as one five-letter consonant-vowel word, so a
//! 32-byte fingerprint becomes 16 short pronounceable words. Reading the words
//! aloud over a phone call or in person is far less error-prone than comparing
//! Base64. The encoding is algorithmic and has no word list to mistype.

#![allow(clippy::redundant_pub_crate)]

const CONSONANTS: [char; 16] = [
    'b', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z',
];
const VOWELS: [char; 4] = ['a', 'i', 'o', 'u'];

/// Encodes a 32-byte fingerprint as sixteen dash-separated proquints.
pub(super) fn proquints(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(16 * 6);
    for pair in bytes.chunks_exact(2) {
        if !output.is_empty() {
            output.push('-');
        }
        let value = u16::from_be_bytes([pair[0], pair[1]]);
        push_proquint(&mut output, value);
    }
    output
}

/// Formats the proquint fingerprint as four indented display lines.
pub(super) fn display_lines(fingerprint: &str, indent: &str) -> String {
    let words: Vec<&str> = fingerprint.split('-').collect();
    words
        .chunks(4)
        .map(|line| format!("{indent}{}", line.join("-")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn push_proquint(output: &mut String, value: u16) {
    let first = usize::from((value >> 12) & 0xF);
    let second = usize::from((value >> 10) & 0x3);
    let third = usize::from((value >> 6) & 0xF);
    let fourth = usize::from((value >> 4) & 0x3);
    let fifth = usize::from(value & 0xF);
    output.push(CONSONANTS[first]);
    output.push(VOWELS[second]);
    output.push(CONSONANTS[third]);
    output.push(VOWELS[fourth]);
    output.push(CONSONANTS[fifth]);
}

#[cfg(test)]
mod tests {
    use super::{display_lines, proquints};

    #[test]
    fn reference_vector_matches_the_proquint_specification() {
        // 0x7F00 0x0001 are the specification's 127.0.0.1 example words.
        let mut bytes = [0_u8; 32];
        for pair in bytes.chunks_exact_mut(4) {
            pair.copy_from_slice(&[0x7F, 0x00, 0x00, 0x01]);
        }
        let expected = "lusab-babad-lusab-babad-lusab-babad-lusab-babad-\
                        lusab-babad-lusab-babad-lusab-babad-lusab-babad";
        assert_eq!(proquints(&bytes), expected);
    }

    #[test]
    fn distinct_fingerprints_produce_distinct_words() {
        assert_ne!(proquints(&[0x11; 32]), proquints(&[0x12; 32]));
        assert_eq!(proquints(&[0x11; 32]), proquints(&[0x11; 32]));
    }

    #[test]
    fn display_lines_group_four_words_per_line() {
        let rendered = display_lines(&proquints(&[0; 32]), "  ");
        assert_eq!(rendered.lines().count(), 4);
        assert!(rendered.lines().all(|line| line.starts_with("  ")));
        assert!(
            rendered
                .lines()
                .all(|line| line.trim().split('-').count() == 4)
        );
    }
}

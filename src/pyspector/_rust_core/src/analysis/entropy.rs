use std::collections::HashMap;

/// Computes the Shannon entropy (in bits per character) of a string.
///
/// High-entropy strings (random-looking base64/hex blobs) are a common
/// signature of secret material that isn't covered by an explicit pattern
/// (e.g. a bespoke API key format). Typical English text sits well under 4.0
/// bits/char; base64-encoded random bytes sit close to 6.0.
pub fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count();
    if len == 0 {
        return 0.0;
    }

    let mut counts: HashMap<char, u32> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }

    let len_f = len as f64;
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len_f;
        acc - p * p.log2()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_has_zero_entropy() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_repeated_char_has_zero_entropy() {
        assert_eq!(shannon_entropy("aaaaaaaaaa"), 0.0);
    }

    #[test]
    fn low_entropy_english_word() {
        // Highly repetitive/structured text should be well under 3 bits/char.
        assert!(shannon_entropy("aaaabbbbcccc") < 2.5);
    }

    #[test]
    fn high_entropy_random_base64_like_token() {
        // Random-looking base64 token should be high entropy (~5.5-6 bits/char).
        let token = "8f3kD9pQmZ2xN7vR1tYcL0aWs6HbUeJg"; // pragma: allowlist secret
        assert!(shannon_entropy(token) > 4.0);
    }

    #[test]
    fn four_char_alphabet_uniform_is_two_bits() {
        // Perfectly uniform 4-symbol alphabet -> exactly 2 bits/char.
        let s = "abcdabcdabcd";
        let e = shannon_entropy(s);
        assert!((e - 2.0).abs() < 1e-9);
    }
}

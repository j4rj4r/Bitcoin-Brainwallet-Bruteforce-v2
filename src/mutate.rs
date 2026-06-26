use std::collections::HashSet;

/// Measured for a representative word ("password" -> 456); the exact count varies
/// per word because case/leetspeak variants can collide, but this is close enough
/// for a rough runtime estimate.
pub const APPROX_VARIANTS_PER_WORD: usize = 450;

fn common_suffixes() -> Vec<String> {
    ["", "1", "12", "123", "1234", "01", "007", "69", "420", "!"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn year_suffixes() -> Vec<String> {
    (1960..=2025).map(|year| year.to_string()).collect()
}

fn all_suffixes() -> Vec<String> {
    let mut suffixes = common_suffixes();
    suffixes.extend(year_suffixes());
    suffixes
}

fn leetspeak(word: &str) -> String {
    word.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '4',
            'e' => '3',
            'i' => '1',
            'o' => '0',
            's' => '5',
            _ => c,
        })
        .collect()
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
    }
}

fn dedup_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

/// Yields password-mutation variants of a word: case changes, leetspeak,
/// and common digit/year suffixes.
///
/// Variants are built from `Vec`s only (a `HashSet` is used solely for membership
/// checks, never iterated for output order), so the order is fully deterministic -
/// required for the resume feature to skip the right candidates.
pub fn mutate_word(word: &str) -> Vec<String> {
    let case_variants = dedup_preserve_order(vec![
        word.to_string(),
        word.to_lowercase(),
        word.to_uppercase(),
        capitalize(word),
    ]);

    let mut bases = case_variants.clone();
    bases.extend(case_variants.iter().map(|variant| leetspeak(variant)));
    let bases = dedup_preserve_order(bases);

    let suffixes = all_suffixes();
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(bases.len() * suffixes.len());
    for base in &bases {
        for suffix in &suffixes {
            let variant = format!("{base}{suffix}");
            if seen.insert(variant.clone()) {
                out.push(variant);
            }
        }
    }
    out
}

/// Expands a stream of dictionary words into their mutation variants.
pub fn mutate_wordlist(words: impl Iterator<Item = String>) -> impl Iterator<Item = String> {
    words.flat_map(|word| mutate_word(&word).into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_case_and_leetspeak_and_suffix_variants() {
        let variants = mutate_word("Pass");
        assert!(variants.contains(&"Pass".to_string()));
        assert!(variants.contains(&"pass".to_string()));
        assert!(variants.contains(&"PASS".to_string()));
        assert!(variants.contains(&"p455".to_string()));
        assert!(variants.contains(&"pass123".to_string()));
        assert!(variants.contains(&"pass2024".to_string()));
    }

    #[test]
    fn never_yields_duplicates() {
        let variants = mutate_word("aaa");
        let unique: HashSet<&String> = variants.iter().collect();
        assert_eq!(variants.len(), unique.len());
    }

    #[test]
    fn deterministic_across_calls() {
        assert_eq!(mutate_word("password"), mutate_word("password"));
    }

    #[test]
    fn wordlist_flattens_each_word() {
        let words = vec!["a".to_string(), "b".to_string()];
        let expanded: Vec<String> = mutate_wordlist(words.into_iter()).collect();
        assert_eq!(
            expanded.len(),
            mutate_word("a").len() + mutate_word("b").len()
        );
    }
}

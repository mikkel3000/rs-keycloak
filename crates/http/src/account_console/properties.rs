//! Java `.properties` files, read as UTF-8 the way Keycloak reads theme
//! messages and theme settings.

/// Parses a properties file into key and value pairs, in file order. A later
/// duplicate key appears after the earlier one, so collecting into a map
/// keeps the last value, as `java.util.Properties` does.
pub(crate) fn parse(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut logical = String::new();
    let mut continuing = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let line = line.trim_start_matches([' ', '\t', '\u{c}']);
        if !continuing && (line.is_empty() || line.starts_with(['#', '!'])) {
            continue;
        }
        let trailing = line.len() - line.trim_end_matches('\\').len();
        if trailing % 2 == 1 {
            logical.push_str(&line[..line.len() - 1]);
            continuing = true;
            continue;
        }
        logical.push_str(line);
        continuing = false;
        pairs.push(pair(&logical));
        logical.clear();
    }
    if continuing {
        pairs.push(pair(&logical));
    }
    pairs
}

/// Splits one logical line at the first unescaped `=`, `:` or whitespace.
fn pair(line: &str) -> (String, String) {
    let mut end = line.len();
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '=' | ':' | ' ' | '\t' | '\u{c}') {
            end = index;
            break;
        }
    }
    let rest = line[end..].trim_start_matches([' ', '\t', '\u{c}']);
    let rest = rest
        .strip_prefix(['=', ':'])
        .map_or(rest, |value| value.trim_start_matches([' ', '\t', '\u{c}']));
    (unescape(&line[..end]), unescape(rest))
}

/// Resolves `\t`, `\n`, `\r`, `\f` and `\uXXXX`; any other escaped character
/// stands for itself.
fn unescape(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            result.push(character);
            continue;
        }
        match characters.next() {
            Some('t') => result.push('\t'),
            Some('n') => result.push('\n'),
            Some('r') => result.push('\r'),
            Some('f') => result.push('\u{c}'),
            Some('u') => {
                let digits: String = characters.by_ref().take(4).collect();
                if let Some(decoded) = u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    result.push(decoded);
                }
            }
            Some(other) => result.push(other),
            None => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::parse;

    fn pairs(text: &str) -> Vec<(String, String)> {
        parse(text)
    }

    #[test]
    fn separators_comments_and_whitespace() {
        assert_eq!(
            pairs("# comment\n! other\n  a = one\nb:two\nc three\n\nd\n"),
            [("a", "one"), ("b", "two"), ("c", "three"), ("d", "")]
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
        );
    }

    #[test]
    fn escapes_and_continuations() {
        assert_eq!(
            pairs("key\\ with\\:colon=a\\tb\\u00e9\\\\\nlong=first \\\n    second\r\n"),
            [("key with:colon", "a\tbé\\"), ("long", "first second")]
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
        );
    }

    #[test]
    fn utf8_values_stay_as_written() {
        assert_eq!(
            pairs("greeting=Grüße {{0}}\n"),
            [("greeting".to_owned(), "Grüße {{0}}".to_owned())]
        );
    }
}

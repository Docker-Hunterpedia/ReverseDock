//! Property tests of the NGINX parser: arbitrary text never panics, and a parsed tree printed
//! back and parsed again is the same tree.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use rdock_migrate::nginx::parser::{Directive, parse};

fn word() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "listen", "80", "server", "a b", "$host", "${x}y", "\"q\"", "'s'", "x;y", "#c", "{", "}",
        "\\", "location", "~*", "",
    ])
    .prop_map(str::to_owned)
}

/// Prints a tree back as NGINX syntax, every argument quoted.
fn print(tree: &[Directive], out: &mut String) {
    for d in tree {
        out.push_str(&quote(&d.name));
        for a in &d.args {
            out.push(' ');
            out.push_str(&quote(&a.text));
        }
        match (&d.block, &d.raw) {
            (Some(block), _) => {
                out.push_str(" {\n");
                print(block, out);
                out.push_str("}\n");
            }
            (None, Some(raw)) => {
                out.push_str(" {");
                out.push_str(raw);
                out.push_str("}\n");
            }
            (None, None) => out.push_str(";\n"),
        }
    }
}

fn quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// A directive's name and arguments, and its block's directives one level down.
type Shape = (String, Vec<String>, Option<Vec<(String, Vec<String>)>>);

fn shape(tree: &[Directive]) -> Vec<Shape> {
    tree.iter()
        .map(|d| {
            (
                d.name.clone(),
                d.values().iter().map(|v| (*v).to_owned()).collect(),
                d.block
                    .as_ref()
                    .map(|b| shape(b).into_iter().map(|(n, a, _)| (n, a)).collect()),
            )
        })
        .collect()
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(text in "[ -~\n\t]{0,400}") {
        let _ = parse(&text, 0);
    }

    #[test]
    fn token_soup_never_panics(words in prop::collection::vec(word(), 0..60)) {
        let _ = parse(&words.join(" "), 0);
    }

    #[test]
    fn printing_and_parsing_again_keeps_the_tree(words in prop::collection::vec(word(), 0..40)) {
        if let Ok(tree) = parse(&words.join(" "), 0) {
            if tree.iter().any(|d| d.raw.is_some()) {
                return Ok(());
            }
            let mut text = String::new();
            print(&tree, &mut text);
            let again = parse(&text, 0).unwrap();
            prop_assert_eq!(shape(&again), shape(&tree));
        }
    }
}

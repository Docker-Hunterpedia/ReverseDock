#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]

use serde_json::{Value, json};

use super::*;

fn ops(patch: Value) -> Vec<PatchOp> {
    serde_json::from_value(patch).unwrap()
}

fn patched(doc: Value, patch: Value) -> Result<Value, PatchError> {
    let mut doc = doc;
    apply(&mut doc, &ops(patch)).map(|()| doc)
}

// RFC 6902 Appendix A, in order.

#[test]
fn a01_adding_an_object_member() {
    let out = patched(
        json!({"foo": "bar"}),
        json!([{ "op": "add", "path": "/baz", "value": "qux" }]),
    );
    assert_eq!(out.unwrap(), json!({"baz": "qux", "foo": "bar"}));
}

#[test]
fn a02_adding_an_array_element() {
    let out = patched(
        json!({"foo": ["bar", "baz"]}),
        json!([{ "op": "add", "path": "/foo/1", "value": "qux" }]),
    );
    assert_eq!(out.unwrap(), json!({"foo": ["bar", "qux", "baz"]}));
}

#[test]
fn a03_removing_an_object_member() {
    let out = patched(
        json!({"baz": "qux", "foo": "bar"}),
        json!([{ "op": "remove", "path": "/baz" }]),
    );
    assert_eq!(out.unwrap(), json!({"foo": "bar"}));
}

#[test]
fn a04_removing_an_array_element() {
    let out = patched(
        json!({"foo": ["bar", "qux", "baz"]}),
        json!([{ "op": "remove", "path": "/foo/1" }]),
    );
    assert_eq!(out.unwrap(), json!({"foo": ["bar", "baz"]}));
}

#[test]
fn a05_replacing_a_value() {
    let out = patched(
        json!({"baz": "qux", "foo": "bar"}),
        json!([{ "op": "replace", "path": "/baz", "value": "boo" }]),
    );
    assert_eq!(out.unwrap(), json!({"baz": "boo", "foo": "bar"}));
}

#[test]
fn a06_moving_a_value() {
    let out = patched(
        json!({"foo": {"bar": "baz", "waldo": "fred"}, "qux": {"corge": "grault"}}),
        json!([{ "op": "move", "from": "/foo/waldo", "path": "/qux/thud" }]),
    );
    assert_eq!(
        out.unwrap(),
        json!({"foo": {"bar": "baz"}, "qux": {"corge": "grault", "thud": "fred"}})
    );
}

#[test]
fn a07_moving_an_array_element() {
    let out = patched(
        json!({"foo": ["all", "grass", "cows", "eat"]}),
        json!([{ "op": "move", "from": "/foo/1", "path": "/foo/3" }]),
    );
    assert_eq!(
        out.unwrap(),
        json!({"foo": ["all", "cows", "eat", "grass"]})
    );
}

#[test]
fn a08_testing_a_value_success() {
    let doc = json!({"baz": "qux", "foo": ["a", 2, "c"]});
    let out = patched(
        doc.clone(),
        json!([
            { "op": "test", "path": "/baz", "value": "qux" },
            { "op": "test", "path": "/foo/1", "value": 2 }
        ]),
    );
    assert_eq!(out.unwrap(), doc);
}

#[test]
fn a09_testing_a_value_error() {
    let err = patched(
        json!({"baz": "qux"}),
        json!([{ "op": "test", "path": "/baz", "value": "bar" }]),
    )
    .unwrap_err();
    assert_eq!(err.kind, PatchErrorKind::TestFailed);
    assert_eq!((err.index, err.op), (0, "test"));
}

#[test]
fn a10_adding_a_nested_member_object() {
    let out = patched(
        json!({"foo": "bar"}),
        json!([{ "op": "add", "path": "/child", "value": { "grandchild": {} } }]),
    );
    assert_eq!(
        out.unwrap(),
        json!({"foo": "bar", "child": {"grandchild": {}}})
    );
}

/// RFC 6902 says unrecognised members are ignored. A configuration is stricter: an unknown
/// member is most likely a typo, so it is refused when the configuration is read; the
/// operation without it applies as the RFC's example shows.
#[test]
fn a11_unrecognized_elements_are_refused_in_configuration() {
    let with_extra = json!([{ "op": "add", "path": "/baz", "value": "qux", "xyz": 123 }]);
    assert!(serde_json::from_value::<Vec<PatchOp>>(with_extra).is_err());
    let out = patched(
        json!({"foo": "bar"}),
        json!([{ "op": "add", "path": "/baz", "value": "qux" }]),
    );
    assert_eq!(out.unwrap(), json!({"foo": "bar", "baz": "qux"}));
}

#[test]
fn a12_adding_to_a_nonexistent_target() {
    let err = patched(
        json!({"foo": "bar"}),
        json!([{ "op": "add", "path": "/baz/bat", "value": "qux" }]),
    )
    .unwrap_err();
    assert_eq!(err.kind, PatchErrorKind::NotFound);
}

/// A.13 is a document with two `op` members: refused when it is read.
#[test]
fn a13_invalid_patch_document() {
    let text = r#"[{ "op": "add", "path": "/baz", "value": "qux", "op": "remove" }]"#;
    assert!(serde_json::from_str::<Vec<PatchOp>>(text).is_err());
}

#[test]
fn a14_escape_ordering() {
    let doc = json!({"/": 9, "~1": 10});
    let out = patched(
        doc.clone(),
        json!([{ "op": "test", "path": "/~01", "value": 10 }]),
    );
    assert_eq!(out.unwrap(), doc);
}

#[test]
fn a15_comparing_strings_and_numbers() {
    let err = patched(
        json!({"/": 9, "~1": 10}),
        json!([{ "op": "test", "path": "/~01", "value": "10" }]),
    )
    .unwrap_err();
    assert_eq!(err.kind, PatchErrorKind::TestFailed);
}

#[test]
fn a16_adding_an_array_value() {
    let out = patched(
        json!({"foo": ["bar"]}),
        json!([{ "op": "add", "path": "/foo/-", "value": ["abc", "def"] }]),
    );
    assert_eq!(out.unwrap(), json!({"foo": ["bar", ["abc", "def"]]}));
}

// RFC 6901 §5: the example document and its pointers.

#[test]
fn rfc6901_examples() {
    let doc = json!({
        "foo": ["bar", "baz"], "": 0, "a/b": 1, "c%d": 2, "e^f": 3, "g|h": 4,
        "i\\j": 5, "k\"l": 6, " ": 7, "m~n": 8
    });
    assert_eq!(lookup(&doc, "").unwrap(), &doc);
    assert_eq!(lookup(&doc, "/foo").unwrap(), &json!(["bar", "baz"]));
    assert_eq!(lookup(&doc, "/foo/0").unwrap(), &json!("bar"));
    for (pointer, want) in [
        ("/", 0),
        ("/a~1b", 1),
        ("/c%d", 2),
        ("/e^f", 3),
        ("/g|h", 4),
        ("/i\\j", 5),
        ("/k\"l", 6),
        ("/ ", 7),
        ("/m~0n", 8),
    ] {
        assert_eq!(lookup(&doc, pointer).unwrap(), &json!(want), "{pointer}");
    }
}

#[test]
fn pointers_are_checked() {
    assert_eq!(parse_pointer("foo"), Err(PatchErrorKind::PointerStart));
    assert_eq!(parse_pointer("/a~2"), Err(PatchErrorKind::PointerEscape));
    assert_eq!(parse_pointer("/a~"), Err(PatchErrorKind::PointerEscape));
    assert_eq!(parse_pointer("/~1~0").unwrap(), vec!["/~".to_owned()]);
    assert_eq!(escape_token("a/b~c"), "a~1b~0c");
    let doc = json!({"list": [1, 2]});
    assert_eq!(lookup(&doc, "/list/01"), Err(PatchErrorKind::BadIndex));
    assert_eq!(lookup(&doc, "/list/-"), Err(PatchErrorKind::BadIndex));
    assert_eq!(lookup(&doc, "/list/2"), Err(PatchErrorKind::NotFound));
}

#[test]
fn edge_cases() {
    // The whole document.
    assert_eq!(
        patched(
            json!({"a": 1}),
            json!([{ "op": "replace", "path": "", "value": [1] }])
        )
        .unwrap(),
        json!([1])
    );
    assert_eq!(
        patched(
            json!(1),
            json!([{ "op": "add", "path": "", "value": {"b": 2} }])
        )
        .unwrap(),
        json!({"b": 2})
    );
    assert_eq!(
        patched(json!({}), json!([{ "op": "remove", "path": "" }]))
            .unwrap_err()
            .kind,
        PatchErrorKind::RemoveRoot
    );
    // Past the end, into a scalar, a missing member.
    assert_eq!(
        patched(
            json!([1]),
            json!([{ "op": "add", "path": "/2", "value": 0 }])
        )
        .unwrap_err()
        .kind,
        PatchErrorKind::BadIndex
    );
    assert_eq!(
        patched(
            json!({"a": 1}),
            json!([{ "op": "add", "path": "/a/b", "value": 0 }])
        )
        .unwrap_err()
        .kind,
        PatchErrorKind::NotContainer
    );
    assert_eq!(
        patched(json!({}), json!([{ "op": "remove", "path": "/a" }]))
            .unwrap_err()
            .kind,
        PatchErrorKind::NotFound
    );
    // Move into itself, onto itself; copy.
    let into = ops(json!([{ "op": "move", "from": "/a", "path": "/a/b" }]));
    assert_eq!(into[0].check(), Err(PatchErrorKind::MoveIntoItself));
    assert_eq!(
        patched(
            json!({"a": {}}),
            json!([{ "op": "move", "from": "/a", "path": "/a" }])
        )
        .unwrap(),
        json!({"a": {}})
    );
    assert_eq!(
        patched(
            json!({"a": {"x": 1}}),
            json!([{ "op": "copy", "from": "/a", "path": "/b" }])
        )
        .unwrap(),
        json!({"a": {"x": 1}, "b": {"x": 1}})
    );
    // Numbers compare by value; objects regardless of order.
    assert!(json_equal(&json!(1), &json!(1.0)));
    assert!(!json_equal(&json!(1), &json!("1")));
    assert!(json_equal(
        &json!({"a": 1, "b": [2.0]}),
        &json!({"b": [2], "a": 1})
    ));
    // Errors name the operation, never a value.
    let err = patched(
        json!({"secret": "hunter2"}),
        json!([{ "op": "test", "path": "/secret", "value": "nope" }]),
    )
    .unwrap_err();
    assert!(!err.to_string().contains("hunter2") && !err.to_string().contains("nope"));
}

/// L5 of the v0.8 review: `copy` of the root into itself doubles the document each time; the
/// size cap fails the patch before it allocates past `max`.
#[test]
fn doubling_copies_stop_at_the_size_cap() {
    let ops: Vec<PatchOp> = (0..64)
        .map(|i| PatchOp::Copy {
            from: String::new(),
            path: format!("/k{i}"),
        })
        .collect();
    let mut doc = json!({ "seed": "x".repeat(100) });
    let err = apply_within(&mut doc, &ops, 64 * 1024).unwrap_err();
    assert_eq!(err.kind, PatchErrorKind::TooLarge);
    assert!(err.index < 12, "{err:?}");
    assert!(serde_json::to_vec(&doc).unwrap().len() <= 64 * 1024);

    // Within the cap, removals make room again.
    let mut doc = json!({ "a": "x".repeat(600) });
    let ops = [
        PatchOp::Copy {
            from: "/a".into(),
            path: "/b".into(),
        },
        PatchOp::Remove { path: "/a".into() },
        PatchOp::Copy {
            from: "/b".into(),
            path: "/c".into(),
        },
        PatchOp::Remove { path: "/b".into() },
        PatchOp::Replace {
            path: "/c".into(),
            value: json!("short"),
        },
        PatchOp::Add {
            path: "/d".into(),
            value: json!([1, 2, 3]),
        },
    ];
    apply_within(&mut doc, &ops, 1300).unwrap();
    assert_eq!(doc, json!({ "c": "short", "d": [1, 2, 3] }));
    let mut big = json!({ "a": 1 });
    let err = apply_within(
        &mut big,
        &[PatchOp::Add {
            path: "/b".into(),
            value: json!("y".repeat(100)),
        }],
        50,
    )
    .unwrap_err();
    assert_eq!(err.kind, PatchErrorKind::TooLarge);
}

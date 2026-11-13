//! Disk store tests: restart, crash leftovers, damage, limits, purge races and streaming.

use std::time::{Duration, SystemTime};

use pingora::cache::key::CacheHashKey;
use pingora::cache::trace::Span;
use pingora::http::ResponseHeader;

use super::*;

fn open(dir: &Path, max_size: u64, max_objects: u64) -> &'static Store {
    Box::leak(Box::new(
        Store::disk("disk", dir, max_size, max_objects, None).unwrap(),
    ))
}

fn meta(url: &str, tags: &[&str]) -> CacheMeta {
    let mut header = ResponseHeader::build(200, None).unwrap();
    header.insert_header("cache-control", "max-age=60").unwrap();
    let now = SystemTime::now();
    let mut meta = CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, header);
    let tags: Vec<String> = tags.iter().map(|t| (*t).to_owned()).collect();
    meta.extensions_mut().insert(ObjectInfo::new(url, &tags));
    meta
}

fn key(name: &str) -> CacheKey {
    CacheKey::new(name.as_bytes().to_vec(), "r")
}

async fn fill(
    store: &'static Store,
    key: &CacheKey,
    url: &str,
    body: &[u8],
) -> pingora::Result<MissFinishType> {
    let span = Span::inactive().handle();
    let mut miss = store
        .get_miss_handler(key, &meta(url, &["t"]), &span)
        .await?;
    for chunk in body.chunks(10_000) {
        miss.write_body(Bytes::copy_from_slice(chunk), false)
            .await?;
    }
    miss.finish().await
}

async fn read(store: &'static Store, key: &CacheKey) -> Option<Vec<u8>> {
    let span = Span::inactive().handle();
    let (_, mut hit) = store.lookup(key, &span).await.unwrap()?;
    let mut out = Vec::new();
    while let Some(chunk) = hit.read_body().await.unwrap() {
        assert!(chunk.len() <= READ_CHUNK, "reads are bounded");
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

fn files(dir: &Path, suffix: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for a in std::fs::read_dir(dir).unwrap().flatten() {
        if !a.path().is_dir() {
            continue;
        }
        for b in std::fs::read_dir(a.path()).unwrap().flatten() {
            for f in std::fs::read_dir(b.path()).unwrap().flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                if suffix.is_none_or(|s| name.ends_with(s)) {
                    out.push(f.path());
                }
            }
        }
    }
    out
}

#[tokio::test]
async fn objects_survive_a_restart_and_the_root_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    let store = open(&root, 1 << 20, 100);
    fill(store, &key("a"), "https://a.test/a", b"alpha")
        .await
        .unwrap();
    fill(store, &key("b"), "https://a.test/b", b"")
        .await
        .unwrap();
    let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    // A second store on the same directory is what a restart sees.
    let again = open(&root, 1 << 20, 100);
    assert_eq!(again.stats().objects, 2);
    assert_eq!(
        read(again, &key("a")).await.as_deref(),
        Some(b"alpha".as_slice())
    );
    assert_eq!(
        read(again, &key("b")).await.as_deref(),
        Some(b"".as_slice())
    );
    assert_eq!(again.stats().hits, 2);
    assert_eq!(again.purge(Selector::Tag("t".into())).await.unwrap(), 2);
    assert_eq!(files(&root, None), Vec::<PathBuf>::new());
}

#[tokio::test]
async fn an_interrupted_fill_is_never_visible_and_its_leftovers_go_at_start() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    let store = open(&root, 1 << 20, 100);
    let span = Span::inactive().handle();
    let mut miss = store
        .get_miss_handler(&key("p"), &meta("https://a.test/p", &[]), &span)
        .await
        .unwrap();
    miss.write_body(Bytes::from(vec![b'x'; 300_000]), false)
        .await
        .unwrap();
    // The fill is in progress: nothing to read.
    assert!(read(store, &key("p")).await.is_none());
    assert_eq!(files(&root, Some(".tmp")).len(), 1);
    // A crash leaves the temporary file behind (simulated by leaking the handler).
    std::mem::forget(miss);
    let again = open(&root, 1 << 20, 100);
    assert_eq!(again.stats().dropped, 1);
    assert_eq!(files(&root, Some(".tmp")), Vec::<PathBuf>::new());
    assert!(read(again, &key("p")).await.is_none());
    // A handler dropped without `finish` (the request failed) removes its file.
    let miss = again
        .get_miss_handler(&key("q"), &meta("https://a.test/q", &[]), &span)
        .await
        .unwrap();
    drop(miss);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(files(&root, Some(".tmp")), Vec::<PathBuf>::new());
}

#[tokio::test]
async fn damaged_files_are_dropped_and_counted_at_start() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    let store = open(&root, 1 << 20, 100);
    for name in ["c1", "c2", "c3", "ok"] {
        fill(
            store,
            &key(name),
            &format!("https://a.test/{name}"),
            b"0123456789",
        )
        .await
        .unwrap();
    }
    let path_of = |name: &str| root.join(file_of(&key(name).combined_bin()));
    // Truncated body, flipped header byte, wrong magic.
    let truncated = std::fs::read(path_of("c1")).unwrap();
    std::fs::write(path_of("c1"), &truncated[..truncated.len() - 3]).unwrap();
    let mut flipped = std::fs::read(path_of("c2")).unwrap();
    flipped[PREFIX_LEN + 20] ^= 0xff;
    std::fs::write(path_of("c2"), flipped).unwrap();
    std::fs::write(path_of("c3"), b"not a cache file at all").unwrap();
    let again = open(&root, 1 << 20, 100);
    let stats = again.stats();
    assert_eq!((stats.objects, stats.dropped), (1, 3));
    assert_eq!(
        read(again, &key("ok")).await.as_deref(),
        Some(b"0123456789".as_slice())
    );
    assert!(!path_of("c1").exists() && !path_of("c2").exists() && !path_of("c3").exists());
}

#[tokio::test]
async fn evicts_by_size_and_by_count() {
    let tmp = tempfile::tempdir().unwrap();
    let body = vec![b'z'; 10_000];
    let by_count = open(&tmp.path().join("count"), 1 << 30, 3);
    for i in 0..5 {
        fill(
            by_count,
            &key(&format!("k{i}")),
            &format!("https://a.test/{i}"),
            &body,
        )
        .await
        .unwrap();
    }
    let stats = by_count.stats();
    assert_eq!((stats.objects, stats.evictions), (3, 2));
    assert!(read(by_count, &key("k0")).await.is_none());
    assert!(read(by_count, &key("k4")).await.is_some());
    assert_eq!(files(&tmp.path().join("count"), None).len(), 3);

    let by_size = open(&tmp.path().join("size"), 35_000, 1000);
    for i in 0..5 {
        fill(
            by_size,
            &key(&format!("s{i}")),
            &format!("https://a.test/s{i}"),
            &body,
        )
        .await
        .unwrap();
        // Keep the first one in use: it must survive.
        assert!(read(by_size, &key("s0")).await.is_some());
    }
    let stats = by_size.stats();
    assert!(stats.bytes <= 35_000, "{stats:?}");
    assert_eq!(stats.objects, 3);
    assert!(read(by_size, &key("s1")).await.is_none());
    // Limits also apply at start.
    let smaller = open(&tmp.path().join("size"), 25_000, 1000);
    assert_eq!(smaller.stats().objects, 2);
}

#[tokio::test]
async fn a_purge_racing_a_slow_fill_wins() {
    let tmp = tempfile::tempdir().unwrap();
    let store = open(&tmp.path().join("store"), 1 << 20, 100);
    let span = Span::inactive().handle();
    let k = key("race");
    fill(store, &k, "https://a.test/race", b"v1").await.unwrap();
    let mut miss = store
        .get_miss_handler(&k, &meta("https://a.test/race", &[]), &span)
        .await
        .unwrap();
    miss.write_body(Bytes::from_static(b"v2-late"), false)
        .await
        .unwrap();
    assert_eq!(
        store
            .purge(Selector::Prefix("https://a.test/".into()))
            .await
            .unwrap(),
        1
    );
    assert!(miss.finish().await.is_err(), "the late fill is discarded");
    assert!(read(store, &k).await.is_none());
    assert_eq!(
        files(&tmp.path().join("store"), None),
        Vec::<PathBuf>::new()
    );
}

#[tokio::test]
async fn a_large_object_streams_in_bounded_chunks_both_ways() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    let store = open(&root, 64 << 20, 10);
    let span = Span::inactive().handle();
    let total = 32 << 20;
    let chunk = vec![7u8; 16 * 1024];
    let mut miss = store
        .get_miss_handler(&key("big"), &meta("https://a.test/big", &[]), &span)
        .await
        .unwrap();
    let mut written = 0usize;
    while written < total {
        miss.write_body(Bytes::copy_from_slice(&chunk), false)
            .await
            .unwrap();
        written += chunk.len();
        // At most one write buffer is held in memory: the file keeps up with the body.
        let on_disk = files(&root, Some(".tmp"))
            .iter()
            .map(|p| std::fs::metadata(p).unwrap().len())
            .sum::<u64>();
        assert!(
            on_disk + WRITE_BUFFER as u64 >= written as u64,
            "{on_disk} on disk after {written}"
        );
    }
    miss.finish().await.unwrap();
    let (_, mut hit) = store.lookup(&key("big"), &span).await.unwrap().unwrap();
    let mut read_total = 0usize;
    while let Some(chunk) = hit.read_body().await.unwrap() {
        assert!(chunk.len() <= READ_CHUNK);
        assert!(chunk.iter().all(|b| *b == 7));
        read_total += chunk.len();
    }
    assert_eq!(read_total, total);
    // Ranges seek into the file.
    let (_, mut hit) = store.lookup(&key("big"), &span).await.unwrap().unwrap();
    hit.seek(total - 10, None).unwrap();
    assert_eq!(hit.read_body().await.unwrap().map(|b| b.len()), Some(10));
    assert!(hit.read_body().await.unwrap().is_none());
}

#[tokio::test]
async fn revalidation_rewrites_the_head_and_keeps_the_body() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("store");
    let store = open(&root, 1 << 20, 100);
    let span = Span::inactive().handle();
    let k = key("rv");
    fill(store, &k, "https://a.test/rv", b"payload")
        .await
        .unwrap();
    let mut updated = meta("https://a.test/rv", &["new"]);
    updated
        .response_header_mut()
        .insert_header("x-version", "2")
        .unwrap();
    assert!(store.update_meta(&k, &updated, &span).await.unwrap());
    let again = open(&root, 1 << 20, 100);
    let (found, _) = again.lookup(&k, &span).await.unwrap().unwrap();
    assert_eq!(found.headers().get("x-version").unwrap(), "2");
    assert_eq!(
        read(again, &k).await.as_deref(),
        Some(b"payload".as_slice())
    );
    assert_eq!(again.purge(Selector::Tag("new".into())).await.unwrap(), 1);
    // Nothing to update once purged.
    assert!(!again.update_meta(&k, &updated, &span).await.unwrap());
}

#[test]
fn hex_names_round_trip_and_only_lower_case_is_ours() {
    let id = [0xab; 16];
    assert_eq!(parse_hex(&hex(&id)), Some(id));
    assert_eq!(parse_hex(&hex(&id).to_uppercase()), None);
    assert_eq!(dir_of(&id), Path::new("ab").join("ab"));
    assert!(is_hex_dir("0f") && !is_hex_dir("0F") && !is_hex_dir("abc"));
}

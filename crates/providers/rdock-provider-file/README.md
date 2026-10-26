# rdock-provider-file

File provider: YAML and JSON files or directories, watched for changes.

**Status:** skeleton. In v0.1 the single configuration file is loaded by `rdock-config` and watched by the binary (`crates/rdock/src/watch.rs`); this crate takes over when extra files and directories (`providers.file`) arrive with the provider merge of v0.2. Design: [architecture §4](../../../docs/05-architecture.md).

//! `rdock trust`: installs the local CA's root into the operating system's trust stores, or
//! removes it (ADR-0020). It only ever runs when asked; `rdock run` never touches trust stores.
//!
//! Each platform tool is called directly with explicit arguments, never through a shell.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::Context;

use crate::TrustArgs;

/// File name of the root in the system anchor directories.
const ANCHOR_FILE: &str = "rdock-local-ca";
/// The macOS keychain that holds trust for all users.
const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// One thing to do to a trust store.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// Copy the root to a system anchor directory.
    Copy { from: PathBuf, to: PathBuf },
    /// Remove a copy of the root; a missing file is fine.
    Remove(PathBuf),
    /// Run a program.
    Run { program: String, args: Vec<String> },
    /// Nothing can be run on this platform; tell the operator what to run.
    Print(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    MacOs,
    Linux,
    Windows,
    Other,
}

impl Platform {
    fn current() -> Self {
        match std::env::consts::OS {
            "macos" => Self::MacOs,
            "linux" => Self::Linux,
            "windows" => Self::Windows,
            _ => Self::Other,
        }
    }
}

/// What the plan may look at on the host.
struct Probe<'a> {
    /// Whether a program is on `PATH`.
    has_program: &'a dyn Fn(&str) -> bool,
    /// Whether a directory exists.
    is_dir: &'a dyn Fn(&Path) -> bool,
    /// The user's home directory, for the NSS database Chrome and Firefox use on Linux.
    home: Option<PathBuf>,
}

/// The Linux anchor directories and the command that rebuilds the bundle from each, in the
/// order distributions are checked: Debian/Ubuntu/Alpine, Fedora/RHEL, Arch.
const LINUX_STORES: &[(&str, &str, &str, &[&str])] = &[
    (
        "/usr/local/share/ca-certificates",
        "crt",
        "update-ca-certificates",
        &[],
    ),
    (
        "/etc/pki/ca-trust/source/anchors",
        "pem",
        "update-ca-trust",
        &["extract"],
    ),
    (
        "/etc/ca-certificates/trust-source/anchors",
        "crt",
        "trust",
        &["extract-compat"],
    ),
];

fn run(program: &str, args: &[&str]) -> Step {
    Step::Run {
        program: program.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
    }
}

/// The steps that install (or, with `uninstall`, remove) `root`, named `name`, on `os`.
fn plan(os: Platform, root: &Path, name: &str, uninstall: bool, probe: &Probe<'_>) -> Vec<Step> {
    let root_arg = root.display().to_string();
    let mut steps = Vec::new();
    match os {
        Platform::MacOs if uninstall => {
            steps.push(run("security", &["remove-trusted-cert", "-d", &root_arg]));
            steps.push(run(
                "security",
                &["delete-certificate", "-c", name, SYSTEM_KEYCHAIN],
            ));
        }
        Platform::MacOs => steps.push(run(
            "security",
            &[
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                SYSTEM_KEYCHAIN,
                &root_arg,
            ],
        )),
        Platform::Linux => {
            let store = LINUX_STORES.iter().find(|(dir, _, program, _)| {
                (probe.is_dir)(Path::new(dir)) && (probe.has_program)(program)
            });
            if let Some((dir, extension, program, args)) = store {
                let anchor = Path::new(dir).join(format!("{ANCHOR_FILE}.{extension}"));
                steps.push(if uninstall {
                    Step::Remove(anchor)
                } else {
                    Step::Copy {
                        from: root.to_owned(),
                        to: anchor,
                    }
                });
                let mut args = args.to_vec();
                // Without --fresh, update-ca-certificates keeps links to removed anchors.
                if uninstall && *program == "update-ca-certificates" {
                    args.push("--fresh");
                }
                steps.push(run(program, &args));
            } else {
                steps.push(Step::Print(
                    "no system trust store found (looked for update-ca-certificates, update-ca-trust and trust); add the root to it by hand".to_owned(),
                ));
            }
        }
        Platform::Windows => steps.push(Step::Print(if uninstall {
            format!("run in an administrator prompt: certutil -delstore ROOT \"{name}\"")
        } else {
            format!("run in an administrator prompt: certutil -addstore -f ROOT \"{root_arg}\"")
        })),
        Platform::Other => steps.push(Step::Print(format!(
            "this platform has no supported trust store; trust {root_arg} by hand"
        ))),
    }
    // NSS keeps its own store (Chrome and Firefox on Linux); Windows' certutil is another tool.
    if os != Platform::Windows
        && (probe.has_program)("certutil")
        && let Some(db) = probe.home.as_ref().map(|h| h.join(".pki/nssdb"))
        && (probe.is_dir)(&db)
    {
        let db = format!("sql:{}", db.display());
        steps.push(if uninstall {
            run("certutil", &["-D", "-d", &db, "-n", name])
        } else {
            run(
                "certutil",
                &["-A", "-d", &db, "-t", "C,,", "-n", name, "-i", &root_arg],
            )
        });
    }
    steps
}

/// `rdock trust [--uninstall]`.
pub(crate) fn trust(args: &TrustArgs) -> anyhow::Result<ExitCode> {
    let dir = args.data_dir.join("pki");
    let (root, name) = if args.uninstall {
        let name = rdock_acme::local_ca::root_name(&dir)
            .context("reading the local CA")?
            .with_context(|| format!("there is no local CA in {}", dir.display()))?;
        (dir.join("root.pem"), name)
    } else {
        let ca = rdock_acme::LocalCa::open(&dir, unix_now()).context("opening the local CA")?;
        (ca.root_path(), ca.name().to_owned())
    };
    let probe = Probe {
        has_program: &on_path,
        is_dir: &|p: &Path| p.is_dir(),
        home: std::env::var_os("HOME").map(PathBuf::from),
    };
    println!("{name}: {}", root.display());
    let mut failed = false;
    for step in plan(Platform::current(), &root, &name, args.uninstall, &probe) {
        if let Err(e) = execute(&step) {
            eprintln!("error: {e:#}");
            failed = true;
        }
    }
    if failed {
        eprintln!(
            "hint: changing the system trust store needs administrator rights; run `sudo rdock trust{} --data-dir {}`",
            if args.uninstall { " --uninstall" } else { "" },
            args.data_dir.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "{}",
        if args.uninstall {
            "removed the local CA from the trust stores"
        } else {
            "the local CA is trusted; restart browsers that were open"
        }
    );
    Ok(ExitCode::SUCCESS)
}

fn execute(step: &Step) -> anyhow::Result<()> {
    match step {
        Step::Copy { from, to } => {
            std::fs::copy(from, to)
                .with_context(|| format!("copying the root to {}", to.display()))?;
            println!("copied the root to {}", to.display());
        }
        Step::Remove(path) => match std::fs::remove_file(path) {
            Ok(()) => println!("removed {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        },
        Step::Run { program, args } => {
            println!("running {program} {}", args.join(" "));
            let status = Command::new(program)
                .args(args)
                .status()
                .with_context(|| format!("starting {program}"))?;
            anyhow::ensure!(status.success(), "{program} failed ({status})");
        }
        Step::Print(text) => println!("{text}"),
    }
    Ok(())
}

/// Whether `program` is an executable file in a `PATH` directory.
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "ReverseDock Local CA 2026";

    fn probe<'a>(
        programs: &'a [&'a str],
        dirs: &'a [&'a str],
        home: Option<&str>,
    ) -> (
        impl Fn(&str) -> bool + 'a,
        impl Fn(&Path) -> bool + 'a,
        Option<PathBuf>,
    ) {
        (
            move |p: &str| programs.contains(&p),
            move |d: &Path| dirs.iter().any(|x| Path::new(x) == d),
            home.map(PathBuf::from),
        )
    }

    fn steps(os: Platform, uninstall: bool, programs: &[&str], dirs: &[&str]) -> Vec<Step> {
        let (has_program, is_dir, home) = probe(programs, dirs, Some("/home/dev"));
        let probe = Probe {
            has_program: &has_program,
            is_dir: &is_dir,
            home,
        };
        plan(os, Path::new("/data/pki/root.pem"), NAME, uninstall, &probe)
    }

    fn cmd(program: &str, args: &[&str]) -> Step {
        run(program, args)
    }

    #[test]
    fn macos_uses_the_system_keychain() {
        assert_eq!(
            steps(Platform::MacOs, false, &[], &[]),
            [cmd(
                "security",
                &[
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-k",
                    "/Library/Keychains/System.keychain",
                    "/data/pki/root.pem"
                ]
            )]
        );
        assert_eq!(
            steps(Platform::MacOs, true, &[], &[]),
            [
                cmd(
                    "security",
                    &["remove-trusted-cert", "-d", "/data/pki/root.pem"]
                ),
                cmd(
                    "security",
                    &[
                        "delete-certificate",
                        "-c",
                        NAME,
                        "/Library/Keychains/System.keychain"
                    ]
                ),
            ]
        );
    }

    #[test]
    fn linux_uses_the_first_store_present_and_nss() {
        let debian = "/usr/local/share/ca-certificates";
        let fedora = "/etc/pki/ca-trust/source/anchors";
        let nss = "/home/dev/.pki/nssdb";
        assert_eq!(
            steps(
                Platform::Linux,
                false,
                &["update-ca-certificates", "certutil"],
                &[debian, nss]
            ),
            [
                Step::Copy {
                    from: "/data/pki/root.pem".into(),
                    to: format!("{debian}/rdock-local-ca.crt").into(),
                },
                cmd("update-ca-certificates", &[]),
                cmd(
                    "certutil",
                    &[
                        "-A",
                        "-d",
                        "sql:/home/dev/.pki/nssdb",
                        "-t",
                        "C,,",
                        "-n",
                        NAME,
                        "-i",
                        "/data/pki/root.pem"
                    ]
                ),
            ]
        );
        assert_eq!(
            steps(
                Platform::Linux,
                true,
                &["update-ca-certificates"],
                &[debian]
            ),
            [
                Step::Remove(format!("{debian}/rdock-local-ca.crt").into()),
                cmd("update-ca-certificates", &["--fresh"]),
            ]
        );
        assert_eq!(
            steps(Platform::Linux, false, &["update-ca-trust"], &[fedora]),
            [
                Step::Copy {
                    from: "/data/pki/root.pem".into(),
                    to: format!("{fedora}/rdock-local-ca.pem").into(),
                },
                cmd("update-ca-trust", &["extract"]),
            ]
        );
        assert_eq!(
            steps(
                Platform::Linux,
                true,
                &["trust", "certutil"],
                &["/etc/ca-certificates/trust-source/anchors", nss]
            )[1..],
            [
                cmd("trust", &["extract-compat"]),
                cmd(
                    "certutil",
                    &["-D", "-d", "sql:/home/dev/.pki/nssdb", "-n", NAME]
                ),
            ]
        );
        assert!(matches!(
            steps(Platform::Linux, false, &[], &[]).as_slice(),
            [Step::Print(_)]
        ));
    }

    #[test]
    fn windows_only_prints_the_command() {
        let install = steps(
            Platform::Windows,
            false,
            &["certutil"],
            &["/home/dev/.pki/nssdb"],
        );
        assert_eq!(
            install,
            [Step::Print(
                "run in an administrator prompt: certutil -addstore -f ROOT \"/data/pki/root.pem\""
                    .to_owned()
            )]
        );
        let uninstall = steps(Platform::Windows, true, &[], &[]);
        assert!(matches!(&uninstall[..], [Step::Print(t)] if t.contains("-delstore ROOT")));
    }
}

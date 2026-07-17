//! Cross-platform repository maintenance commands.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::process::{Command, ExitCode};

type DynError = Box<dyn Error + Send + Sync + 'static>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), DynError> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("check") => check(),
        Some("test") => test(),
        Some("security") => security(),
        Some(command) => Err(format!("unknown command `{command}`").into()),
        None => Err("expected one of: check, test, security".into()),
    }
}

fn check() -> Result<(), DynError> {
    cargo(["fmt", "--all", "--check"])?;
    cargo(["check", "--workspace", "--all-targets", "--all-features"])?;
    cargo([
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ])?;
    command(
        "cargo",
        ["doc", "--workspace", "--all-features", "--no-deps"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )
}

fn test() -> Result<(), DynError> {
    cargo(["test", "--workspace", "--all-features"])?;
    cargo(["test", "--workspace", "--doc"])
}

fn security() -> Result<(), DynError> {
    command("cargo", ["audit"], &[])?;
    command("cargo", ["deny", "check"], &[])
}

fn cargo<const N: usize>(args: [&str; N]) -> Result<(), DynError> {
    command("cargo", args, &[])
}

fn command<I, S>(program: &str, args: I, envs: &[(&str, &str)]) -> Result<(), DynError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(program)
        .args(args)
        .envs(envs.iter().copied())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{program}` exited with {status}").into())
    }
}

//! Safe shell snippets for the Rebyte executable path.

#![allow(clippy::redundant_pub_crate)]

use std::path::Path;

use clap::{Args, ValueEnum};

use super::{CliError, EXIT_GENERIC};

#[derive(Debug, Args)]
pub(super) struct ShellEnvCommand {
    /// Shell syntax to generate.
    #[arg(value_enum)]
    shell: EnvironmentShell,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum EnvironmentShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

pub(super) fn run(command: &ShellEnvCommand) -> Result<(), CliError> {
    let executable = std::env::current_exe().map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!("cannot resolve the current Rebyte executable: {error}"),
        )
    })?;
    println!("{}", render(command.shell, &executable));
    Ok(())
}

fn render(shell: EnvironmentShell, executable: &Path) -> String {
    let path = executable.to_string_lossy();
    match shell {
        EnvironmentShell::Bash | EnvironmentShell::Zsh => {
            format!("export REBYTE='{}'", path.replace('\'', "'\\''"))
        }
        EnvironmentShell::Fish => format!(
            "set -gx REBYTE '{}'",
            path.replace('\\', "\\\\").replace('\'', "\\'")
        ),
        EnvironmentShell::Powershell => {
            format!("$env:REBYTE = '{}'", path.replace('\'', "''"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{EnvironmentShell, render};

    #[test]
    fn quotes_each_supported_shell_without_losing_the_path() {
        let path = Path::new("/tmp/Rebyte's build/rebyte");
        assert_eq!(
            render(EnvironmentShell::Bash, path),
            "export REBYTE='/tmp/Rebyte'\\''s build/rebyte'"
        );
        assert_eq!(
            render(EnvironmentShell::Zsh, path),
            "export REBYTE='/tmp/Rebyte'\\''s build/rebyte'"
        );
        assert_eq!(
            render(EnvironmentShell::Fish, path),
            "set -gx REBYTE '/tmp/Rebyte\\'s build/rebyte'"
        );
        assert_eq!(
            render(EnvironmentShell::Powershell, path),
            "$env:REBYTE = '/tmp/Rebyte''s build/rebyte'"
        );
    }
}

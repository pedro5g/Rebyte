//! Best-effort process hardening against accidental secret exposure.
//!
//! Disabling core dumps keeps decrypted seeds and passphrases out of crash
//! files, and marking the Linux process non-dumpable additionally blocks
//! `ptrace` attachment by other unprivileged processes. This is defense
//! against accidents and casual local attackers only: root, a debugger
//! started before hardening, cold-boot access and a compromised OS remain
//! outside the boundary, as documented in the security model. Failures are
//! ignored so restricted sandboxes can still run read-only commands.

#![allow(clippy::redundant_pub_crate)]

pub(super) fn harden_process() {
    disable_core_dumps();
    disable_tracing();
}

#[cfg(unix)]
fn disable_core_dumps() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let _best_effort = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
}

#[cfg(not(unix))]
fn disable_core_dumps() {}

#[cfg(target_os = "linux")]
fn disable_tracing() {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};

    let _best_effort = set_dumpable_behavior(DumpableBehavior::NotDumpable);
}

#[cfg(not(target_os = "linux"))]
fn disable_tracing() {}

#[cfg(test)]
mod tests {
    use super::harden_process;

    #[cfg(unix)]
    #[test]
    fn core_dump_limit_is_zero_after_hardening() {
        use rustix::process::{Resource, getrlimit};

        harden_process();
        let limit = getrlimit(Resource::Core);
        assert_eq!(limit.current, Some(0));
    }

    #[cfg(not(unix))]
    #[test]
    fn hardening_is_a_supported_no_op() {
        harden_process();
    }
}

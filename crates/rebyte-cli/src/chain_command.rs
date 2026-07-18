//! Rebyte Chain identity, group-consensus and encrypted capsule commands.

#![allow(clippy::redundant_pub_crate)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Args, Subcommand};
use rebyte_chain::{
    Capability, CapsuleApproval, CapsuleEnvelope, CapsuleProposal, ChainError, ChainLimits,
    ContentKind as ContractContentKind, EncryptedIdentityDocument, GroupAcceptance,
    GroupCertificate, GroupProposal, IdentityPublicDocument, ReleasePolicy, UnlockedIdentity,
    accept_group, approve_capsule, create_capsule_proposal, create_semantic_patch_proposal,
    finalize_capsule, finalize_group, generate_identity, open_capsule, open_semantic_patch,
};
use rebyte_core::{
    ApplyOptions, ApplyReport, ArtifactEntryKind, ArtifactKind, DiffReport, DirectoryChangeKind,
    DirectoryDiffEntry, VerifiedFile, apply_verified_tree, decode_artifact, decode_artifact_file,
    diff_verified_directories, diff_verified_files,
};
use rebyte_format::{ContentKind as FileContentKind, Digest32, RelativeArtifactPath};
use serde::Serialize;

use super::keys::{PassphraseArgs, ensure_output_absent, read_passphrase};
use super::security_io::{read_bounded_nofollow, require_private_permissions, write_new};
use super::{
    CliError, EXIT_DIGEST, EXIT_GENERIC, EXIT_INVALID_SIGNATURE, EXIT_MALFORMED, EXIT_POLICY,
    write_json,
};

const MAX_IDENTITY_DOCUMENT_BYTES: u64 = 128 * 1_024;
const MAX_GROUP_DOCUMENT_BYTES: u64 = 2 * 1_024 * 1_024;
const MAX_APPROVAL_DOCUMENT_BYTES: u64 = 128 * 1_024;

#[derive(Debug, Args)]
pub(super) struct ChainCommand {
    #[command(subcommand)]
    command: ChainSubcommand,
}

#[derive(Debug, Subcommand)]
enum ChainSubcommand {
    /// Generate and inspect self-custodied signing and encryption identities.
    Identity(IdentityCommand),
    /// Form a unanimous group with a configurable capsule threshold.
    Group(GroupCommand),
    /// Encrypt, approve, finalize, inspect and open group capsules.
    Capsule(CapsuleCommand),
}

#[derive(Debug, Args)]
struct IdentityCommand {
    #[command(subcommand)]
    command: IdentitySubcommand,
}

#[derive(Debug, Subcommand)]
enum IdentitySubcommand {
    /// Generate independent Ed25519 and X25519 keys in an encrypted bundle.
    Generate(IdentityGenerateCommand),
    /// Validate a distributable public identity package.
    Inspect(IdentityInspectCommand),
}

#[derive(Debug, Args)]
struct IdentityGenerateCommand {
    /// Human-readable local identity name.
    #[arg(long, value_name = "NAME")]
    name: String,
    /// Passphrase-protected private `.rbk` output.
    #[arg(long, value_name = "PATH", default_value = "rebyte-identity.rbk")]
    private_key: PathBuf,
    /// Distributable public identity output.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "rebyte-identity.public.json"
    )]
    public_key: PathBuf,
    #[command(flatten)]
    passphrase: PassphraseArgs,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct IdentityInspectCommand {
    /// Public identity document.
    public_key: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct GroupCommand {
    #[command(subcommand)]
    command: GroupSubcommand,
}

#[derive(Debug, Subcommand)]
enum GroupSubcommand {
    /// Create a proposal from public identities.
    Create(GroupCreateCommand),
    /// Accept one exact group proposal with a listed private identity.
    Accept(GroupAcceptCommand),
    /// Require every member acceptance and issue the group certificate.
    Finalize(GroupFinalizeCommand),
    /// Verify and display a finalized group certificate.
    Inspect(GroupInspectCommand),
}

#[derive(Debug, Args)]
struct GroupCreateCommand {
    /// Human-readable group name.
    #[arg(long, value_name = "NAME")]
    name: String,
    /// Public identity document; repeat for every member.
    #[arg(long = "member", value_name = "PATH", required = true)]
    members: Vec<PathBuf>,
    /// Number of unique member approvals required for each capsule.
    #[arg(long, value_name = "T")]
    threshold: u16,
    /// New group-proposal document.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct GroupAcceptCommand {
    /// Group-proposal document to accept.
    proposal: PathBuf,
    #[command(flatten)]
    identity: PrivateIdentityArgs,
    /// New member-acceptance document.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct GroupFinalizeCommand {
    /// Group proposal accepted by the members.
    proposal: PathBuf,
    /// Member-acceptance document; every member is mandatory.
    #[arg(long = "acceptance", value_name = "PATH", required = true)]
    acceptances: Vec<PathBuf>,
    /// New finalized group certificate.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct GroupInspectCommand {
    /// Group proposal or finalized certificate.
    document: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleCommand {
    #[command(subcommand)]
    command: CapsuleSubcommand,
}

#[derive(Debug, Subcommand)]
enum CapsuleSubcommand {
    /// Encrypt one canonical `.rba` or semantic patch for recipients.
    Create(CapsuleCreateCommand),
    /// Approve one exact encrypted proposal as a group member.
    Approve(CapsuleApproveCommand),
    /// Verify the group threshold and create the final `.rbe`.
    Finalize(CapsuleFinalizeCommand),
    /// Verify and display an encrypted proposal or finalized capsule.
    Inspect(CapsuleInspectCommand),
    /// Decrypt and reconstruct an artifact for an authorized recipient.
    Open(CapsuleOpenCommand),
    /// Decrypt and compare an authorized artifact with a local root.
    Diff(CapsuleDiffCommand),
    /// Decrypt and transactionally apply an authorized artifact.
    Apply(CapsuleApplyCommand),
    /// Decrypt and atomically apply an authorized semantic patch.
    Patch(CapsulePatchCommand),
}

#[derive(Debug, Args)]
struct CapsuleCreateCommand {
    /// Finalized group certificate controlling capsule approval.
    #[arg(long, value_name = "PATH")]
    group: PathBuf,
    /// Canonical `.rba` produced by `rebyte encode --format binary`.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "patch",
        conflicts_with = "patch"
    )]
    artifact: Option<PathBuf>,
    /// Canonical patch produced by `rebyte patch create`.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "artifact",
        conflicts_with = "artifact"
    )]
    patch: Option<PathBuf>,
    /// Public recipient identity; repeat for every person allowed to open.
    #[arg(long = "recipient", value_name = "PATH", required = true)]
    recipients: Vec<PathBuf>,
    /// New encrypted proposal awaiting group approvals.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleApproveCommand {
    /// Encrypted capsule proposal.
    proposal: PathBuf,
    #[command(flatten)]
    identity: PrivateIdentityArgs,
    /// New capsule-approval document.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleFinalizeCommand {
    /// Encrypted capsule proposal.
    proposal: PathBuf,
    /// Member capsule approval; repeat until the group threshold is met.
    #[arg(long = "approval", value_name = "PATH", required = true)]
    approvals: Vec<PathBuf>,
    /// New binary `.rbe` encrypted capsule.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
    /// Also print the equivalent `rbe2_` token.
    #[arg(long)]
    print_token: bool,
    /// Emit stable JSON; cannot be combined with `--print-token`.
    #[arg(long, conflicts_with = "print_token")]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleInspectCommand {
    #[command(flatten)]
    input: CapsuleInputArgs,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleOpenCommand {
    #[command(flatten)]
    input: CapsuleInputArgs,
    #[command(flatten)]
    identity: PrivateIdentityArgs,
    /// Reconstructed file or directory output.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
    /// Write the decrypted canonical `.rba` instead of reconstructing it.
    #[arg(long)]
    raw_artifact: bool,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleDiffCommand {
    #[command(flatten)]
    input: CapsuleInputArgs,
    #[command(flatten)]
    identity: PrivateIdentityArgs,
    /// Capability-confined local comparison root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Relative target for a single-file artifact, overriding its suggestion.
    #[arg(long, value_name = "RELATIVE_PATH")]
    path: Option<String>,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsuleApplyCommand {
    #[command(flatten)]
    input: CapsuleInputArgs,
    #[command(flatten)]
    identity: PrivateIdentityArgs,
    /// Capability-confined local application root.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Relative target for a single-file artifact, overriding its suggestion.
    #[arg(long, value_name = "RELATIVE_PATH")]
    path: Option<String>,
    #[command(flatten)]
    mode: super::ApplyModeArgs,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CapsulePatchCommand {
    #[command(flatten)]
    input: CapsuleInputArgs,
    #[command(flatten)]
    identity: PrivateIdentityArgs,
    /// Existing JSON or TOML target file.
    #[arg(long, value_name = "PATH")]
    target: PathBuf,
    #[command(flatten)]
    mode: super::semantic_command::PatchApplyMode,
    /// Emit stable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PrivateIdentityArgs {
    /// Passphrase-protected Chain private identity.
    #[arg(long, value_name = "PATH")]
    private_key: PathBuf,
    #[command(flatten)]
    passphrase: PassphraseArgs,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct CapsuleInputArgs {
    /// Inline `rbe2_` capsule token.
    #[arg(value_name = "TOKEN", conflicts_with = "file")]
    token: Option<String>,
    /// Binary `.rbe` capsule file.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
}

pub(super) fn run(command: &ChainCommand) -> Result<(), CliError> {
    match &command.command {
        ChainSubcommand::Identity(command) => run_identity(command),
        ChainSubcommand::Group(command) => run_group(command),
        ChainSubcommand::Capsule(command) => run_capsule(command),
    }
}

fn run_identity(command: &IdentityCommand) -> Result<(), CliError> {
    match &command.command {
        IdentitySubcommand::Generate(command) => generate_identity_command(command),
        IdentitySubcommand::Inspect(command) => inspect_identity(command),
    }
}

fn run_group(command: &GroupCommand) -> Result<(), CliError> {
    match &command.command {
        GroupSubcommand::Create(command) => create_group(command),
        GroupSubcommand::Accept(command) => accept_group_command(command),
        GroupSubcommand::Finalize(command) => finalize_group_command(command),
        GroupSubcommand::Inspect(command) => inspect_group(command),
    }
}

fn run_capsule(command: &CapsuleCommand) -> Result<(), CliError> {
    match &command.command {
        CapsuleSubcommand::Create(command) => create_capsule(command),
        CapsuleSubcommand::Approve(command) => approve_capsule_command(command),
        CapsuleSubcommand::Finalize(command) => finalize_capsule_command(command),
        CapsuleSubcommand::Inspect(command) => inspect_capsule(command),
        CapsuleSubcommand::Open(command) => open_capsule_command(command),
        CapsuleSubcommand::Diff(command) => diff_capsule_command(command),
        CapsuleSubcommand::Apply(command) => apply_capsule_command(command),
        CapsuleSubcommand::Patch(command) => patch_capsule_command(command),
    }
}

fn generate_identity_command(command: &IdentityGenerateCommand) -> Result<(), CliError> {
    if command.private_key == command.public_key {
        return Err(CliError::new(
            EXIT_GENERIC,
            "private and public identity outputs must differ",
        ));
    }
    ensure_output_absent(&command.private_key)?;
    ensure_output_absent(&command.public_key)?;
    let passphrase = read_passphrase(&command.passphrase, true)?;
    let (private, public) =
        generate_identity(&command.name, passphrase.as_bytes()).map_err(chain_error)?;
    write_new(
        &command.private_key,
        &private.to_json().map_err(chain_error)?,
        true,
    )
    .map_err(|error| {
        CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create Chain private identity {}: {error}",
                command.private_key.display()
            ),
        )
    })?;
    if let Err(error) = write_new(
        &command.public_key,
        &public.to_json().map_err(chain_error)?,
        false,
    ) {
        let _cleanup = fs::remove_file(&command.private_key);
        return Err(CliError::new(
            EXIT_GENERIC,
            format!(
                "cannot create Chain public identity {}: {error}",
                command.public_key.display()
            ),
        ));
    }
    let report = identity_report(&public)?;
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Chain identity generated"));
        println!("  Name            {}", report.display_name);
        println!("  Identity ID     {}", report.identity_id);
        println!("  Signing         Ed25519");
        println!("  Encryption      HPKE X25519/HKDF-SHA256/ChaCha20-Poly1305");
        println!("  Private bundle  {}", command.private_key.display());
        println!("  Public package  {}", command.public_key.display());
        println!("\nKeep the private bundle and passphrase in separate verified backups.");
        Ok(())
    }
}

fn inspect_identity(command: &IdentityInspectCommand) -> Result<(), CliError> {
    let public = read_public_identity(&command.public_key)?;
    let report = identity_report(&public)?;
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::heading("Rebyte Chain identity"));
        println!("  Name         {}", report.display_name);
        println!("  Identity ID  {}", report.identity_id);
        println!("  Signing      Ed25519");
        println!("  Encryption   HPKE X25519/HKDF-SHA256/ChaCha20-Poly1305");
        println!("  Proof        valid");
        Ok(())
    }
}

fn create_group(command: &GroupCreateCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let members = command
        .members
        .iter()
        .map(|path| read_public_identity(path))
        .collect::<Result<Vec<_>, _>>()?;
    let proposal =
        GroupProposal::new(&command.name, command.threshold, members).map_err(chain_error)?;
    write_new(
        &command.output,
        &proposal.to_json().map_err(chain_error)?,
        false,
    )
    .map_err(|error| output_error("group proposal", &command.output, &error))?;
    let report = GroupReport::from_proposal(&proposal, false, 0)?;
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Group proposal created"));
        print_group_report(&report);
        println!("  Output      {}", command.output.display());
        println!("\nEvery listed member must accept this exact Group ID.");
        Ok(())
    }
}

fn accept_group_command(command: &GroupAcceptCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let proposal = read_group_proposal(&command.proposal)?;
    let identity = unlock_identity(&command.identity)?;
    let acceptance = accept_group(&proposal, &identity).map_err(chain_error)?;
    write_new(
        &command.output,
        &acceptance.to_json().map_err(chain_error)?,
        false,
    )
    .map_err(|error| output_error("group acceptance", &command.output, &error))?;
    let report = SignatureReport {
        schema_version: 1,
        kind: "groupAcceptance",
        group_id: proposal.group_id().map_err(chain_error)?.to_base64(),
        proposal_id: None,
        member_id: acceptance.member_id().map_err(chain_error)?.to_base64(),
        output: command.output.display().to_string(),
    };
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Group proposal accepted"));
        println!("  Group ID   {}", report.group_id);
        println!("  Member ID  {}", report.member_id);
        println!("  Output     {}", report.output);
        Ok(())
    }
}

fn finalize_group_command(command: &GroupFinalizeCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let proposal = read_group_proposal(&command.proposal)?;
    let acceptances = command
        .acceptances
        .iter()
        .map(|path| read_group_acceptance(path))
        .collect::<Result<Vec<_>, _>>()?;
    let certificate = finalize_group(proposal, acceptances).map_err(chain_error)?;
    write_new(
        &command.output,
        &certificate.to_json().map_err(chain_error)?,
        false,
    )
    .map_err(|error| output_error("group certificate", &command.output, &error))?;
    let report = GroupReport::from_certificate(&certificate)?;
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Consensus group finalized"));
        print_group_report(&report);
        println!("  Output      {}", command.output.display());
        Ok(())
    }
}

fn inspect_group(command: &GroupInspectCommand) -> Result<(), CliError> {
    let bytes = read_bounded_nofollow(&command.document, MAX_GROUP_DOCUMENT_BYTES)
        .map_err(|error| input_error("group document", &command.document, &error))?;
    let (report, heading) = match GroupCertificate::from_json(&bytes) {
        Ok(certificate) => (
            GroupReport::from_certificate(&certificate)?,
            "Rebyte Chain group certificate",
        ),
        Err(certificate_error) => match GroupProposal::from_json(&bytes) {
            Ok(proposal) => (
                GroupReport::from_proposal(&proposal, false, 0)?,
                "Rebyte Chain group proposal",
            ),
            Err(_) => return Err(chain_error(certificate_error)),
        },
    };
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::heading(heading));
        print_group_report(&report);
        if report.formation_complete {
            println!("  Formation   unanimous and verified");
        } else {
            println!("  Formation   proposal · every listed member must accept");
        }
        Ok(())
    }
}

fn create_capsule(command: &CapsuleCreateCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let limits = ChainLimits::STANDARD;
    let group = read_group_certificate(&command.group)?;
    let (content, semantic_patch) = if let Some(path) = &command.artifact {
        (
            read_bounded_nofollow(path, limits.artifact.max_capsule_bytes).map_err(|error| {
                CliError::new(
                    EXIT_GENERIC,
                    format!("cannot read Chain artifact {}: {error}", path.display()),
                )
            })?,
            false,
        )
    } else if let Some(path) = &command.patch {
        (
            read_bounded_nofollow(path, rebyte_core::MAX_PATCH_BYTES).map_err(|error| {
                CliError::new(
                    EXIT_GENERIC,
                    format!(
                        "cannot read Chain semantic patch {}: {error}",
                        path.display()
                    ),
                )
            })?,
            true,
        )
    } else {
        return Err(CliError::new(
            EXIT_MALFORMED,
            "either --artifact or --patch is required",
        ));
    };
    let recipients = command
        .recipients
        .iter()
        .map(|path| read_public_identity(path))
        .collect::<Result<Vec<_>, _>>()?;
    let proposal = if semantic_patch {
        create_semantic_patch_proposal(group, &content, recipients, &limits)
    } else {
        create_capsule_proposal(group, &content, recipients, &limits)
    }
    .map_err(chain_error)?;
    let bytes = proposal.to_bytes(&limits).map_err(chain_error)?;
    write_new(&command.output, &bytes, false)
        .map_err(|error| output_error("capsule proposal", &command.output, &error))?;
    let report = CapsuleReport::from_proposal(&proposal, false, 0, bytes.len())?;
    if command.json {
        write_json(&report)
    } else {
        println!(
            "{}",
            super::ui::success("✓ Encrypted capsule proposal created")
        );
        print_capsule_report(&report);
        println!("  Output       {}", command.output.display());
        println!(
            "\nCollect {} unique group approvals before finalization.",
            report.required_approvals
        );
        Ok(())
    }
}

fn approve_capsule_command(command: &CapsuleApproveCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let limits = ChainLimits::STANDARD;
    let proposal = read_capsule_proposal(&command.proposal, &limits)?;
    let identity = unlock_identity(&command.identity)?;
    let approval = approve_capsule(&proposal, &identity, &limits).map_err(chain_error)?;
    write_new(
        &command.output,
        &approval.to_json().map_err(chain_error)?,
        false,
    )
    .map_err(|error| output_error("capsule approval", &command.output, &error))?;
    let report = SignatureReport {
        schema_version: 1,
        kind: "capsuleApproval",
        group_id: proposal
            .group()
            .group_id()
            .map_err(chain_error)?
            .to_base64(),
        proposal_id: Some(encode(proposal.proposal_id())),
        member_id: approval.member_id().map_err(chain_error)?.to_base64(),
        output: command.output.display().to_string(),
    };
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Capsule proposal approved"));
        println!("  Group ID     {}", report.group_id);
        println!(
            "  Proposal ID  {}",
            report.proposal_id.as_deref().unwrap_or_default()
        );
        println!("  Member ID    {}", report.member_id);
        println!("  Output       {}", report.output);
        Ok(())
    }
}

fn finalize_capsule_command(command: &CapsuleFinalizeCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let limits = ChainLimits::STANDARD;
    let proposal = read_capsule_proposal(&command.proposal, &limits)?;
    let approvals = command
        .approvals
        .iter()
        .map(|path| read_capsule_approval(path))
        .collect::<Result<Vec<_>, _>>()?;
    let envelope = finalize_capsule(proposal, approvals, &limits).map_err(chain_error)?;
    let bytes = envelope.to_bytes(&limits).map_err(chain_error)?;
    write_new(&command.output, &bytes, false)
        .map_err(|error| output_error("encrypted capsule", &command.output, &error))?;
    let report = CapsuleReport::from_envelope(&envelope, bytes.len())?;
    if command.print_token {
        println!("{}", envelope.to_token(&limits).map_err(chain_error)?);
        return Ok(());
    }
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Consensus capsule finalized"));
        print_capsule_report(&report);
        println!("  Envelope ID  {}", encode(envelope.envelope_id()));
        println!("  Output       {}", command.output.display());
        Ok(())
    }
}

fn inspect_capsule(command: &CapsuleInspectCommand) -> Result<(), CliError> {
    let limits = ChainLimits::STANDARD;
    let (report, envelope_id) = if let Some(path) = &command.input.file {
        let bytes = read_bounded_nofollow(path, limits.max_envelope_bytes)
            .map_err(|error| input_error("encrypted capsule", path, &error))?;
        match CapsuleEnvelope::from_bytes(&bytes, &limits) {
            Ok(envelope) => (
                CapsuleReport::from_envelope(&envelope, bytes.len())?,
                Some(encode(envelope.envelope_id())),
            ),
            Err(envelope_error) => match CapsuleProposal::from_bytes(&bytes, &limits) {
                Ok(proposal) => (
                    CapsuleReport::from_proposal(&proposal, false, 0, bytes.len())?,
                    None,
                ),
                Err(_) => return Err(chain_error(envelope_error)),
            },
        }
    } else {
        let envelope = read_capsule_input(&command.input, &limits)?;
        let bytes = envelope.to_bytes(&limits).map_err(chain_error)?;
        (
            CapsuleReport::from_envelope(&envelope, bytes.len())?,
            Some(encode(envelope.envelope_id())),
        )
    };
    if command.json {
        write_json(&report)
    } else {
        println!(
            "{}",
            super::ui::heading(if report.finalized {
                "Rebyte Chain encrypted capsule"
            } else {
                "Rebyte Chain encrypted proposal"
            })
        );
        print_capsule_report(&report);
        if let Some(envelope_id) = envelope_id {
            println!("  Envelope ID  {envelope_id}");
            println!("  Consensus    threshold satisfied and verified");
        } else {
            println!("  Consensus    pending group approvals");
        }
        Ok(())
    }
}

fn open_capsule_command(command: &CapsuleOpenCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let limits = ChainLimits::STANDARD;
    let envelope = read_capsule_input(&command.input, &limits)?;
    if !command.raw_artifact
        && !envelope
            .proposal()
            .contract()
            .capabilities()
            .contains(Capability::Reconstruct)
    {
        return Err(CliError::new(
            EXIT_POLICY,
            "access contract does not grant reconstruction",
        ));
    }
    let identity = unlock_identity(&command.identity)?;
    let opened = open_capsule(&envelope, &identity, &limits).map_err(chain_error)?;
    let content_bytes = opened.artifact_binary();
    if command.raw_artifact {
        write_new(&command.output, content_bytes, false)
            .map_err(|error| output_error("decrypted artifact", &command.output, &error))?;
    } else {
        let mut temporary = tempfile::Builder::new()
            .prefix("rebyte-chain-open-")
            .suffix(".rba")
            .tempfile()
            .map_err(|error| {
                CliError::new(
                    EXIT_GENERIC,
                    format!("cannot stage decrypted Chain artifact: {error}"),
                )
            })?;
        temporary.write_all(content_bytes).map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot stage decrypted Chain bytes: {error}"),
            )
        })?;
        temporary.as_file().sync_all().map_err(|error| {
            CliError::new(
                EXIT_GENERIC,
                format!("cannot synchronize decrypted Chain staging: {error}"),
            )
        })?;
        decode_artifact_file(temporary.path(), Some(&command.output), &limits.artifact).map_err(
            |error| {
                CliError::new(
                    EXIT_GENERIC,
                    format!("cannot reconstruct decrypted Chain artifact: {error}"),
                )
            },
        )?;
    }
    let report = OpenReport {
        schema_version: 2,
        contract_id: opened.contract_id().to_base64(),
        group_id: opened.group_id().to_base64(),
        proposal_id: encode(opened.proposal_id()),
        recipient_id: opened.recipient_id().to_base64(),
        content_bytes: content_bytes.len(),
        raw_artifact: command.raw_artifact,
        output: command.output.display().to_string(),
    };
    if command.json {
        write_json(&report)
    } else {
        println!("{}", super::ui::success("✓ Consensus capsule opened"));
        println!("  Contract     {}", report.contract_id);
        println!("  Group ID     {}", report.group_id);
        println!("  Proposal ID  {}", report.proposal_id);
        println!("  Recipient    {}", report.recipient_id);
        println!(
            "  Artifact     {} encrypted bytes verified",
            report.content_bytes
        );
        println!("  Output       {}", report.output);
        Ok(())
    }
}

fn diff_capsule_command(command: &CapsuleDiffCommand) -> Result<(), CliError> {
    let authorized = authorize_file_operations(
        &command.input,
        &command.identity,
        command.path.as_deref(),
        Capability::Diff,
    )?;
    let report = diff_verified_files(&authorized.files, &command.root)
        .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    let directories = diff_verified_directories(&authorized.directories, &command.root)
        .map_err(|error| CliError::new(EXIT_GENERIC, error.to_string()))?;
    if command.json {
        write_json(&ChainDiffJson::new(&authorized, &report, &directories))
    } else {
        println!(
            "{}",
            super::ui::heading("Chain diff · contract and plaintext fully verified")
        );
        println!("Contract: {}", authorized.contract_id);
        println!(
            "Proposal: {}",
            encode(authorized.proposal_digest.as_bytes())
        );
        super::print_diff(&report);
        print_directory_diff(&directories);
        Ok(())
    }
}

fn apply_capsule_command(command: &CapsuleApplyCommand) -> Result<(), CliError> {
    let authorized = authorize_file_operations(
        &command.input,
        &command.identity,
        command.path.as_deref(),
        Capability::Apply,
    )?;
    let changes = diff_verified_files(&authorized.files, &command.root)
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    let directories = diff_verified_directories(&authorized.directories, &command.root)
        .map_err(|error| CliError::new(EXIT_POLICY, error.to_string()))?;
    if command.mode.dry_run {
        if command.json {
            return write_json(&ChainApplyJson::preview(
                &authorized,
                &changes,
                &directories,
            ));
        }
        println!(
            "{}",
            super::ui::heading(
                "Chain dry run · contract and plaintext verified · no files written"
            )
        );
        println!("Contract: {}", authorized.contract_id);
        super::print_diff(&changes);
        print_directory_diff(&directories);
        return Ok(());
    }
    if !command.mode.yes && !super::confirm_apply(&changes, !command.json)? {
        if command.json {
            return write_json(&ChainApplyJson::cancelled(
                &authorized,
                &changes,
                &directories,
            ));
        }
        println!(
            "{}",
            super::ui::heading("Chain application cancelled · no files were written")
        );
        return Ok(());
    }
    let report = apply_verified_tree(
        authorized.proposal_digest,
        &authorized.files,
        &authorized.directories,
        &command.root,
        &ApplyOptions {
            retain_backup: command.mode.backup,
        },
    )
    .map_err(CliError::apply)?;
    if command.json {
        write_json(&ChainApplyJson::applied(
            &authorized,
            &changes,
            &directories,
            &report,
        ))
    } else {
        println!(
            "{}",
            super::ui::success(&format!(
                "✓ Applied {} contract-authorized files ({} bytes) · transaction {}",
                report.files_written, report.bytes_written, report.transaction_id
            ))
        );
        println!("  Contract     {}", authorized.contract_id);
        if let Some(path) = report.retained_backup {
            println!("  Backup       {}", path.display());
        }
        Ok(())
    }
}

fn patch_capsule_command(command: &CapsulePatchCommand) -> Result<(), CliError> {
    let limits = ChainLimits::STANDARD;
    let envelope = read_capsule_input(&command.input, &limits)?;
    if !envelope
        .proposal()
        .contract()
        .capabilities()
        .contains(Capability::ApplySemanticPatch)
    {
        return Err(CliError::new(
            EXIT_POLICY,
            "access contract does not grant semantic patch application",
        ));
    }
    let identity = unlock_identity(&command.identity)?;
    let opened = open_semantic_patch(&envelope, &identity, &limits).map_err(chain_error)?;
    super::semantic_command::apply_patch_document(
        opened.patch(),
        &super::semantic_command::PatchApplyRequest {
            target: &command.target,
            mode: super::semantic_command::PatchApplyMode {
                dry_run: command.mode.dry_run,
                yes: command.mode.yes,
                backup: command.mode.backup,
            },
            json: command.json,
            authorization: Some(format!(
                "Chain contract {} · proposal {}",
                opened.contract_id().to_base64(),
                encode(opened.proposal_id())
            )),
        },
    )
}

struct AuthorizedFileSet {
    contract_id: String,
    proposal_digest: Digest32,
    files: Vec<VerifiedFile>,
    directories: Vec<RelativeArtifactPath>,
}

fn authorize_file_operations(
    input: &CapsuleInputArgs,
    identity: &PrivateIdentityArgs,
    path_override: Option<&str>,
    required: Capability,
) -> Result<AuthorizedFileSet, CliError> {
    let limits = ChainLimits::STANDARD;
    let envelope = read_capsule_input(input, &limits)?;
    let contract = envelope.proposal().contract();
    if !contract.capabilities().contains(required) {
        return Err(CliError::new(
            EXIT_POLICY,
            format!(
                "access contract does not grant {}",
                capability_label(required)
            ),
        ));
    }
    let identity = unlock_identity(identity)?;
    let opened = open_capsule(&envelope, &identity, &limits).map_err(chain_error)?;
    let (files, directories) =
        artifact_verified_tree(opened.artifact_binary(), path_override, &limits)?;
    Ok(AuthorizedFileSet {
        contract_id: opened.contract_id().to_base64(),
        proposal_digest: Digest32(*opened.proposal_id()),
        files,
        directories,
    })
}

fn artifact_verified_tree(
    artifact_binary: &[u8],
    path_override: Option<&str>,
    limits: &ChainLimits,
) -> Result<(Vec<VerifiedFile>, Vec<RelativeArtifactPath>), CliError> {
    let decoded = decode_artifact(artifact_binary, &limits.artifact).map_err(|error| {
        CliError::new(
            EXIT_DIGEST,
            format!("cannot verify decrypted artifact: {error}"),
        )
    })?;
    let artifact = decoded.artifact();
    match artifact.kind() {
        ArtifactKind::File => {
            let entry = artifact
                .entries()
                .first()
                .filter(|entry| entry.kind() == ArtifactEntryKind::File)
                .ok_or_else(|| CliError::new(EXIT_MALFORMED, "invalid file artifact shape"))?;
            let path = if let Some(path) = path_override {
                RelativeArtifactPath::new(path)
            } else if let Some(path) = artifact.suggested_path() {
                Ok(path.clone())
            } else if let Some(name) = artifact.suggested_name() {
                RelativeArtifactPath::new(name)
            } else {
                return Err(CliError::new(
                    EXIT_POLICY,
                    "single-file artifact has no target; pass --path RELATIVE_PATH",
                ));
            }
            .map_err(|error| {
                CliError::new(
                    EXIT_POLICY,
                    format!("invalid contract-authorized target path: {error}"),
                )
            })?;
            Ok((vec![verified_file(path, entry)], Vec::new()))
        }
        ArtifactKind::Directory => {
            if path_override.is_some() {
                return Err(CliError::new(
                    EXIT_POLICY,
                    "--path is valid only for a single-file artifact; use --root for a directory",
                ));
            }
            let files = artifact
                .entries()
                .iter()
                .filter(|entry| entry.kind() == ArtifactEntryKind::File)
                .map(|entry| {
                    entry
                        .path()
                        .cloned()
                        .map(|path| verified_file(path, entry))
                        .ok_or_else(|| {
                            CliError::new(EXIT_MALFORMED, "directory file entry has no path")
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let directories = artifact
                .entries()
                .iter()
                .filter(|entry| entry.kind() == ArtifactEntryKind::Directory)
                .map(|entry| {
                    entry
                        .path()
                        .cloned()
                        .ok_or_else(|| CliError::new(EXIT_MALFORMED, "directory entry has no path"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((files, directories))
        }
    }
}

fn verified_file(path: RelativeArtifactPath, entry: &rebyte_core::ArtifactEntry) -> VerifiedFile {
    VerifiedFile {
        path,
        bytes: entry.bytes().to_vec(),
        executable: entry.executable(),
        content_kind: if core::str::from_utf8(entry.bytes()).is_ok() {
            FileContentKind::TextUtf8
        } else {
            FileContentKind::Binary
        },
    }
}

fn print_directory_diff(directories: &[DirectoryDiffEntry]) {
    for directory in directories {
        println!(
            "{}  {}/",
            match directory.kind {
                DirectoryChangeKind::Create => "CREATE-DIR",
                DirectoryChangeKind::Unchanged => "UNCHANGED-DIR",
                _ => "UNKNOWN-DIR",
            },
            directory.path
        );
    }
}

const fn capability_label(capability: Capability) -> &'static str {
    match capability {
        Capability::InspectMetadata => "metadata inspection",
        Capability::Decrypt => "decryption",
        Capability::Reconstruct => "reconstruction",
        Capability::Diff => "diff",
        Capability::Apply => "transactional apply",
        Capability::ApplySemanticPatch => "semantic patch application",
        _ => "the requested operation",
    }
}

fn read_public_identity(path: &Path) -> Result<IdentityPublicDocument, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_IDENTITY_DOCUMENT_BYTES).map_err(|error| {
        CliError::new(
            EXIT_POLICY,
            format!(
                "cannot read Chain public identity {}: {error}",
                path.display()
            ),
        )
    })?;
    IdentityPublicDocument::from_json(&bytes).map_err(chain_error)
}

fn unlock_identity(args: &PrivateIdentityArgs) -> Result<UnlockedIdentity, CliError> {
    require_private_permissions(&args.private_key).map_err(|error| {
        CliError::new(
            EXIT_POLICY,
            format!(
                "unsafe Chain private identity {}: {error}",
                args.private_key.display()
            ),
        )
    })?;
    let bytes =
        read_bounded_nofollow(&args.private_key, MAX_IDENTITY_DOCUMENT_BYTES).map_err(|error| {
            CliError::new(
                EXIT_POLICY,
                format!(
                    "cannot read Chain private identity {}: {error}",
                    args.private_key.display()
                ),
            )
        })?;
    let document = EncryptedIdentityDocument::from_json(&bytes).map_err(chain_error)?;
    let passphrase = read_passphrase(&args.passphrase, false)?;
    document.unlock(passphrase.as_bytes()).map_err(chain_error)
}

fn read_group_proposal(path: &Path) -> Result<GroupProposal, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_GROUP_DOCUMENT_BYTES)
        .map_err(|error| input_error("group proposal", path, &error))?;
    GroupProposal::from_json(&bytes).map_err(chain_error)
}

fn read_group_acceptance(path: &Path) -> Result<GroupAcceptance, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_APPROVAL_DOCUMENT_BYTES)
        .map_err(|error| input_error("group acceptance", path, &error))?;
    GroupAcceptance::from_json(&bytes).map_err(chain_error)
}

fn read_group_certificate(path: &Path) -> Result<GroupCertificate, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_GROUP_DOCUMENT_BYTES)
        .map_err(|error| input_error("group certificate", path, &error))?;
    GroupCertificate::from_json(&bytes).map_err(chain_error)
}

fn read_capsule_proposal(path: &Path, limits: &ChainLimits) -> Result<CapsuleProposal, CliError> {
    let bytes = read_bounded_nofollow(path, limits.max_envelope_bytes)
        .map_err(|error| input_error("capsule proposal", path, &error))?;
    CapsuleProposal::from_bytes(&bytes, limits).map_err(chain_error)
}

fn read_capsule_approval(path: &Path) -> Result<CapsuleApproval, CliError> {
    let bytes = read_bounded_nofollow(path, MAX_APPROVAL_DOCUMENT_BYTES)
        .map_err(|error| input_error("capsule approval", path, &error))?;
    CapsuleApproval::from_json(&bytes).map_err(chain_error)
}

fn read_capsule_input(
    input: &CapsuleInputArgs,
    limits: &ChainLimits,
) -> Result<CapsuleEnvelope, CliError> {
    if let Some(path) = &input.file {
        let bytes = read_bounded_nofollow(path, limits.max_envelope_bytes)
            .map_err(|error| input_error("encrypted capsule", path, &error))?;
        return CapsuleEnvelope::from_bytes(&bytes, limits).map_err(chain_error);
    }
    input
        .token
        .as_deref()
        .ok_or_else(|| CliError::new(EXIT_MALFORMED, "capsule input is required"))
        .and_then(|token| CapsuleEnvelope::from_token(token, limits).map_err(chain_error))
}

fn chain_error(error: ChainError) -> CliError {
    let exit_code = match error {
        ChainError::InvalidSignature => EXIT_INVALID_SIGNATURE,
        ChainError::IntegrityMismatch
        | ChainError::InvalidArtifact
        | ChainError::InvalidContent => EXIT_DIGEST,
        ChainError::NotGroupMember
        | ChainError::NotRecipient
        | ChainError::IncompleteGroup
        | ChainError::InsufficientApprovals
        | ChainError::InvalidThreshold
        | ChainError::AuthenticationFailed
        | ChainError::IdentityMismatch
        | ChainError::BindingMismatch
        | ChainError::InvalidContract
        | ChainError::UnsupportedReleasePolicy => EXIT_POLICY,
        _ => EXIT_MALFORMED,
    };
    CliError::new(exit_code, error.to_string())
}

fn input_error(kind: &str, path: &Path, error: &std::io::Error) -> CliError {
    CliError::new(
        EXIT_GENERIC,
        format!("cannot read Chain {kind} {}: {error}", path.display()),
    )
}

fn output_error(kind: &str, path: &Path, error: &std::io::Error) -> CliError {
    CliError::new(
        EXIT_GENERIC,
        format!("cannot create Chain {kind} {}: {error}", path.display()),
    )
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityReport {
    schema_version: u16,
    display_name: String,
    identity_id: String,
    signing_algorithm: &'static str,
    encryption_algorithm: &'static str,
}

fn identity_report(public: &IdentityPublicDocument) -> Result<IdentityReport, CliError> {
    Ok(IdentityReport {
        schema_version: 1,
        display_name: public.display_name().to_string(),
        identity_id: public.identity_id().map_err(chain_error)?.to_base64(),
        signing_algorithm: "Ed25519",
        encryption_algorithm: "HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305",
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupMemberReport {
    display_name: String,
    identity_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupReport {
    schema_version: u16,
    display_name: String,
    group_id: String,
    members: Vec<GroupMemberReport>,
    member_count: usize,
    capsule_threshold: u16,
    formation_complete: bool,
    formation_acceptances: usize,
}

impl GroupReport {
    fn from_proposal(
        proposal: &GroupProposal,
        formation_complete: bool,
        formation_acceptances: usize,
    ) -> Result<Self, CliError> {
        let members = proposal
            .members()
            .iter()
            .map(|member| {
                Ok(GroupMemberReport {
                    display_name: member.display_name().to_string(),
                    identity_id: member.identity_id().map_err(chain_error)?.to_base64(),
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        Ok(Self {
            schema_version: 1,
            display_name: proposal.display_name().to_string(),
            group_id: proposal.group_id().map_err(chain_error)?.to_base64(),
            member_count: members.len(),
            members,
            capsule_threshold: proposal.capsule_threshold(),
            formation_complete,
            formation_acceptances,
        })
    }

    fn from_certificate(certificate: &GroupCertificate) -> Result<Self, CliError> {
        Self::from_proposal(
            certificate.proposal(),
            true,
            certificate.acceptances().len(),
        )
    }
}

fn print_group_report(report: &GroupReport) {
    println!("  Name        {}", report.display_name);
    println!("  Group ID    {}", report.group_id);
    println!("  Members     {}", report.member_count);
    println!(
        "  Threshold   {} of {}",
        report.capsule_threshold, report.member_count
    );
    for member in &report.members {
        println!("    {}  {}", member.display_name, member.identity_id);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureReport {
    schema_version: u16,
    kind: &'static str,
    group_id: String,
    proposal_id: Option<String>,
    member_id: String,
    output: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapsuleRecipientReport {
    display_name: String,
    identity_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapsuleReport {
    schema_version: u16,
    contract_id: String,
    group_id: String,
    proposal_id: String,
    content_digest: String,
    content_bytes: u64,
    content_kind: &'static str,
    capabilities: Vec<&'static str>,
    release_policy: &'static str,
    recipients: Vec<CapsuleRecipientReport>,
    recipient_count: usize,
    required_approvals: u16,
    approvals: usize,
    finalized: bool,
    envelope_bytes: usize,
}

impl CapsuleReport {
    fn from_proposal(
        proposal: &CapsuleProposal,
        finalized: bool,
        approvals: usize,
        envelope_bytes: usize,
    ) -> Result<Self, CliError> {
        let recipients = proposal
            .recipients()
            .into_iter()
            .map(|recipient| {
                Ok(CapsuleRecipientReport {
                    display_name: recipient.display_name().to_string(),
                    identity_id: recipient.identity_id().map_err(chain_error)?.to_base64(),
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        Ok(Self {
            schema_version: 2,
            contract_id: proposal.contract().contract_id().to_base64(),
            group_id: proposal
                .group()
                .group_id()
                .map_err(chain_error)?
                .to_base64(),
            proposal_id: encode(proposal.proposal_id()),
            content_digest: encode(proposal.content_digest()),
            content_bytes: proposal.content_size(),
            content_kind: match proposal.contract().content().kind() {
                ContractContentKind::ExactArtifact => "exactArtifact",
                ContractContentKind::SemanticPatch => "semanticPatch",
                _ => "unknown",
            },
            capabilities: capability_names(proposal),
            release_policy: match proposal.contract().release() {
                ReleasePolicy::DirectRecipients => "directRecipients",
                ReleasePolicy::Quorum(_) => "quorum",
                _ => "unknown",
            },
            recipient_count: recipients.len(),
            recipients,
            required_approvals: proposal.group().capsule_threshold(),
            approvals,
            finalized,
            envelope_bytes,
        })
    }

    fn from_envelope(envelope: &CapsuleEnvelope, envelope_bytes: usize) -> Result<Self, CliError> {
        Self::from_proposal(
            envelope.proposal(),
            true,
            envelope.approvals().len(),
            envelope_bytes,
        )
    }
}

fn print_capsule_report(report: &CapsuleReport) {
    println!("  Contract      {}", report.contract_id);
    println!("  Group ID      {}", report.group_id);
    println!("  Proposal ID   {}", report.proposal_id);
    println!(
        "  Content       {} · {} bytes",
        report.content_kind, report.content_bytes
    );
    println!("  Release       {}", report.release_policy);
    println!("  Capabilities  {}", report.capabilities.join(", "));
    println!(
        "  Approvals     {} of {} required",
        report.approvals, report.required_approvals
    );
    println!("  Recipients    {}", report.recipient_count);
    for recipient in &report.recipients {
        println!("    {}  {}", recipient.display_name, recipient.identity_id);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenReport {
    schema_version: u16,
    contract_id: String,
    group_id: String,
    proposal_id: String,
    recipient_id: String,
    content_bytes: usize,
    raw_artifact: bool,
    output: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChainDiffJson {
    schema_version: u16,
    contract_id: String,
    proposal_id: String,
    diff: super::DiffJson,
    directories: Vec<DirectoryDiffJson>,
}

impl ChainDiffJson {
    fn new(
        authorized: &AuthorizedFileSet,
        report: &DiffReport,
        directories: &[DirectoryDiffEntry],
    ) -> Self {
        Self {
            schema_version: 2,
            contract_id: authorized.contract_id.clone(),
            proposal_id: encode(authorized.proposal_digest.as_bytes()),
            diff: super::DiffJson::from_report(report),
            directories: directory_diff_json(directories),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryDiffJson {
    path: String,
    kind: &'static str,
}

fn directory_diff_json(directories: &[DirectoryDiffEntry]) -> Vec<DirectoryDiffJson> {
    directories
        .iter()
        .map(|directory| DirectoryDiffJson {
            path: directory.path.as_str().to_string(),
            kind: match directory.kind {
                DirectoryChangeKind::Create => "create",
                DirectoryChangeKind::Unchanged => "unchanged",
                _ => "unknown",
            },
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChainApplyJson {
    schema_version: u16,
    contract_id: String,
    proposal_id: String,
    status: &'static str,
    dry_run: bool,
    diff: super::DiffJson,
    directories: Vec<DirectoryDiffJson>,
    transaction_id: Option<String>,
    files_written: usize,
    directories_ensured: usize,
    bytes_written: u64,
    retained_backup: Option<String>,
}

impl ChainApplyJson {
    fn preview(
        authorized: &AuthorizedFileSet,
        diff: &DiffReport,
        directories: &[DirectoryDiffEntry],
    ) -> Self {
        Self::new(authorized, diff, directories, "preview", true, None)
    }

    fn cancelled(
        authorized: &AuthorizedFileSet,
        diff: &DiffReport,
        directories: &[DirectoryDiffEntry],
    ) -> Self {
        Self::new(authorized, diff, directories, "cancelled", false, None)
    }

    fn applied(
        authorized: &AuthorizedFileSet,
        diff: &DiffReport,
        directories: &[DirectoryDiffEntry],
        report: &ApplyReport,
    ) -> Self {
        Self::new(
            authorized,
            diff,
            directories,
            "applied",
            false,
            Some(report),
        )
    }

    fn new(
        authorized: &AuthorizedFileSet,
        diff: &DiffReport,
        directories: &[DirectoryDiffEntry],
        status: &'static str,
        dry_run: bool,
        report: Option<&ApplyReport>,
    ) -> Self {
        Self {
            schema_version: 2,
            contract_id: authorized.contract_id.clone(),
            proposal_id: encode(authorized.proposal_digest.as_bytes()),
            status,
            dry_run,
            diff: super::DiffJson::from_report(diff),
            directories: directory_diff_json(directories),
            transaction_id: report.map(|value| value.transaction_id.clone()),
            files_written: report.map_or(0, |value| value.files_written),
            directories_ensured: report.map_or(0, |value| value.directories_ensured),
            bytes_written: report.map_or(0, |value| value.bytes_written),
            retained_backup: report
                .and_then(|value| value.retained_backup.as_ref())
                .map(|value| value.display().to_string()),
        }
    }
}

fn capability_names(proposal: &CapsuleProposal) -> Vec<&'static str> {
    let capabilities = proposal.contract().capabilities();
    [
        (Capability::InspectMetadata, "inspectMetadata"),
        (Capability::Decrypt, "decrypt"),
        (Capability::Reconstruct, "reconstruct"),
        (Capability::Diff, "diff"),
        (Capability::Apply, "apply"),
        (Capability::ApplySemanticPatch, "applySemanticPatch"),
    ]
    .into_iter()
    .filter_map(|(capability, name)| capabilities.contains(capability).then_some(name))
    .collect()
}

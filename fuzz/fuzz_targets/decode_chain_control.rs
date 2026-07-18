#![no_main]

use libfuzzer_sys::fuzz_target;
use rebyte_chain::{
    AccessContract, CapsuleApproval, CapsuleProposal, ChainLimits, EncryptedIdentityDocument,
    GroupAcceptance, GroupCertificate, GroupProposal, IdentityPublicDocument, ReleaseGrant,
    ReleaseRequest,
};

fuzz_target!(|data: &[u8]| {
    let _ = IdentityPublicDocument::from_json(data);
    let _ = EncryptedIdentityDocument::from_json(data);
    let _ = GroupProposal::from_json(data);
    let _ = GroupAcceptance::from_json(data);
    let _ = GroupCertificate::from_json(data);
    let _ = CapsuleApproval::from_json(data);
    let _ = ReleaseRequest::from_json(data);
    let _ = ReleaseGrant::from_json(data);
    let _ = AccessContract::from_bytes(data);
    let _ = CapsuleProposal::from_bytes(data, &ChainLimits::STANDARD);
});

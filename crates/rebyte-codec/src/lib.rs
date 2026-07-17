// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical, bounded binary and textual codec for RAP v1.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod decode;
mod encode;
mod error;
mod model;
mod token;

pub use decode::{decode_capsule, decode_header};
pub use encode::{encode_capsule, encode_header, encode_manifest};
pub use error::CodecError;
pub use model::{DecodedCapsule, SignatureBytes};
pub use token::{decode_token, encode_token};

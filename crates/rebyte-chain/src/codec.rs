// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::redundant_pub_crate)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::ChainError;

pub(crate) fn encode_base64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn decode_base64(value: &str) -> Result<Vec<u8>, ChainError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(ChainError::InvalidEncoding);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| ChainError::InvalidEncoding)?;
    if encode_base64(&decoded) != value {
        return Err(ChainError::InvalidEncoding);
    }
    Ok(decoded)
}

pub(crate) fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], ChainError> {
    decode_base64(value)?
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::InvalidEncoding)
}

pub(crate) fn domain_hash(context: &'static str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_bytes_u16(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ChainError> {
    let length = u16::try_from(value.len()).map_err(|_| ChainError::LengthOverflow)?;
    put_u16(output, length);
    output.extend_from_slice(value);
    Ok(())
}

pub(crate) fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ChainError> {
    let length = u32::try_from(value.len()).map_err(|_| ChainError::LengthOverflow)?;
    put_u32(output, length);
    output.extend_from_slice(value);
    Ok(())
}

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ChainError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ChainError::UnexpectedEof)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ChainError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ChainError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ChainError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn bytes_u32(&mut self, maximum: usize) -> Result<Vec<u8>, ChainError> {
        let length = usize::try_from(self.u32()?).map_err(|_| ChainError::LengthOverflow)?;
        if length > maximum {
            return Err(ChainError::LimitExceeded);
        }
        Ok(self.take(length)?.to_vec())
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], ChainError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ChainError::LengthOverflow)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(ChainError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) const fn finish(self) -> Result<(), ChainError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ChainError::NonCanonicalEnvelope)
        }
    }
}

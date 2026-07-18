// Copyright (c) 2026 Pedro Martins (pedro5g)
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Shamir sharing for the 256-bit Chain content-encryption key.

#![allow(clippy::redundant_pub_crate)]

use zeroize::Zeroizing;

use crate::ChainError;

pub(super) const SECRET_BYTES: usize = 32;
pub(super) const SHARE_BYTES: usize = SECRET_BYTES + 1;
const MAX_SHARES: usize = 64;

pub(super) fn split_secret(
    secret: &[u8; SECRET_BYTES],
    share_count: u8,
    threshold: u8,
) -> Result<Vec<Zeroizing<[u8; SHARE_BYTES]>>, ChainError> {
    validate_parameters(usize::from(share_count), usize::from(threshold))?;
    let coefficient_count = usize::from(threshold.saturating_sub(1))
        .checked_mul(SECRET_BYTES)
        .ok_or(ChainError::LengthOverflow)?;
    let mut coefficients = Zeroizing::new(vec![0_u8; coefficient_count]);
    getrandom::fill(coefficients.as_mut()).map_err(|_| ChainError::EntropyUnavailable)?;
    split_with_coefficients(secret, share_count, threshold, &coefficients)
}

pub(super) fn combine_shares(
    shares: &[[u8; SHARE_BYTES]],
    threshold: u8,
) -> Result<Zeroizing<[u8; SECRET_BYTES]>, ChainError> {
    validate_parameters(shares.len(), usize::from(threshold))?;
    if shares.len() != usize::from(threshold) {
        return Err(ChainError::InvalidShare);
    }
    let mut seen = [false; 256];
    for share in shares {
        let x = usize::from(share[0]);
        if x == 0 || seen[x] {
            return Err(ChainError::InvalidShare);
        }
        seen[x] = true;
    }
    let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
    for byte_index in 0..SECRET_BYTES {
        let mut value = 0_u8;
        for (index, share) in shares.iter().enumerate() {
            let x_i = share[0];
            let mut numerator = 1_u8;
            let mut denominator = 1_u8;
            for (other_index, other) in shares.iter().enumerate() {
                if index != other_index {
                    numerator = gf_mul(numerator, other[0]);
                    denominator = gf_mul(denominator, other[0] ^ x_i);
                }
            }
            let coefficient = gf_mul(numerator, gf_inverse(denominator)?);
            value ^= gf_mul(share[byte_index + 1], coefficient);
        }
        secret[byte_index] = value;
    }
    Ok(secret)
}

fn split_with_coefficients(
    secret: &[u8; SECRET_BYTES],
    share_count: u8,
    threshold: u8,
    coefficients: &[u8],
) -> Result<Vec<Zeroizing<[u8; SHARE_BYTES]>>, ChainError> {
    validate_parameters(usize::from(share_count), usize::from(threshold))?;
    let expected = usize::from(threshold.saturating_sub(1))
        .checked_mul(SECRET_BYTES)
        .ok_or(ChainError::LengthOverflow)?;
    if coefficients.len() != expected {
        return Err(ChainError::InvalidShare);
    }
    let mut shares = Vec::with_capacity(usize::from(share_count));
    for x in 1..=share_count {
        let mut share = Zeroizing::new([0_u8; SHARE_BYTES]);
        share[0] = x;
        for (byte_index, secret_byte) in secret.iter().copied().enumerate() {
            let start = byte_index
                .checked_mul(usize::from(threshold.saturating_sub(1)))
                .ok_or(ChainError::LengthOverflow)?;
            let end = start
                .checked_add(usize::from(threshold.saturating_sub(1)))
                .ok_or(ChainError::LengthOverflow)?;
            let polynomial = coefficients
                .get(start..end)
                .ok_or(ChainError::InvalidShare)?;
            share[byte_index + 1] = evaluate_polynomial(secret_byte, polynomial, x);
        }
        shares.push(share);
    }
    Ok(shares)
}

fn evaluate_polynomial(constant: u8, coefficients: &[u8], x: u8) -> u8 {
    let mut value = 0_u8;
    for coefficient in coefficients.iter().rev().copied() {
        value = gf_mul(value, x) ^ coefficient;
    }
    gf_mul(value, x) ^ constant
}

const fn validate_parameters(share_count: usize, threshold: usize) -> Result<(), ChainError> {
    if share_count == 0 || share_count > MAX_SHARES || threshold == 0 || threshold > share_count {
        Err(ChainError::InvalidThreshold)
    } else {
        Ok(())
    }
}

fn gf_inverse(value: u8) -> Result<u8, ChainError> {
    if value == 0 {
        return Err(ChainError::InvalidShare);
    }
    let mut result = 1_u8;
    let mut base = value;
    let mut exponent = 254_u8;
    for _ in 0..8 {
        result = gf_mul(result, select_u8(1, base, exponent & 1));
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    Ok(result)
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0_u8;
    for _ in 0..8 {
        product ^= left & 0_u8.wrapping_sub(right & 1);
        let high_bit = left >> 7;
        left = (left << 1) ^ (0x1b & 0_u8.wrapping_sub(high_bit));
        right >>= 1;
    }
    product
}

const fn select_u8(if_zero: u8, if_one: u8, selector: u8) -> u8 {
    let mask = 0_u8.wrapping_sub(selector & 1);
    (if_zero & !mask) | (if_one & mask)
}

#[cfg(test)]
mod tests {
    use super::{SECRET_BYTES, combine_shares, split_with_coefficients};

    #[test]
    fn every_threshold_subset_recovers_the_exact_secret() -> Result<(), Box<dyn std::error::Error>>
    {
        let secret = [0xa5; SECRET_BYTES];
        let coefficients = vec![0x35; SECRET_BYTES * 2];
        let shares = split_with_coefficients(&secret, 5, 3, &coefficients)?;
        for first in 0..3 {
            for second in (first + 1)..4 {
                for third in (second + 1)..5 {
                    let selected = [*shares[first], *shares[second], *shares[third]];
                    assert_eq!(combine_shares(&selected, 3)?.as_ref(), &secret);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn rejects_duplicate_zero_and_insufficient_shares() -> Result<(), Box<dyn std::error::Error>> {
        let secret = [0x55; SECRET_BYTES];
        let coefficients = vec![0x73; SECRET_BYTES];
        let shares = split_with_coefficients(&secret, 3, 2, &coefficients)?;
        assert!(combine_shares(&[*shares[0]], 2).is_err());
        assert!(combine_shares(&[*shares[0], *shares[0]], 2).is_err());
        let mut zero = *shares[1];
        zero[0] = 0;
        assert!(combine_shares(&[*shares[0], zero], 2).is_err());
        Ok(())
    }
}

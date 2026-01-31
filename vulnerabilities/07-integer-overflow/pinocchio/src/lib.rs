//! # Integer Overflow - Pinocchio Implementation
//!
//! This module demonstrates integer overflow/underflow vulnerabilities and
//! their fixes using the Pinocchio framework.
//!
//! ## Key Points
//!
//! 1. Rust in release mode wraps on overflow (no panic)
//! 2. Solana programs run in release mode
//! 3. All arithmetic must use checked operations
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: direct arithmetic operators
//! - `secure.rs` - SECURE: checked arithmetic methods

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod vulnerable;
pub mod secure;

pinocchio::declare_id!("Int7777777777777777777777777777777777777777");

/// Vault data layout
/// 
/// | Offset | Size | Field            |
/// |--------|------|------------------|
/// | 0      | 8    | discriminator    |
/// | 8      | 32   | owner            |
/// | 40     | 8    | balance          |
/// | 48     | 8    | total_deposited  |
/// | 56     | 8    | total_withdrawn  |
/// | 64     | 1    | bump             |
pub const VAULT_SIZE: usize = 8 + 32 + 8 + 8 + 8 + 1;
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"INTVAULT";

pub mod offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const OWNER: usize = 8;
    pub const BALANCE: usize = 40;
    pub const TOTAL_DEPOSITED: usize = 48;
    pub const TOTAL_WITHDRAWN: usize = 56;
    pub const BUMP: usize = 64;
}

/// Helper functions
#[inline]
pub fn read_pubkey(data: &[u8], offset: usize) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[offset..offset + 32]);
    Pubkey::new_from_array(bytes)
}

#[inline]
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

#[inline]
pub fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
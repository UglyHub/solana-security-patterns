//! # Reinitialization - Pinocchio Implementation
//!
//! This module demonstrates the reinitialization vulnerability and its fix
//! using the Pinocchio framework.
//!
//! ## Key Difference from Anchor
//!
//! In Pinocchio, there are NO automatic initialization protections.
//! You must manually:
//! 1. Check if account is already initialized before writing
//! 2. Set an initialization flag after first initialization
//! 3. Reject any attempts to reinitialize
//!
//! ## Methods to Detect Initialization
//!
//! 1. **Discriminator check**: If discriminator is set, account is initialized
//! 2. **Explicit flag**: Check `is_initialized` byte
//! 3. **Non-zero authority**: If authority != default, account is initialized
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: no initialization check
//! - `secure.rs` - SECURE: proper initialization check

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod vulnerable;
pub mod secure;

pinocchio::declare_id!("ReIn555555555555555555555555555555555555555");

/// Vault account data layout
/// 
/// | Offset | Size | Field          |
/// |--------|------|----------------|
/// | 0      | 8    | discriminator  |
/// | 8      | 1    | is_initialized |
/// | 9      | 32   | authority      |
/// | 41     | 8    | balance        |
/// | 49     | 1    | bump           |
pub const VAULT_SIZE: usize = 8 + 1 + 32 + 8 + 1;

/// Vault discriminator
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"VAULT_05";

/// Offsets for vault fields
pub mod offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const IS_INITIALIZED: usize = 8;
    pub const AUTHORITY: usize = 9;
    pub const BALANCE: usize = 41;
    pub const BUMP: usize = 49;
}

/// Helper: Read Pubkey from data
#[inline]
pub fn read_pubkey(data: &[u8], offset: usize) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[offset..offset + 32]);
    Pubkey::new_from_array(bytes)
}

/// Helper: Read u64 from data
#[inline]
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Helper: Write u64 to data
#[inline]
pub fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Default/zero pubkey for comparison
pub const DEFAULT_PUBKEY: Pubkey = Pubkey::new_from_array([0u8; 32]);
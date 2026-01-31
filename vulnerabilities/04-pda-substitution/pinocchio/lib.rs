//! # PDA Substitution - Pinocchio Implementation
//!
//! This module demonstrates the PDA substitution vulnerability and its fix
//! using the Pinocchio framework.
//!
//! ## Key Difference from Anchor
//!
//! In Pinocchio, there are NO automatic PDA verification constraints.
//! You must manually:
//! 1. Derive the expected PDA using `create_program_address`
//! 2. Compare the expected PDA to the actual account address
//! 3. Reject if they don't match
//!
//! ## The Critical Check
//!
//! ```rust
//! let expected_pda = Pubkey::create_program_address(
//!     &[b"vault", authority.key().as_ref(), &[bump]],
//!     &program_id
//! )?;
//!
//! if vault.key() != &expected_pda {
//!     return Err(ProgramError::InvalidSeeds);
//! }
//! ```
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: no PDA verification
//! - `secure.rs` - SECURE: manual PDA verification

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod vulnerable;
pub mod secure;

pinocchio::declare_id!("PDA4444444444444444444444444444444444444444");

/// Vault account data layout
/// 
/// | Offset | Size | Field         |
/// |--------|------|---------------|
/// | 0      | 8    | discriminator |
/// | 8      | 32   | authority     |
/// | 40     | 8    | balance       |
/// | 48     | 1    | bump          |
pub const VAULT_SIZE: usize = 8 + 32 + 8 + 1;
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"VAULTPDA";

/// Offsets for vault fields
pub mod offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const AUTHORITY: usize = 8;
    pub const BALANCE: usize = 40;
    pub const BUMP: usize = 48;
}

/// Seed prefix for vault PDAs
pub const VAULT_SEED: &[u8] = b"vault";

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
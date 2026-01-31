//! # Missing Signer Check - Pinocchio Implementation
//!
//! This module demonstrates the missing signer check vulnerability and its fix
//! using the Pinocchio framework.
//!
//! ## Key Difference from Anchor
//! 
//! In Pinocchio, there is NO type-level enforcement of signers. You MUST
//! manually call `is_signer()` on any account that should authorize an action.
//! Forgetting this check is a critical vulnerability!
//!
//! ## Pinocchio Philosophy
//! 
//! Pinocchio is a zero-dependency, low-level framework that prioritizes:
//! - Minimal compute unit usage
//! - Small binary size
//! - Maximum developer control
//! 
//! The tradeoff: YOU are responsible for all security checks.
//!
//! ## Files
//! 
//! - `vulnerable.rs` - INSECURE implementation without is_signer() check
//! - `secure.rs` - SECURE implementation with proper is_signer() check

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod vulnerable;
pub mod secure;

// Program ID - replace with actual deployed address
pinocchio::declare_id!("Sig1111111111111111111111111111111111111111");

/// Vault account data layout
/// 
/// In Pinocchio, we manually define the byte layout:
/// 
/// | Offset | Size | Field        | Description                    |
/// |--------|------|--------------|--------------------------------|
/// | 0      | 8    | discriminator| Unique identifier for Vault    |
/// | 8      | 32   | authority    | Pubkey that can withdraw       |
/// | 40     | 8    | balance      | Current balance in lamports    |
/// | 48     | 1    | bump         | PDA bump seed                  |
/// 
/// Total: 49 bytes
pub const VAULT_SIZE: usize = 8 + 32 + 8 + 1;

/// Unique identifier for Vault accounts
/// 
/// This discriminator prevents type confusion attacks where an attacker
/// passes a different account type that has similar data layout.
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"VAULT001";

/// Byte offsets for reading/writing vault data
pub mod offsets {
    /// Discriminator: bytes 0-8
    pub const DISCRIMINATOR: usize = 0;
    /// Authority pubkey: bytes 8-40
    pub const AUTHORITY: usize = 8;
    /// Balance: bytes 40-48
    pub const BALANCE: usize = 40;
    /// Bump: byte 48
    pub const BUMP: usize = 48;
}

/// Helper function: Read a Pubkey from account data
/// 
/// # Arguments
/// * `data` - The account data bytes
/// * `offset` - Starting position to read from
/// 
/// # Returns
/// * `Pubkey` - The 32-byte public key
#[inline]
pub fn read_pubkey(data: &[u8], offset: usize) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[offset..offset + 32]);
    Pubkey::new_from_array(bytes)
}

/// Helper function: Read a u64 from account data (little-endian)
/// 
/// # Arguments
/// * `data` - The account data bytes
/// * `offset` - Starting position to read from
/// 
/// # Returns
/// * `u64` - The 8-byte unsigned integer
#[inline]
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Helper function: Write a u64 to account data (little-endian)
/// 
/// # Arguments
/// * `data` - The mutable account data bytes
/// * `offset` - Starting position to write to
/// * `value` - The value to write
#[inline]
pub fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Helper function: Write a Pubkey to account data
/// 
/// # Arguments
/// * `data` - The mutable account data bytes
/// * `offset` - Starting position to write to
/// * `pubkey` - The pubkey to write
#[inline]
pub fn write_pubkey(data: &mut [u8], offset: usize, pubkey: &Pubkey) {
    data[offset..offset + 32].copy_from_slice(pubkey.as_ref());
}
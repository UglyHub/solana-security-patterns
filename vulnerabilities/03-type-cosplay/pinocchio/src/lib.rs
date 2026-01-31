//! # Type Cosplay - Pinocchio Implementation
//!
//! This module demonstrates the type cosplay vulnerability and its fix
//! using the Pinocchio framework.
//!
//! ## Key Difference from Anchor
//!
//! In Pinocchio, there are NO automatic discriminators. You must:
//! 1. Define your own discriminator constants
//! 2. Write discriminator when creating accounts
//! 3. Check discriminator before reading account data
//!
//! Forgetting step 3 makes your program vulnerable to type cosplay!
//!
//! ## Account Types in This Example
//!
//! We have two account types with IDENTICAL layouts:
//! - Vault: [8 discriminator][32 authority][8 balance][1 is_locked]
//! - UserProfile: [8 discriminator][32 owner][8 points][1 is_premium]
//!
//! Without discriminator checks, these can be confused!
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: skips discriminator check
//! - `secure.rs` - SECURE: verifies discriminator first

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod vulnerable;
pub mod secure;

pinocchio::declare_id!("Typ3333333333333333333333333333333333333333");

/// Vault discriminator - unique identifier for Vault accounts
/// 
/// In a real program, you might use a hash, but for clarity we use ASCII.
/// The important thing is that each account type has a DIFFERENT discriminator.
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"VAULT_01";

/// UserProfile discriminator - unique identifier for UserProfile accounts
/// 
/// DIFFERENT from Vault discriminator!
pub const PROFILE_DISCRIMINATOR: [u8; 8] = *b"PROFILE1";

/// Common offsets (same for both types - this is what enables the attack!)
pub mod offsets {
    /// Discriminator: bytes 0-8
    pub const DISCRIMINATOR: usize = 0;
    /// Authority/Owner: bytes 8-40
    pub const AUTHORITY: usize = 8;
    /// Balance/Points: bytes 40-48
    pub const BALANCE: usize = 40;
    /// IsLocked/IsPremium: byte 48
    pub const FLAGS: usize = 48;
}

/// Account size (same for both types)
pub const ACCOUNT_SIZE: usize = 8 + 32 + 8 + 1;

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
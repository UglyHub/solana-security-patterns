//! # Arbitrary CPI - Pinocchio Implementation
//!
//! This module demonstrates the arbitrary CPI vulnerability and its fix
//! using the Pinocchio framework.
//!
//! ## Key Difference from Anchor
//!
//! In Pinocchio, there is NO automatic program ID verification.
//! You must manually verify every CPI target before invocation:
//!
//! ```rust
//! if program.key() != &EXPECTED_PROGRAM_ID {
//!     return Err(ProgramError::IncorrectProgramId);
//! }
//! ```
//!
//! ## The Critical Check
//!
//! Before ANY CPI:
//! 1. Compare program key to expected constant
//! 2. Optionally check `is_executable()`
//! 3. Only then invoke
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: no program ID verification
//! - `secure.rs` - SECURE: proper program ID verification

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod vulnerable;
pub mod secure;

pinocchio::declare_id!("CPI6666666666666666666666666666666666666666");

/// Well-known program IDs
/// 
/// In production, import these from the actual crates.
/// Here we define them for demonstration.
pub mod program_ids {
    use super::Pubkey;
    
    /// SPL Token Program ID
    /// Real value: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
    pub const TOKEN_PROGRAM: Pubkey = Pubkey::new_from_array([
        0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
        0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
        0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
        0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
    ]);
    
    /// System Program ID
    pub const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);
}

/// Vault account data layout
pub const VAULT_SIZE: usize = 8 + 32 + 32 + 8 + 8 + 1;
pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"CPIVAULT";

pub mod offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const OWNER: usize = 8;
    pub const MINT: usize = 40;
    pub const BALANCE: usize = 72;
    pub const TOTAL_WITHDRAWN: usize = 80;
    pub const BUMP: usize = 88;
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
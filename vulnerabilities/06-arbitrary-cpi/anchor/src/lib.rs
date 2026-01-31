//! # Arbitrary CPI - Anchor Implementation
//!
//! This module demonstrates the arbitrary CPI vulnerability and its fix
//! using the Anchor framework.
//!
//! ## The Vulnerability
//!
//! Arbitrary CPI occurs when a program invokes another program without
//! verifying the target's identity. Attackers can substitute malicious
//! programs that mimic expected behavior but act differently.
//!
//! ## Anchor's Solution
//!
//! Anchor provides `Program<'info, T>` which automatically verifies:
//! 1. The account's key matches `T::id()`
//! 2. The account is executable
//!
//! Using `AccountInfo` or `UncheckedAccount` for program accounts bypasses
//! these critical checks!
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: uses AccountInfo for program accounts
//! - `secure.rs` - SECURE: uses Program<T> for verified CPIs

use anchor_lang::prelude::*;

pub mod vulnerable;
pub mod secure;

declare_id!("CPI6666666666666666666666666666666666666666");

/// User vault for storing token balances
#[account]
pub struct UserVault {
    /// Owner of this vault
    pub owner: Pubkey,
    /// Token mint this vault holds
    pub mint: Pubkey,
    /// Internal balance tracking (may differ from actual tokens)
    pub balance: u64,
    /// Total withdrawn
    pub total_withdrawn: u64,
    /// Bump for PDA
    pub bump: u8,
}

impl UserVault {
    /// 8 + 32 + 32 + 8 + 8 + 1 = 89
    pub const SIZE: usize = 8 + 32 + 32 + 8 + 8 + 1;
}

/// Protocol configuration
#[account]
pub struct ProtocolConfig {
    /// Admin authority
    pub admin: Pubkey,
    /// Fee recipient
    pub fee_recipient: Pubkey,
    /// Fee in basis points
    pub fee_bps: u16,
    /// Bump
    pub bump: u8,
}

impl ProtocolConfig {
    pub const SIZE: usize = 8 + 32 + 32 + 2 + 1;
}

/// Custom error codes
#[error_code]
pub enum CPIError {
    #[msg("Invalid program ID for CPI target")]
    InvalidProgramId,
    
    #[msg("Program account is not executable")]
    ProgramNotExecutable,
    
    #[msg("Invalid authority")]
    InvalidAuthority,
    
    #[msg("Insufficient balance")]
    InsufficientBalance,
    
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
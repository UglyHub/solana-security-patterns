//! # Missing Signer Check - Anchor Implementation
//! 
//! This module demonstrates the missing signer check vulnerability and its fix
//! using the Anchor framework.
//!
//! ## The Vulnerability
//! 
//! In Solana, just because an account's pubkey is passed to an instruction doesn't
//! mean the owner of that account authorized the action. The `is_signer` flag must
//! be explicitly checked.
//!
//! ## Anchor's Solution
//! 
//! Anchor provides the `Signer<'info>` type which automatically verifies that an
//! account has signed the transaction. Using `UncheckedAccount<'info>` instead
//! bypasses this critical security check.
//!
//! ## Files
//! 
//! - `vulnerable.rs` - INSECURE implementation using UncheckedAccount
//! - `secure.rs` - SECURE implementation using Signer

use anchor_lang::prelude::*;

pub mod vulnerable;
pub mod secure;

declare_id!("Sig1111111111111111111111111111111111111111");

/// Vault account structure that holds user funds
/// 
/// ## Fields
/// - `authority`: The pubkey that can withdraw from this vault
/// - `balance`: Current balance in lamports
/// - `bump`: PDA bump seed (if used as PDA)
#[account]
pub struct Vault {
    /// The authority who can withdraw from this vault
    pub authority: Pubkey,
    /// Total lamports stored in this vault
    pub balance: u64,
    /// Bump seed for PDA derivation
    pub bump: u8,
}

impl Vault {
    /// Size of Vault account in bytes
    /// 8 (discriminator) + 32 (authority) + 8 (balance) + 1 (bump) = 49 bytes
    pub const SIZE: usize = 8 + 32 + 8 + 1;
}

/// Custom error codes for the vault program
#[error_code]
pub enum VaultError {
    #[msg("The provided authority does not match the vault's authority")]
    InvalidAuthority,
    
    #[msg("Insufficient funds in the vault for this withdrawal")]
    InsufficientFunds,
    
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
}
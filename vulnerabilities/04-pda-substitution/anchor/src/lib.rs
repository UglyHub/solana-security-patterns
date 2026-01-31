//! # PDA Substitution - Anchor Implementation
//!
//! This module demonstrates the PDA substitution vulnerability and its fix
//! using the Anchor framework.
//!
//! ## The Vulnerability
//!
//! PDA substitution occurs when a program accepts any PDA without verifying
//! it was derived from the expected seeds. Attackers can create PDAs with
//! different seeds and substitute them for legitimate accounts.
//!
//! ## Anchor's Solution
//!
//! Anchor provides the `seeds` and `bump` constraints that automatically
//! verify a PDA was derived from specific seeds:
//!
//! ```rust
//! #[account(
//!     seeds = [b"vault", user.key().as_ref()],
//!     bump = vault.bump
//! )]
//! pub vault: Account<'info, Vault>,
//! ```
//!
//! This ensures the vault address equals `derive(["vault", user], program_id)`.
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: accepts any vault without seed verification
//! - `secure.rs` - SECURE: verifies PDA seeds with constraints

use anchor_lang::prelude::*;

pub mod vulnerable;
pub mod secure;

declare_id!("PDA4444444444444444444444444444444444444444");

/// Vault PDA account
/// 
/// Each user should have exactly ONE vault, derived from:
/// `seeds = ["vault", user_pubkey]`
/// 
/// The bump is stored to save compute on verification.
#[account]
pub struct Vault {
    /// The authority who can withdraw (should match PDA derivation)
    pub authority: Pubkey,
    /// Current balance in lamports
    pub balance: u64,
    /// PDA bump seed for efficient verification
    pub bump: u8,
}

impl Vault {
    /// 8 (discriminator) + 32 (authority) + 8 (balance) + 1 (bump) = 49
    pub const SIZE: usize = 8 + 32 + 8 + 1;
    
    /// Seed prefix for vault PDAs
    pub const SEED_PREFIX: &'static [u8] = b"vault";
}

/// Global configuration account (singleton PDA)
/// 
/// Derived from: `seeds = ["config"]`
#[account]
pub struct Config {
    /// Admin who can update config
    pub admin: Pubkey,
    /// Protocol fee in basis points
    pub fee_bps: u16,
    /// Whether protocol is paused
    pub paused: bool,
    /// PDA bump
    pub bump: u8,
}

impl Config {
    /// 8 + 32 + 2 + 1 + 1 = 44
    pub const SIZE: usize = 8 + 32 + 2 + 1 + 1;
    
    pub const SEED_PREFIX: &'static [u8] = b"config";
}

/// Custom error codes
#[error_code]
pub enum PDAError {
    #[msg("Invalid PDA - seeds do not match expected derivation")]
    InvalidPDA,
    
    #[msg("Invalid authority for this vault")]
    InvalidAuthority,
    
    #[msg("Insufficient balance in vault")]
    InsufficientBalance,
    
    #[msg("Protocol is paused")]
    ProtocolPaused,
    
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
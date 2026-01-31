//! # Reinitialization - Anchor Implementation
//!
//! This module demonstrates the reinitialization vulnerability and its fix
//! using the Anchor framework.
//!
//! ## The Vulnerability
//!
//! Reinitialization occurs when an already-initialized account can be
//! initialized again, allowing attackers to overwrite critical data like
//! authorities or balances.
//!
//! ## Anchor's Solution
//!
//! Anchor provides the `init` constraint which:
//! 1. Creates the account via System Program
//! 2. Allocates space
//! 3. Sets the owner to the program
//! 4. Fails if account already exists
//!
//! The dangerous alternative is `init_if_needed` which allows re-initialization.
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: allows reinitialization
//! - `secure.rs` - SECURE: prevents reinitialization

use anchor_lang::prelude::*;

pub mod vulnerable;
pub mod secure;

declare_id!("ReIn555555555555555555555555555555555555555");

/// Vault account that can be reinitialized (vulnerable version)
/// 
/// Note: No `is_initialized` flag - relies on program logic to prevent re-init
#[account]
pub struct Vault {
    /// Authority who controls this vault
    pub authority: Pubkey,
    /// Current balance tracked by the program
    pub balance: u64,
    /// Bump seed for PDA (if applicable)
    pub bump: u8,
}

impl Vault {
    /// 8 (discriminator) + 32 (authority) + 8 (balance) + 1 (bump) = 49
    pub const SIZE: usize = 8 + 32 + 8 + 1;
}

/// Vault with explicit initialization flag (secure version)
#[account]
pub struct SecureVault {
    /// Whether this vault has been initialized
    pub is_initialized: bool,
    /// Authority who controls this vault
    pub authority: Pubkey,
    /// Current balance tracked by the program
    pub balance: u64,
    /// Bump seed for PDA
    pub bump: u8,
}

impl SecureVault {
    /// 8 + 1 (is_initialized) + 32 + 8 + 1 = 50
    pub const SIZE: usize = 8 + 1 + 32 + 8 + 1;
}

/// Configuration account (singleton)
#[account]
pub struct Config {
    /// Admin who can update config
    pub admin: Pubkey,
    /// Protocol fee in basis points
    pub fee_bps: u16,
    /// Whether protocol is paused
    pub is_paused: bool,
    /// Initialization flag
    pub is_initialized: bool,
    /// Bump for PDA
    pub bump: u8,
}

impl Config {
    /// 8 + 32 + 2 + 1 + 1 + 1 = 45
    pub const SIZE: usize = 8 + 32 + 2 + 1 + 1 + 1;
}

/// Custom error codes
#[error_code]
pub enum ReinitError {
    #[msg("Account is already initialized")]
    AlreadyInitialized,
    
    #[msg("Account is not initialized")]
    NotInitialized,
    
    #[msg("Invalid authority")]
    InvalidAuthority,
    
    #[msg("Insufficient balance")]
    InsufficientBalance,
    
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
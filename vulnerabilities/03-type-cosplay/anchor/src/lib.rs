//! # Type Cosplay - Anchor Implementation
//!
//! This module demonstrates the type cosplay vulnerability and its fix
//! using the Anchor framework.
//!
//! ## The Vulnerability
//!
//! Type cosplay occurs when an attacker passes an account of one type where
//! a different type is expected. If the data layouts are similar, the program
//! may misinterpret the data.
//!
//! ## Anchor's Solution
//!
//! Anchor's `#[account]` macro automatically generates an 8-byte discriminator
//! (hash of the type name) for each account type. When you use `Account<'info, T>`,
//! Anchor verifies this discriminator matches before allowing access.
//!
//! ## The Dangerous Pattern
//!
//! Using `UncheckedAccount` and manually deserializing bypasses discriminator
//! checks, making your program vulnerable to type cosplay attacks.
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE implementation that skips discriminator check
//! - `secure.rs` - SECURE implementation using Account<T>

use anchor_lang::prelude::*;

pub mod vulnerable;
pub mod secure;

declare_id!("Typ3333333333333333333333333333333333333333");

/// Vault account - stores protocol funds
/// 
/// ## Layout
/// | Offset | Size | Field      |
/// |--------|------|------------|
/// | 0      | 8    | discriminator (auto) |
/// | 8      | 32   | authority  |
/// | 40     | 8    | balance    |
/// | 48     | 1    | is_locked  |
/// 
/// The discriminator is SHA256("account:Vault")[0..8]
#[account]
pub struct Vault {
    /// Authority who can withdraw from this vault
    pub authority: Pubkey,
    /// Current balance in lamports
    pub balance: u64,
    /// Whether vault is locked
    pub is_locked: bool,
}

impl Vault {
    /// 8 (discriminator) + 32 (authority) + 8 (balance) + 1 (is_locked) = 49
    pub const SIZE: usize = 8 + 32 + 8 + 1;
}

/// UserProfile account - stores user metadata
/// 
/// ## Layout (SIMILAR TO VAULT!)
/// | Offset | Size | Field      |
/// |--------|------|------------|
/// | 0      | 8    | discriminator (auto) |
/// | 8      | 32   | owner      | ← SAME POSITION as Vault.authority!
/// | 40     | 8    | points     | ← SAME POSITION as Vault.balance!
/// | 48     | 1    | is_premium |
/// 
/// The discriminator is SHA256("account:UserProfile")[0..8]
/// 
/// ⚠️ WARNING: This has the SAME data layout as Vault!
/// Without discriminator checks, these types can be confused.
#[account]
pub struct UserProfile {
    /// Owner of this profile (user controls this!)
    pub owner: Pubkey,
    /// Points earned (user-controlled value)
    pub points: u64,
    /// Premium status
    pub is_premium: bool,
}

impl UserProfile {
    /// 8 + 32 + 8 + 1 = 49 (SAME SIZE as Vault!)
    pub const SIZE: usize = 8 + 32 + 8 + 1;
}

/// Custom error codes
#[error_code]
pub enum TypeCosplayError {
    #[msg("Invalid account type - discriminator mismatch")]
    InvalidAccountType,
    
    #[msg("Invalid authority for this vault")]
    InvalidAuthority,
    
    #[msg("Vault is locked")]
    VaultLocked,
    
    #[msg("Insufficient balance")]
    InsufficientBalance,
    
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
//! # Integer Overflow - Anchor Implementation
//!
//! This module demonstrates integer overflow/underflow vulnerabilities and
//! their fixes using the Anchor framework.
//!
//! ## The Vulnerability
//!
//! Integer overflow occurs when arithmetic results exceed the type's range,
//! causing values to wrap around. In Solana (release mode), this happens
//! silently without any error!
//!
//! ## Examples
//!
//! ```rust
//! // u8 overflow: 255 + 1 = 0 (not 256!)
//! // u64 underflow: 0 - 1 = 18,446,744,073,709,551,615 (not -1!)
//! ```
//!
//! ## The Fix
//!
//! Use Rust's checked arithmetic methods:
//! - `checked_add()` - Returns None on overflow
//! - `checked_sub()` - Returns None on underflow
//! - `checked_mul()` - Returns None on overflow
//! - `checked_div()` - Returns None on division by zero
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE: uses direct arithmetic operators
//! - `secure.rs` - SECURE: uses checked arithmetic methods

use anchor_lang::prelude::*;

pub mod vulnerable;
pub mod secure;

declare_id!("Int7777777777777777777777777777777777777777");

/// Token vault for deposits and withdrawals
#[account]
pub struct TokenVault {
    /// Owner of the vault
    pub owner: Pubkey,
    /// Current balance
    pub balance: u64,
    /// Total deposited all-time
    pub total_deposited: u64,
    /// Total withdrawn all-time
    pub total_withdrawn: u64,
    /// Bump for PDA
    pub bump: u8,
}

impl TokenVault {
    /// 8 + 32 + 8 + 8 + 8 + 1 = 65
    pub const SIZE: usize = 8 + 32 + 8 + 8 + 8 + 1;
}

/// Staking account with rewards calculation
#[account]
pub struct StakingAccount {
    /// Staker
    pub owner: Pubkey,
    /// Amount staked
    pub staked_amount: u64,
    /// Timestamp when staked
    pub stake_timestamp: i64,
    /// Accumulated rewards
    pub rewards: u64,
    /// Bump
    pub bump: u8,
}

impl StakingAccount {
    /// 8 + 32 + 8 + 8 + 8 + 1 = 65
    pub const SIZE: usize = 8 + 32 + 8 + 8 + 8 + 1;
}

/// Protocol fee configuration
#[account]
pub struct FeeConfig {
    /// Admin
    pub admin: Pubkey,
    /// Fee in basis points (100 = 1%)
    pub fee_bps: u16,
    /// Total fees collected
    pub total_fees_collected: u64,
    /// Bump
    pub bump: u8,
}

impl FeeConfig {
    pub const SIZE: usize = 8 + 32 + 2 + 8 + 1;
}

/// Custom error codes
#[error_code]
pub enum OverflowError {
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
    
    #[msg("Arithmetic underflow occurred")]
    ArithmeticUnderflow,
    
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
    
    #[msg("Invalid fee calculation")]
    InvalidFeeCalculation,
    
    #[msg("Division by zero")]
    DivisionByZero,
    
    #[msg("Invalid authority")]
    InvalidAuthority,
}
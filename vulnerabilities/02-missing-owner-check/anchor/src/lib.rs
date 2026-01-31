//! # Missing Owner Check - Anchor Implementation
//!
//! This module demonstrates the missing owner check vulnerability and its fix
//! using the Anchor framework.
//!
//! ## The Vulnerability
//!
//! In Solana, any program can create accounts and write arbitrary data to them.
//! The `owner` field indicates which program has authority over an account's data.
//! 
//! If you read data from an account without verifying its owner, you might be
//! reading attacker-controlled fake data!
//!
//! ## Anchor's Solution
//!
//! Anchor provides `Account<'info, T>` which automatically verifies:
//! 1. The account owner matches `T::owner()` (usually your program)
//! 2. The discriminator matches (first 8 bytes)
//! 3. The data deserializes correctly to type `T`
//!
//! Using `UncheckedAccount<'info>` bypasses ALL of these checks!
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE implementation using UncheckedAccount
//! - `secure.rs` - SECURE implementation using Account<T>

use anchor_lang::prelude::*;

pub mod vulnerable;
pub mod secure;

declare_id!("Own2222222222222222222222222222222222222222");

/// User account that stores balance and rewards
#[account]
pub struct UserAccount {
    /// The user's wallet address
    pub authority: Pubkey,
    /// User's current balance
    pub balance: u64,
    /// Total rewards claimed
    pub total_rewards_claimed: u64,
}

impl UserAccount {
    /// 8 (discriminator) + 32 (authority) + 8 (balance) + 8 (rewards) = 56
    pub const SIZE: usize = 8 + 32 + 8 + 8;
}

/// Reward pool that holds pending rewards for users
/// 
/// This account MUST be owned by this program to be trusted.
/// If an attacker creates a fake one, they control the data!
#[account]
pub struct RewardPool {
    /// Authority who manages this reward pool
    pub authority: Pubkey,
    /// User who can claim these rewards
    pub beneficiary: Pubkey,
    /// Amount of pending rewards
    pub pending_rewards: u64,
    /// Whether rewards have been claimed
    pub claimed: bool,
}

impl RewardPool {
    /// 8 + 32 + 32 + 8 + 1 = 81
    pub const SIZE: usize = 8 + 32 + 32 + 8 + 1;
}

/// Custom error codes
#[error_code]
pub enum OwnerCheckError {
    #[msg("Invalid account owner - account not owned by expected program")]
    InvalidAccountOwner,
    
    #[msg("Invalid authority for this account")]
    InvalidAuthority,
    
    #[msg("Rewards already claimed")]
    AlreadyClaimed,
    
    #[msg("Invalid account data format")]
    InvalidAccountData,
    
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
//! # SECURE Implementation - Proper Arithmetic Safety
//!
//! ✅ This code demonstrates the CORRECT way to handle arithmetic in Anchor.
//!
//! ## The Fix
//!
//! Use Rust's checked arithmetic methods that return Option:
//! - `checked_add()` - Returns None if overflow
//! - `checked_sub()` - Returns None if underflow
//! - `checked_mul()` - Returns None if overflow
//! - `checked_div()` - Returns None if division by zero
//!
//! ## Pattern
//!
//! ```rust
//! let result = a.checked_add(b).ok_or(Error::Overflow)?;
//! ```
//!
//! This converts None to an error and unwraps Some(value).

use anchor_lang::prelude::*;
use crate::{TokenVault, StakingAccount, FeeConfig, OverflowError};

/// ✅ SECURE: Withdraw with underflow protection
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ OverflowError::InvalidAuthority
    )]
    pub vault: Account<'info, TokenVault>,
    
    pub owner: Signer<'info>,
}

/// ✅ SECURE: Withdraw with checked arithmetic
pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ SECURE: checked_sub returns None if underflow
    //
    // If amount > vault.balance:
    // - checked_sub returns None
    // - ok_or converts None to Error
    // - ? propagates error, stopping execution
    //
    // Attack prevented: Cannot underflow to huge balance!
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(OverflowError::InsufficientBalance)?;
    
    // ✅ SECURE: checked_add returns None if overflow
    vault.total_withdrawn = vault.total_withdrawn
        .checked_add(amount)
        .ok_or(OverflowError::ArithmeticOverflow)?;
    
    msg!("✅ SECURE: Withdrew {} tokens", amount);
    msg!("✅ New balance: {} (underflow-protected)", vault.balance);
    
    Ok(())
}

/// ✅ SECURE: Deposit with overflow protection
#[derive(Accounts)]
pub struct DepositSecure<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ OverflowError::InvalidAuthority
    )]
    pub vault: Account<'info, TokenVault>,
    
    pub owner: Signer<'info>,
}

/// ✅ SECURE: Deposit with checked arithmetic
pub fn deposit_secure(ctx: Context<DepositSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ SECURE: checked_add returns None if overflow
    //
    // If balance + amount > u64::MAX:
    // - checked_add returns None
    // - ok_or converts to Error
    // - Transaction fails safely
    //
    // Attack prevented: Cannot wrap balance to small number!
    vault.balance = vault.balance
        .checked_add(amount)
        .ok_or(OverflowError::ArithmeticOverflow)?;
    
    vault.total_deposited = vault.total_deposited
        .checked_add(amount)
        .ok_or(OverflowError::ArithmeticOverflow)?;
    
    msg!("✅ SECURE: Deposited {} tokens", amount);
    msg!("✅ New balance: {} (overflow-protected)", vault.balance);
    
    Ok(())
}

/// ✅ SECURE: Fee calculation with overflow protection
#[derive(Accounts)]
pub struct CalculateFeeSecure<'info> {
    pub fee_config: Account<'info, FeeConfig>,
}

/// ✅ SECURE: Calculate fee using checked operations
pub fn calculate_fee_secure(
    ctx: Context<CalculateFeeSecure>,
    amount: u64,
) -> Result<u64> {
    let fee_bps = ctx.accounts.fee_config.fee_bps as u64;
    
    // ✅ SECURE: Use checked_mul to catch overflow
    let numerator = amount
        .checked_mul(fee_bps)
        .ok_or(OverflowError::ArithmeticOverflow)?;
    
    // ✅ SECURE: Use checked_div (also catches div by zero)
    let fee = numerator
        .checked_div(10000)
        .ok_or(OverflowError::DivisionByZero)?;
    
    msg!("✅ SECURE: Calculated fee = {} (overflow-protected)", fee);
    
    Ok(fee)
}

/// ✅ SECURE: Alternative fee calculation using u128
pub fn calculate_fee_u128(amount: u64, fee_bps: u64) -> Result<u64> {
    // ✅ SECURE: Use u128 for intermediate calculation
    // This gives us much more headroom before overflow
    //
    // u64::MAX * 10000 fits comfortably in u128
    let numerator = (amount as u128)
        .checked_mul(fee_bps as u128)
        .ok_or(OverflowError::ArithmeticOverflow)?;
    
    let result = numerator / 10000u128;
    
    // ✅ SECURE: Verify result fits in u64 before casting
    if result > u64::MAX as u128 {
        return Err(OverflowError::ArithmeticOverflow.into());
    }
    
    msg!("✅ SECURE: Fee calculated using u128 intermediates");
    
    Ok(result as u64)
}

/// ✅ SECURE: Reward calculation with full protection
#[derive(Accounts)]
pub struct CalculateRewardsSecure<'info> {
    #[account(
        has_one = owner @ OverflowError::InvalidAuthority
    )]
    pub staking: Account<'info, StakingAccount>,
    
    pub owner: Signer<'info>,
}

/// ✅ SECURE: Calculate staking rewards with overflow protection
pub fn calculate_rewards_secure(
    ctx: Context<CalculateRewardsSecure>,
    current_timestamp: i64,
    reward_rate: u64,
) -> Result<u64> {
    let staking = &ctx.accounts.staking;
    
    // ✅ SECURE: Use checked arithmetic for timestamp subtraction
    let elapsed = current_timestamp
        .checked_sub(staking.stake_timestamp)
        .ok_or(OverflowError::ArithmeticUnderflow)?;
    
    // ✅ SECURE: Validate elapsed is positive
    if elapsed < 0 {
        return Err(OverflowError::ArithmeticUnderflow.into());
    }
    
    let elapsed_u64 = elapsed as u64;
    
    // ✅ SECURE: Use u128 for multi-step calculation
    // staked_amount * elapsed * reward_rate could easily overflow u64
    let rewards_u128 = (staking.staked_amount as u128)
        .checked_mul(elapsed_u64 as u128)
        .ok_or(OverflowError::ArithmeticOverflow)?
        .checked_mul(reward_rate as u128)
        .ok_or(OverflowError::ArithmeticOverflow)?;
    
    // ✅ SECURE: Verify result fits in u64
    if rewards_u128 > u64::MAX as u128 {
        msg!("Rewards exceed u64::MAX, capping");
        return Ok(u64::MAX);  // Or return error based on requirements
    }
    
    let rewards = rewards_u128 as u64;
    
    msg!("✅ SECURE: Calculated rewards = {} (overflow-protected)", rewards);
    
    Ok(rewards)
}

/// ✅ SECURE: Transfer with full protection
pub fn transfer_secure(
    from_balance: u64,
    to_balance: u64,
    amount: u64,
) -> Result<(u64, u64)> {
    // ✅ SECURE: Check underflow on source
    let new_from = from_balance
        .checked_sub(amount)
        .ok_or(OverflowError::InsufficientBalance)?;
    
    // ✅ SECURE: Check overflow on destination
    let new_to = to_balance
        .checked_add(amount)
        .ok_or(OverflowError::ArithmeticOverflow)?;
    
    msg!("✅ SECURE: Transfer {} tokens (protected)", amount);
    msg!("✅ From: {} -> {} (underflow-checked)", from_balance, new_from);
    msg!("✅ To: {} -> {} (overflow-checked)", to_balance, new_to);
    
    Ok((new_from, new_to))
}

/// Initialize vault
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = owner,
        space = TokenVault::SIZE,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, TokenVault>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.owner = ctx.accounts.owner.key();
    vault.balance = 0;
    vault.total_deposited = 0;
    vault.total_withdrawn = 0;
    vault.bump = ctx.bumps.vault;
    
    msg!("✅ Vault initialized for: {}", vault.owner);
    Ok(())
}

/*
 * ============================================================================
 * RUST CHECKED ARITHMETIC REFERENCE
 * ============================================================================
 *
 * All integer types (u8, u16, u32, u64, u128, i8, i16, i32, i64, i128) have:
 *
 * CHECKED OPERATIONS (return Option<T>):
 * - checked_add(rhs) - Addition
 * - checked_sub(rhs) - Subtraction
 * - checked_mul(rhs) - Multiplication
 * - checked_div(rhs) - Division
 * - checked_rem(rhs) - Remainder
 * - checked_pow(exp) - Power
 * - checked_neg() - Negation (signed only)
 * - checked_shl(rhs) - Shift left
 * - checked_shr(rhs) - Shift right
 *
 * SATURATING OPERATIONS (clamp at min/max):
 * - saturating_add(rhs)
 * - saturating_sub(rhs)
 * - saturating_mul(rhs)
 *
 * WRAPPING OPERATIONS (explicit wrap):
 * - wrapping_add(rhs)
 * - wrapping_sub(rhs)
 * - wrapping_mul(rhs)
 *
 * OVERFLOWING OPERATIONS (return (result, bool)):
 * - overflowing_add(rhs)
 * - overflowing_sub(rhs)
 * - overflowing_mul(rhs)
 *
 * ============================================================================
 * COMMON PATTERNS
 * ============================================================================
 *
 * // Pattern 1: Convert to error
 * let result = a.checked_add(b).ok_or(Error::Overflow)?;
 *
 * // Pattern 2: Use default on overflow
 * let result = a.checked_add(b).unwrap_or(u64::MAX);
 *
 * // Pattern 3: Chain multiple operations
 * let result = a
 *     .checked_mul(b).ok_or(Error::Overflow)?
 *     .checked_div(c).ok_or(Error::DivByZero)?
 *     .checked_add(d).ok_or(Error::Overflow)?;
 *
 * // Pattern 4: Use u128 for intermediates
 * let result = ((a as u128) * (b as u128) / (c as u128)) as u64;
 *
 * ============================================================================
 */
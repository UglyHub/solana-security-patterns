//! # VULNERABLE Implementation - Integer Overflow Attacks
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation uses direct arithmetic operators (+, -, *, /) which
//! can overflow/underflow silently in release mode.
//!
//! ## Attack Scenarios
//!
//! 1. **Underflow Attack**: Withdraw more than balance to get max u64 balance
//! 2. **Overflow Attack**: Deposit huge amount to wrap balance to small number
//! 3. **Fee Bypass**: Use large amounts that overflow fee calculation

use anchor_lang::prelude::*;
use crate::{TokenVault, StakingAccount, FeeConfig, OverflowError};

/// ❌ VULNERABLE: Withdraw with potential underflow
#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ OverflowError::InvalidAuthority
    )]
    pub vault: Account<'info, TokenVault>,
    
    pub owner: Signer<'info>,
}

/// ❌ VULNERABLE: Withdraw without underflow protection
pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ VULNERABILITY #1: No underflow check!
    //
    // If amount > vault.balance, this WRAPS in release mode:
    // Example: 100 - 200 = 18,446,744,073,709,551,516 (u64::MAX - 99)
    //
    // Attack: Request withdrawal of more than balance
    // Result: Balance becomes astronomically large!
    vault.balance = vault.balance - amount;
    
    // ❌ VULNERABILITY #2: No overflow check!
    //
    // If total_withdrawn is near u64::MAX, this wraps to small number
    vault.total_withdrawn = vault.total_withdrawn + amount;
    
    msg!("⚠️ VULNERABLE: Withdrew {} tokens", amount);
    msg!("⚠️ New balance: {} (may have underflowed!)", vault.balance);
    
    Ok(())
}

/// ❌ VULNERABLE: Deposit with potential overflow
#[derive(Accounts)]
pub struct DepositVulnerable<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ OverflowError::InvalidAuthority
    )]
    pub vault: Account<'info, TokenVault>,
    
    pub owner: Signer<'info>,
}

/// ❌ VULNERABLE: Deposit without overflow protection
pub fn deposit_vulnerable(ctx: Context<DepositVulnerable>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ VULNERABILITY: No overflow check!
    //
    // If balance + amount > u64::MAX, wraps to small number
    // Example: u64::MAX + 1 = 0
    //
    // Attack: Deposit amount that causes wrap
    // Result: Balance becomes tiny instead of huge!
    vault.balance = vault.balance + amount;
    vault.total_deposited = vault.total_deposited + amount;
    
    msg!("⚠️ VULNERABLE: Deposited {} tokens", amount);
    msg!("⚠️ New balance: {} (may have overflowed!)", vault.balance);
    
    Ok(())
}

/// ❌ VULNERABLE: Fee calculation with overflow
#[derive(Accounts)]
pub struct CalculateFeeVulnerable<'info> {
    pub fee_config: Account<'info, FeeConfig>,
}

/// ❌ VULNERABLE: Calculate fee without overflow protection
pub fn calculate_fee_vulnerable(
    ctx: Context<CalculateFeeVulnerable>,
    amount: u64,
) -> Result<u64> {
    let fee_bps = ctx.accounts.fee_config.fee_bps as u64;
    
    // ❌ VULNERABILITY: Multiplication overflow!
    //
    // If amount is large (e.g., 10^18), amount * fee_bps overflows
    // Example: 10,000,000,000,000,000,000 * 100 overflows u64
    //
    // Attack: Use large amount that overflows to small number
    // Result: Pay almost no fees!
    let fee = amount * fee_bps / 10000;
    
    msg!("⚠️ VULNERABLE: Calculated fee = {} (may have overflowed!)", fee);
    
    Ok(fee)
}

/// ❌ VULNERABLE: Reward calculation with multiple overflows
#[derive(Accounts)]
pub struct CalculateRewardsVulnerable<'info> {
    #[account(
        has_one = owner @ OverflowError::InvalidAuthority
    )]
    pub staking: Account<'info, StakingAccount>,
    
    pub owner: Signer<'info>,
}

/// ❌ VULNERABLE: Calculate staking rewards
pub fn calculate_rewards_vulnerable(
    ctx: Context<CalculateRewardsVulnerable>,
    current_timestamp: i64,
    reward_rate: u64,  // Rewards per second per token
) -> Result<u64> {
    let staking = &ctx.accounts.staking;
    
    // Calculate time elapsed
    // ❌ VULNERABILITY: i64 subtraction can underflow if timestamps wrong
    let elapsed = current_timestamp - staking.stake_timestamp;
    
    if elapsed < 0 {
        return Err(OverflowError::ArithmeticUnderflow.into());
    }
    
    let elapsed_u64 = elapsed as u64;
    
    // ❌ VULNERABILITY: Multiple overflow points!
    //
    // staked_amount * elapsed_u64 can overflow
    // Then * reward_rate can overflow again
    //
    // Attack: Stake for long time or use high reward rate
    // Result: Rewards wrap to tiny amount, or calculation corrupted
    let rewards = staking.staked_amount * elapsed_u64 * reward_rate;
    
    msg!("⚠️ VULNERABLE: Calculated rewards = {}", rewards);
    msg!("⚠️ This calculation may have overflowed multiple times!");
    
    Ok(rewards)
}

/// ❌ VULNERABLE: Transfer with both over/underflow risks
pub fn transfer_vulnerable(
    from_balance: u64,
    to_balance: u64,
    amount: u64,
) -> Result<(u64, u64)> {
    // ❌ Both operations can fail!
    let new_from = from_balance - amount;  // Underflow if amount > from_balance
    let new_to = to_balance + amount;      // Overflow if to_balance + amount > MAX
    
    msg!("⚠️ VULNERABLE: Transfer {} tokens", amount);
    msg!("⚠️ From: {} -> {}", from_balance, new_from);
    msg!("⚠️ To: {} -> {}", to_balance, new_to);
    
    Ok((new_from, new_to))
}

/*
 * ============================================================================
 * EXPLOIT DEMONSTRATIONS
 * ============================================================================
 *
 * EXPLOIT 1: Underflow Attack
 * ---------------------------
 * 
 * Setup: User has vault with balance = 100
 * 
 * Attack:
 * ```javascript
 * await program.methods
 *     .withdrawVulnerable(new BN(101))  // More than balance!
 *     .accounts({ vault, owner })
 *     .rpc();
 * ```
 * 
 * Result:
 * - 100 - 101 = 18,446,744,073,709,551,615 (u64::MAX - 0)
 * - User now has ~18 quintillion tokens!
 *
 * EXPLOIT 2: Fee Bypass Attack
 * ----------------------------
 * 
 * Setup: Protocol charges 1% fee (fee_bps = 100)
 * 
 * Attack:
 * ```javascript
 * // This amount causes overflow in amount * fee_bps
 * const maliciousAmount = new BN("18446744073709551615");  // u64::MAX
 * 
 * await program.methods
 *     .calculateFeeVulnerable(maliciousAmount)
 *     .accounts({ feeConfig })
 *     .rpc();
 * ```
 * 
 * Result:
 * - u64::MAX * 100 overflows to small number
 * - Fee calculated as tiny amount instead of 1%
 * - Attacker pays almost nothing!
 *
 * EXPLOIT 3: Balance Wrap Attack
 * ------------------------------
 * 
 * Setup: User has balance = 100
 * 
 * Attack:
 * ```javascript
 * // Deposit amount that wraps balance to 0
 * const wrapAmount = new BN(u64::MAX - 99);  
 * 
 * await program.methods
 *     .depositVulnerable(wrapAmount)
 *     .accounts({ vault, owner })
 *     .rpc();
 * ```
 * 
 * Result:
 * - 100 + (u64::MAX - 99) = 0 (wrapped!)
 * - User's balance is now 0!
 *
 * ============================================================================
 */
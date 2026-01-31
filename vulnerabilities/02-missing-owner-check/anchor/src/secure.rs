//! # SECURE Implementation - Proper Owner Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify account ownership in Anchor.
//!
//! ## The Fix
//!
//! This implementation uses `Account<'info, RewardPool>` which automatically
//! verifies that the account is owned by THIS program before allowing access.
//!
//! ## How Account<T> Protects You
//!
//! When you write `pub reward_source: Account<'info, RewardPool>`, Anchor:
//!
//! 1. Checks `account.owner == RewardPool::owner()` (this program's ID)
//! 2. Checks discriminator matches RewardPool::DISCRIMINATOR
//! 3. Deserializes data into RewardPool struct
//!
//! If ANY check fails, the transaction is rejected BEFORE your code runs.
//!
//! ## Why Attackers Can't Bypass This
//!
//! - Attacker creates fake account owned by their program
//! - Attacker calls our program with fake account
//! - Anchor checks: fake_account.owner == our_program_id?
//! - Check fails: fake_account.owner == attacker_program_id
//! - Transaction rejected: "Account not owned by expected program"
//! - Attack prevented!

use anchor_lang::prelude::*;
use crate::{UserAccount, RewardPool, OwnerCheckError};

/// ✅ SECURE: Claim rewards with proper owner verification
#[derive(Accounts)]
pub struct ClaimRewardsSecure<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    /// User's account where rewards will be deposited
    #[account(
        mut,
        constraint = user_account.authority == user.key() @ OwnerCheckError::InvalidAuthority
    )]
    pub user_account: Account<'info, UserAccount>,
    
    /// ✅ SECURE: Using Account<'info, RewardPool>
    /// 
    /// Anchor automatically verifies:
    /// 1. reward_source.owner == crate::ID (this program)
    /// 2. Discriminator matches RewardPool
    /// 3. Data deserializes to RewardPool struct
    /// 
    /// An attacker CANNOT pass a fake account because:
    /// - Fake account owned by attacker's program
    /// - Our program ID != attacker's program ID
    /// - Anchor rejects with "AccountOwnedByWrongProgram"
    #[account(
        mut,
        constraint = reward_source.beneficiary == user.key() @ OwnerCheckError::InvalidAuthority,
        constraint = !reward_source.claimed @ OwnerCheckError::AlreadyClaimed
    )]
    pub reward_source: Account<'info, RewardPool>,
}

/// ✅ SECURE: Claim rewards function
///
/// By the time this function runs, Anchor has ALREADY verified:
/// 1. reward_source is owned by THIS program
/// 2. The discriminator matches RewardPool
/// 3. The data deserializes correctly
/// 4. beneficiary == user (constraint)
/// 5. claimed == false (constraint)
///
/// We can safely trust all data in reward_source!
pub fn claim_rewards_secure(ctx: Context<ClaimRewardsSecure>) -> Result<()> {
    let reward_source = &mut ctx.accounts.reward_source;
    let user_account = &mut ctx.accounts.user_account;
    
    // ✅ SAFE: This data is verified to come from a legitimate account
    // owned by our program. No attacker can fake this!
    let pending_rewards = reward_source.pending_rewards;
    
    // Update user account
    user_account.balance = user_account.balance
        .checked_add(pending_rewards)
        .ok_or(OwnerCheckError::ArithmeticOverflow)?;
    
    user_account.total_rewards_claimed = user_account.total_rewards_claimed
        .checked_add(pending_rewards)
        .ok_or(OwnerCheckError::ArithmeticOverflow)?;
    
    // Mark rewards as claimed
    reward_source.claimed = true;
    reward_source.pending_rewards = 0;
    
    msg!("✅ SECURE: Claimed {} verified rewards", pending_rewards);
    msg!("✅ Account ownership verified by Anchor");
    
    Ok(())
}

/// Initialize a reward pool (for completeness)
#[derive(Accounts)]
pub struct InitializeRewardPool<'info> {
    #[account(
        init,
        payer = authority,
        space = RewardPool::SIZE,
    )]
    pub reward_pool: Account<'info, RewardPool>,
    
    /// CHECK: Beneficiary can be any account
    pub beneficiary: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize_reward_pool(
    ctx: Context<InitializeRewardPool>,
    reward_amount: u64,
) -> Result<()> {
    let reward_pool = &mut ctx.accounts.reward_pool;
    
    reward_pool.authority = ctx.accounts.authority.key();
    reward_pool.beneficiary = ctx.accounts.beneficiary.key();
    reward_pool.pending_rewards = reward_amount;
    reward_pool.claimed = false;
    
    msg!("✅ Reward pool initialized");
    msg!("✅ Beneficiary: {}", reward_pool.beneficiary);
    msg!("✅ Pending rewards: {}", reward_pool.pending_rewards);
    
    Ok(())
}

/*
 * ============================================================================
 * HOW ANCHOR OWNER CHECKS WORK (DEEP DIVE)
 * ============================================================================
 *
 * When you write:
 * ```rust
 * pub reward_source: Account<'info, RewardPool>,
 * ```
 *
 * Anchor generates code equivalent to:
 * ```rust
 * // Step 1: Get the account
 * let reward_source_info = next_account_info(accounts)?;
 *
 * // Step 2: Check owner (THE KEY SECURITY CHECK!)
 * if reward_source_info.owner != &RewardPool::owner() {
 *     return Err(ErrorCode::AccountOwnedByWrongProgram.into());
 * }
 *
 * // Step 3: Check it's not the system program with 0 lamports
 * if reward_source_info.owner == &system_program::ID 
 *     && reward_source_info.lamports() == 0 {
 *     return Err(ErrorCode::AccountNotInitialized.into());
 * }
 *
 * // Step 4: Borrow and deserialize data
 * let data = reward_source_info.try_borrow_data()?;
 *
 * // Step 5: Check discriminator
 * if data[0..8] != RewardPool::DISCRIMINATOR {
 *     return Err(ErrorCode::AccountDiscriminatorMismatch.into());
 * }
 *
 * // Step 6: Deserialize the rest
 * let reward_source = RewardPool::try_deserialize(&mut &data[8..])?;
 * ```
 *
 * The #[account] macro implements:
 * ```rust
 * impl Owner for RewardPool {
 *     fn owner() -> Pubkey {
 *         crate::ID  // This program's ID
 *     }
 * }
 * ```
 *
 * ============================================================================
 * ACCOUNT TYPE GUIDE
 * ============================================================================
 *
 * | Type | Owner Check | Discriminator | Use Case |
 * |------|-------------|---------------|----------|
 * | Account<T> | ✅ Auto | ✅ Auto | Your program's accounts |
 * | UncheckedAccount | ❌ None | ❌ None | Only pubkey/lamports needed |
 * | Signer | ❌ None | ❌ None | Signature verification |
 * | Program<T> | ✅ Auto | N/A | Verifying program accounts |
 * | SystemAccount | ✅ System | N/A | System-owned accounts |
 *
 * RULE: If you READ DATA, use Account<T>. Period.
 *
 * ============================================================================
 */
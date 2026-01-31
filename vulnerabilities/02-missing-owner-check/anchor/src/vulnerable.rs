//! # VULNERABLE Implementation - Missing Owner Check
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation uses `UncheckedAccount<'info>` for the reward source
//! and reads its data without verifying the account owner. An attacker can
//! create their own account with fake reward data and pass it to this function.
//!
//! ## Attack Scenario
//!
//! 1. Attacker deploys their own program (let's call it "FakeProgram")
//! 2. Attacker creates an account owned by FakeProgram with structure:
//!    - Bytes 0-8: Copy our RewardPool discriminator
//!    - Bytes 8-40: Some pubkey (authority)
//!    - Bytes 40-72: Attacker's pubkey (beneficiary)
//!    - Bytes 72-80: 1,000,000,000,000 (1 trillion fake rewards!)
//!    - Byte 80: 0 (not claimed)
//! 3. Attacker calls claim_rewards_vulnerable with their fake account
//! 4. Our program reads the fake data and grants 1 trillion rewards!
//!
//! ## Why Discriminator Check Alone Fails
//!
//! You might think: "But I check the discriminator!"
//! 
//! WRONG. The attacker owns their account, so they can write ANY bytes,
//! including a copy of your discriminator. The discriminator only proves
//! the data FORMAT, not the data SOURCE.

use anchor_lang::prelude::*;
use crate::{UserAccount, OwnerCheckError};

/// ❌ VULNERABLE: Claim rewards without verifying account owner
#[derive(Accounts)]
pub struct ClaimRewardsVulnerable<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    
    /// User's account where rewards will be deposited
    #[account(
        mut,
        constraint = user_account.authority == user.key() @ OwnerCheckError::InvalidAuthority
    )]
    pub user_account: Account<'info, UserAccount>,
    
    /// ❌ VULNERABILITY: Using UncheckedAccount for external data!
    /// 
    /// We read data from this account but NEVER verify who owns it.
    /// An attacker can pass ANY account here with fake reward data.
    /// 
    /// CHECK: We verify beneficiary matches user, but this is INSUFFICIENT!
    /// The attacker just puts the user's pubkey in their fake account.
    pub reward_source: UncheckedAccount<'info>,
}

/// ❌ VULNERABLE: Claim rewards function
///
/// This function reads reward data from an unverified account.
/// An attacker can create a fake account with inflated rewards.
pub fn claim_rewards_vulnerable(ctx: Context<ClaimRewardsVulnerable>) -> Result<()> {
    let reward_source = &ctx.accounts.reward_source;
    let user_account = &mut ctx.accounts.user_account;
    let user = &ctx.accounts.user;
    
    // ❌ MISSING: Owner verification!
    // 
    // We should check:
    // if reward_source.owner != &crate::ID {
    //     return Err(OwnerCheckError::InvalidAccountOwner.into());
    // }
    
    // Borrow account data
    let data = reward_source.try_borrow_data()?;
    
    // Check minimum data length
    if data.len() < 81 {
        return Err(OwnerCheckError::InvalidAccountData.into());
    }
    
    // Check discriminator (INSUFFICIENT!)
    // 
    // ❌ This check is NOT enough!
    // Attacker can copy our discriminator into their fake account.
    // Discriminator only verifies FORMAT, not SOURCE.
    let expected_discriminator: [u8; 8] = [0x52, 0x45, 0x57, 0x41, 0x52, 0x44, 0x50, 0x4C]; // "REWARDPL"
    if data[0..8] != expected_discriminator {
        return Err(OwnerCheckError::InvalidAccountData.into());
    }
    
    // Read beneficiary (bytes 40-72)
    let beneficiary = Pubkey::try_from(&data[40..72])
        .map_err(|_| OwnerCheckError::InvalidAccountData)?;
    
    // Check beneficiary matches user
    // 
    // ❌ This check is ALSO not enough!
    // Attacker just puts the user's pubkey as beneficiary in their fake account.
    if beneficiary != user.key() {
        return Err(OwnerCheckError::InvalidAuthority.into());
    }
    
    // Read pending rewards (bytes 72-80)
    // 
    // ❌ DANGER: This value is completely controlled by attacker!
    let pending_rewards = u64::from_le_bytes(
        data[72..80].try_into().map_err(|_| OwnerCheckError::InvalidAccountData)?
    );
    
    // Read claimed flag (byte 80)
    let claimed = data[80] != 0;
    
    if claimed {
        return Err(OwnerCheckError::AlreadyClaimed.into());
    }
    
    drop(data);
    
    // ❌ CRITICAL VULNERABILITY: Granting fake rewards!
    // 
    // The attacker's fake account says they have 1 trillion rewards.
    // We never verified the account is actually owned by our program.
    // Result: Attacker gets 1 trillion free rewards!
    
    user_account.balance = user_account.balance
        .checked_add(pending_rewards)
        .ok_or(OwnerCheckError::ArithmeticOverflow)?;
    
    user_account.total_rewards_claimed = user_account.total_rewards_claimed
        .checked_add(pending_rewards)
        .ok_or(OwnerCheckError::ArithmeticOverflow)?;
    
    msg!("⚠️ VULNERABLE: Claimed {} rewards (POTENTIALLY FAKE!)", pending_rewards);
    msg!("⚠️ Account owner was NOT verified!");
    
    Ok(())
}

/*
 * ============================================================================
 * EXPLOIT DEMONSTRATION
 * ============================================================================
 *
 * // Attacker's TypeScript code:
 *
 * // 1. Deploy a simple program that can create accounts
 * const attackerProgram = await deployAttackerProgram();
 *
 * // 2. Create a fake reward account
 * const fakeRewardAccount = Keypair.generate();
 *
 * // 3. Build fake data that looks like a RewardPool
 * const fakeData = Buffer.alloc(81);
 * 
 * // Discriminator (copy from real program)
 * fakeData.set([0x52, 0x45, 0x57, 0x41, 0x52, 0x44, 0x50, 0x4C], 0);
 * 
 * // Authority (any pubkey)
 * fakeData.set(somePubkey.toBuffer(), 8);
 * 
 * // Beneficiary (attacker's pubkey - will pass the check!)
 * fakeData.set(attackerPubkey.toBuffer(), 40);
 * 
 * // Pending rewards (1 TRILLION!)
 * fakeData.writeBigUInt64LE(BigInt(1_000_000_000_000), 72);
 * 
 * // Claimed flag (false)
 * fakeData.writeUInt8(0, 80);
 *
 * // 4. Create account owned by attacker's program (NOT the victim program!)
 * await attackerProgram.methods
 *     .createFakeAccount(fakeData)
 *     .accounts({ newAccount: fakeRewardAccount.publicKey })
 *     .signers([fakeRewardAccount])
 *     .rpc();
 *
 * // 5. Call vulnerable program with fake account
 * await vulnerableProgram.methods
 *     .claimRewardsVulnerable()
 *     .accounts({
 *         user: attackerPubkey,
 *         userAccount: attackerUserAccount,
 *         rewardSource: fakeRewardAccount.publicKey,  // FAKE!
 *     })
 *     .rpc();
 *
 * // 6. Attacker now has 1 trillion rewards!
 *
 * ============================================================================
 */
//! # VULNERABLE Implementation - Missing Owner Check
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation reads data from the reward_source account without
//! verifying that the account is owned by this program. An attacker can
//! create their own account with fake reward data and pass it here.
//!
//! ## What's Missing
//!
//! ```rust
//! // This critical check is MISSING:
//! if !reward_source.is_owned_by(&crate::ID) {
//!     return Err(ProgramError::InvalidAccountOwner);
//! }
//! ```

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    user_offsets, reward_offsets,
    USER_DISCRIMINATOR, REWARD_DISCRIMINATOR,
};

/// ❌ VULNERABLE: Claim rewards without verifying account owner
///
/// ## Expected Accounts
///
/// | Index | Writable | Description                          |
/// |-------|----------|--------------------------------------|
/// | 0     | Yes      | User account (to receive rewards)    |
/// | 1     | No       | Reward source (NOT VERIFIED!)        |
/// | 2     | No       | User (signer)                        |
///
/// ## Security Flaw
///
/// Account 1 (reward_source) is read without owner verification.
/// Attacker can pass any account with fake reward data!
pub fn claim_rewards_vulnerable(accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let user_account = &accounts[0];
    let reward_source = &accounts[1];
    let user = &accounts[2];
    
    // Verify user signed
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ❌ VULNERABILITY: Missing owner check!
    //
    // We should verify:
    // if !reward_source.is_owned_by(&crate::ID) {
    //     return Err(ProgramError::InvalidAccountOwner);
    // }
    //
    // Without this check, attacker can pass a fake account they control!
    
    // Borrow reward source data
    let reward_data = reward_source.try_borrow_data()?;
    
    // Check discriminator (NOT ENOUGH!)
    // 
    // ❌ Attacker can copy our discriminator into their fake account!
    if reward_data.len() < REWARD_POOL_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    
    if reward_data[..8] != REWARD_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Read beneficiary
    let beneficiary = read_pubkey(&reward_data, reward_offsets::BENEFICIARY);
    
    // Check beneficiary matches user (NOT ENOUGH!)
    //
    // ❌ Attacker just puts user's pubkey in their fake account!
    if &beneficiary != user.key() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Check not already claimed
    let claimed = reward_data[reward_offsets::CLAIMED] != 0;
    if claimed {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ❌ DANGER: Reading attacker-controlled value!
    let pending_rewards = read_u64(&reward_data, reward_offsets::PENDING_REWARDS);
    
    drop(reward_data);
    
    // Verify user_account discriminator
    let user_data = user_account.try_borrow_data()?;
    if user_data[..8] != USER_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Verify user_account authority
    let authority = read_pubkey(&user_data, user_offsets::AUTHORITY);
    if &authority != user.key() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let current_balance = read_u64(&user_data, user_offsets::BALANCE);
    let current_claimed = read_u64(&user_data, user_offsets::TOTAL_CLAIMED);
    drop(user_data);
    
    // Update user account with (potentially fake!) rewards
    let mut user_data = user_account.try_borrow_mut_data()?;
    
    let new_balance = current_balance
        .checked_add(pending_rewards)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    let new_claimed = current_claimed
        .checked_add(pending_rewards)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    write_u64(&mut user_data, user_offsets::BALANCE, new_balance);
    write_u64(&mut user_data, user_offsets::TOTAL_CLAIMED, new_claimed);
    
    pinocchio::msg!("⚠️ VULNERABLE: Claimed {} rewards", pending_rewards);
    pinocchio::msg!("⚠️ Account owner was NOT verified - rewards may be FAKE!");
    
    Ok(())
}

/*
 * ============================================================================
 * WHY DISCRIMINATOR CHECKS ALONE ARE INSUFFICIENT
 * ============================================================================
 *
 * Common misconception: "I check the discriminator, so I'm safe!"
 *
 * WRONG. Here's why:
 *
 * 1. YOU control what discriminator you check for
 * 2. ATTACKER controls what bytes are in their account
 * 3. ATTACKER can write YOUR discriminator into THEIR account
 *
 * Discriminators prove DATA FORMAT, not DATA SOURCE.
 *
 * ============================================================================
 * EXAMPLE ATTACK
 * ============================================================================
 *
 * Attacker's program (simplified):
 *
 * ```rust
 * pub fn create_fake_reward_account(
 *     accounts: &[AccountInfo],
 *     victim_pubkey: Pubkey,
 *     fake_amount: u64,
 * ) -> ProgramResult {
 *     let fake_account = &accounts[0];
 *     let mut data = fake_account.try_borrow_mut_data()?;
 *     
 *     // Copy victim program's discriminator
 *     data[0..8].copy_from_slice(b"REWARDPL");
 *     
 *     // Authority (doesn't matter)
 *     data[8..40].copy_from_slice(&[0u8; 32]);
 *     
 *     // Beneficiary = victim's pubkey (passes the check!)
 *     data[40..72].copy_from_slice(victim_pubkey.as_ref());
 *     
 *     // Fake rewards = 1 TRILLION
 *     data[72..80].copy_from_slice(&fake_amount.to_le_bytes());
 *     
 *     // Not claimed
 *     data[80] = 0;
 *     
 *     Ok(())
 * }
 * ```
 *
 * The fake account will:
 * ✅ Pass discriminator check (attacker copied it)
 * ✅ Pass beneficiary check (attacker set it to victim)
 * ❌ FAIL owner check (if we had one!)
 *
 * ============================================================================
 */
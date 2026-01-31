//! # SECURE Implementation - Proper Owner Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify account ownership
//! in Pinocchio.
//!
//! ## The Fix
//!
//! This implementation calls `is_owned_by()` on the reward_source account
//! BEFORE reading any data from it. This ensures the account is controlled
//! by this program, not an attacker.
//!
//! ## Security Guarantees
//!
//! 1. We verify `reward_source.is_owned_by(&crate::ID)` FIRST
//! 2. Only THIS program can create accounts owned by THIS program
//! 3. Therefore, the data must have been written by THIS program
//! 4. Therefore, the data can be trusted

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    user_offsets, reward_offsets,
    USER_DISCRIMINATOR, REWARD_DISCRIMINATOR,
    ID,
};

/// ✅ SECURE: Claim rewards with proper owner verification
///
/// ## Expected Accounts
///
/// | Index | Writable | Description                          |
/// |-------|----------|--------------------------------------|
/// | 0     | Yes      | User account (owned by this program) |
/// | 1     | Yes      | Reward source (owned by this program)|
/// | 2     | No       | User (signer)                        |
///
/// ## Security Checks (in order)
///
/// 1. ✅ User signed the transaction
/// 2. ✅ User account owned by this program
/// 3. ✅ Reward source owned by this program
/// 4. ✅ Discriminators match expected types
/// 5. ✅ Beneficiary matches user
/// 6. ✅ Not already claimed
pub fn claim_rewards_secure(accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let user_account = &accounts[0];
    let reward_source = &accounts[1];
    let user = &accounts[2];
    
    // ✅ SECURITY CHECK #1: Verify user signed
    if !user.is_signer() {
        pinocchio::msg!("❌ Error: User must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ✅ SECURITY CHECK #2: Verify user_account owned by this program
    //
    // This ensures we're updating a legitimate user account,
    // not some fake account the attacker created.
    if !user_account.is_owned_by(&ID) {
        pinocchio::msg!("❌ Error: User account not owned by this program");
        pinocchio::msg!("❌ Expected owner: {:?}", ID);
        pinocchio::msg!("❌ Actual owner: {:?}", user_account.owner());
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // ✅ SECURITY CHECK #3: Verify reward_source owned by this program
    //
    // THIS IS THE KEY FIX!
    //
    // Why this works:
    // - Only THIS program can create accounts owned by THIS program
    // - If account.owner == our_program_id, WE created it
    // - If WE created it, WE wrote the data
    // - If WE wrote the data, it's LEGITIMATE
    //
    // Attacker's fake account would have:
    // - fake_account.owner == attacker_program_id
    // - attacker_program_id != our_program_id
    // - This check FAILS
    // - Attack PREVENTED!
    if !reward_source.is_owned_by(&ID) {
        pinocchio::msg!("❌ Error: Reward source not owned by this program");
        pinocchio::msg!("❌ Expected owner: {:?}", ID);
        pinocchio::msg!("❌ Actual owner: {:?}", reward_source.owner());
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // ✅ SECURITY CHECK #4: Verify discriminators
    //
    // Now that we've verified ownership, discriminator checks are meaningful.
    // They distinguish between different account TYPES from our program.
    let user_data = user_account.try_borrow_data()?;
    if user_data[..8] != USER_DISCRIMINATOR {
        pinocchio::msg!("❌ Error: Invalid user account discriminator");
        return Err(ProgramError::InvalidAccountData);
    }
    
    let reward_data = reward_source.try_borrow_data()?;
    if reward_data[..8] != REWARD_DISCRIMINATOR {
        pinocchio::msg!("❌ Error: Invalid reward source discriminator");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ SECURITY CHECK #5: Verify user_account authority
    let authority = read_pubkey(&user_data, user_offsets::AUTHORITY);
    if &authority != user.key() {
        pinocchio::msg!("❌ Error: User is not account authority");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ SECURITY CHECK #6: Verify beneficiary
    let beneficiary = read_pubkey(&reward_data, reward_offsets::BENEFICIARY);
    if &beneficiary != user.key() {
        pinocchio::msg!("❌ Error: User is not reward beneficiary");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ SECURITY CHECK #7: Verify not already claimed
    let claimed = reward_data[reward_offsets::CLAIMED] != 0;
    if claimed {
        pinocchio::msg!("❌ Error: Rewards already claimed");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ SAFE: All checks passed, data is legitimate
    let pending_rewards = read_u64(&reward_data, reward_offsets::PENDING_REWARDS);
    let current_balance = read_u64(&user_data, user_offsets::BALANCE);
    let current_claimed = read_u64(&user_data, user_offsets::TOTAL_CLAIMED);
    
    drop(user_data);
    drop(reward_data);
    
    // Update user account
    let mut user_data = user_account.try_borrow_mut_data()?;
    
    let new_balance = current_balance
        .checked_add(pending_rewards)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    let new_claimed = current_claimed
        .checked_add(pending_rewards)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    write_u64(&mut user_data, user_offsets::BALANCE, new_balance);
    write_u64(&mut user_data, user_offsets::TOTAL_CLAIMED, new_claimed);
    drop(user_data);
    
    // Mark rewards as claimed
    let mut reward_data = reward_source.try_borrow_mut_data()?;
    reward_data[reward_offsets::CLAIMED] = 1;
    write_u64(&mut reward_data, reward_offsets::PENDING_REWARDS, 0);
    
    pinocchio::msg!("✅ SECURE: Claimed {} verified rewards", pending_rewards);
    pinocchio::msg!("✅ Account ownership verified");
    
    Ok(())
}

/*
 * ============================================================================
 * PINOCCHIO OWNER VERIFICATION CHECKLIST
 * ============================================================================
 *
 * For EVERY account whose data you read:
 *
 * □ 1. Identify the expected owner
 *      - Your program's accounts: is_owned_by(&crate::ID)
 *      - Token accounts: is_owned_by(&spl_token::ID)
 *      - System accounts: is_owned_by(&system_program::ID)
 *
 * □ 2. Check owner BEFORE reading data
 *      ```rust
 *      if !account.is_owned_by(&EXPECTED_OWNER) {
 *          return Err(ProgramError::InvalidAccountOwner);
 *      }
 *      // Now safe to read data
 *      let data = account.try_borrow_data()?;
 *      ```
 *
 * □ 3. THEN check discriminator (to verify account TYPE)
 *
 * □ 4. Document expected owner in comments
 *
 * □ 5. Log helpful error messages
 *
 * ============================================================================
 * VERIFICATION ORDER MATTERS
 * ============================================================================
 *
 * CORRECT ORDER:
 * 1. Check owner (who controls this account?)
 * 2. Check discriminator (what type is it?)
 * 3. Read and validate data fields
 *
 * WRONG ORDER:
 * 1. Check discriminator ← Attacker can fake this!
 * 2. Read data fields ← Attacker controls these!
 * 3. Check owner ← Too late, already read fake data!
 *
 * ============================================================================
 */
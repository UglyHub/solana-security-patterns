//! # VULNERABLE Implementation - Type Cosplay Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation reads account data without checking the discriminator.
//! Because Vault and UserProfile have identical layouts (except discriminator),
//! an attacker can pass a UserProfile where a Vault is expected.
//!
//! ## The Attack
//!
//! 1. Attacker creates UserProfile:
//!    - [PROFILE1][attacker_pubkey][99999][0]
//!
//! 2. Attacker calls withdraw with their UserProfile as "vault"
//!
//! 3. Program reads bytes 8-40 expecting Vault.authority
//!    - Gets UserProfile.owner = attacker_pubkey
//!    - Check passes!
//!
//! 4. Funds transferred to attacker

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, ID,
};

/// ❌ VULNERABLE: Withdraw without discriminator check
///
/// ## Expected Accounts
///
/// | Index | Writable | Description        |
/// |-------|----------|--------------------|
/// | 0     | Yes      | Vault (NOT VERIFIED!) |
/// | 1     | No       | Authority (signer) |
/// | 2     | Yes      | Destination        |
///
/// ## Security Flaw
///
/// We read "authority" from offset 8 without verifying this is actually a Vault.
/// UserProfile.owner is also at offset 8, so type confusion is possible!
pub fn withdraw_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    let destination = &accounts[2];
    
    // Verify signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Verify owner (still important, but not sufficient!)
    if !vault.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let data = vault.try_borrow_data()?;
    
    // Check data length
    if data.len() < crate::ACCOUNT_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ❌ CRITICAL VULNERABILITY!
    //
    // We should check: data[0..8] == VAULT_DISCRIMINATOR
    // But we don't!
    //
    // This allows passing UserProfile where Vault expected:
    // - Both owned by this program ✓
    // - Both have pubkey at offset 8 ✓
    // - Both have u64 at offset 40 ✓
    // - But they're DIFFERENT types!
    
    // Read "authority" from offset 8
    // This is actually UserProfile.owner if wrong type passed!
    let vault_authority = read_pubkey(&data, offsets::AUTHORITY);
    
    // This check PASSES for UserProfile.owner!
    if authority.key() != &vault_authority {
        pinocchio::msg!("Authority mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Read "balance" from offset 40
    // Actually UserProfile.points if wrong type!
    let balance = read_u64(&data, offsets::BALANCE);
    
    // Read flags from offset 48
    let is_locked = data[offsets::FLAGS] != 0;
    
    drop(data);
    
    if is_locked {
        pinocchio::msg!("Vault is locked");
        return Err(ProgramError::InvalidAccountData);
    }
    
    if balance < amount {
        pinocchio::msg!("Insufficient balance");
        return Err(ProgramError::InsufficientFunds);
    }
    
    // ❌ PROCEEDING WITH WRONG ACCOUNT TYPE!
    
    // Update balance
    let mut data = vault.try_borrow_mut_data()?;
    let new_balance = balance.checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    drop(data);
    
    // Transfer lamports
    unsafe {
        let vault_lamports = vault.borrow_mut_lamports_unchecked();
        *vault_lamports = (*vault_lamports)
            .checked_sub(amount)
            .ok_or(ProgramError::InsufficientFunds)?;
        
        let dest_lamports = destination.borrow_mut_lamports_unchecked();
        *dest_lamports = (*dest_lamports)
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    
    pinocchio::msg!("⚠️ VULNERABLE: Withdrew {} lamports", amount);
    pinocchio::msg!("⚠️ Account type was NOT verified!");
    
    Ok(())
}

/// Create a UserProfile (attacker uses this to create attack account)
pub fn create_user_profile(accounts: &[AccountInfo], points: u64) -> ProgramResult {
    let profile = &accounts[0];
    let owner = &accounts[1];
    
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    let mut data = profile.try_borrow_mut_data()?;
    
    // Write discriminator
    data[0..8].copy_from_slice(&crate::PROFILE_DISCRIMINATOR);
    
    // Write owner at offset 8 (same position as Vault.authority!)
    data[8..40].copy_from_slice(owner.key().as_ref());
    
    // Write points at offset 40 (same position as Vault.balance!)
    write_u64(&mut data, offsets::BALANCE, points);
    
    // Write is_premium at offset 48
    data[offsets::FLAGS] = 0;
    
    pinocchio::msg!("Created UserProfile for: {:?}", owner.key());
    pinocchio::msg!("⚠️ This can be used for type cosplay attack!");
    
    Ok(())
}

/*
 * ============================================================================
 * MEMORY LAYOUT COMPARISON
 * ============================================================================
 *
 * Vault account:
 * +--------+------------------+------------+-----------+
 * | 0-8    | 8-40             | 40-48      | 48        |
 * +--------+------------------+------------+-----------+
 * |VAULT_01| authority        | balance    | is_locked |
 * +--------+------------------+------------+-----------+
 *
 * UserProfile account:
 * +--------+------------------+------------+-----------+
 * | 0-8    | 8-40             | 40-48      | 48        |
 * +--------+------------------+------------+-----------+
 * |PROFILE1| owner            | points     | is_premium|
 * +--------+------------------+------------+-----------+
 *          ↑                  ↑
 *          SAME OFFSET!       SAME OFFSET!
 *
 * Without discriminator check, program can't tell them apart!
 *
 * ============================================================================
 */
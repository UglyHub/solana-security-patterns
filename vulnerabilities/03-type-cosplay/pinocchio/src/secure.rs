//! # SECURE Implementation - Proper Type Verification
//!
//! ✅ This code demonstrates the CORRECT way to prevent type cosplay in Pinocchio.
//!
//! ## The Fix
//!
//! This implementation checks the discriminator (bytes 0-8) BEFORE reading any
//! type-specific data. This ensures we're working with the correct account type.
//!
//! ## Security Guarantees
//!
//! 1. We verify `data[0..8] == VAULT_DISCRIMINATOR` FIRST
//! 2. If an attacker passes UserProfile, discriminator won't match
//! 3. Transaction fails before any sensitive operations
//! 4. Attack prevented!

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, ID,
};

/// ✅ SECURE: Withdraw with discriminator verification
///
/// ## Expected Accounts
///
/// | Index | Writable | Description            |
/// |-------|----------|------------------------|
/// | 0     | Yes      | Vault (VERIFIED!)      |
/// | 1     | No       | Authority (signer)     |
/// | 2     | Yes      | Destination            |
///
/// ## Security Checks (in order)
///
/// 1. ✅ Authority signed
/// 2. ✅ Vault owned by this program
/// 3. ✅ Discriminator matches VAULT_DISCRIMINATOR
/// 4. ✅ Authority matches vault.authority
/// 5. ✅ Vault not locked
/// 6. ✅ Sufficient balance
pub fn withdraw_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    let destination = &accounts[2];
    
    // ✅ CHECK #1: Verify signer
    if !authority.is_signer() {
        pinocchio::msg!("❌ Authority must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ✅ CHECK #2: Verify owner
    if !vault.is_owned_by(&ID) {
        pinocchio::msg!("❌ Vault not owned by this program");
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let data = vault.try_borrow_data()?;
    
    // Check data length
    if data.len() < crate::ACCOUNT_SIZE {
        pinocchio::msg!("❌ Account too small");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ CHECK #3: VERIFY DISCRIMINATOR (THE KEY FIX!)
    //
    // This is what prevents type cosplay:
    // - Vault has discriminator: "VAULT_01"
    // - UserProfile has discriminator: "PROFILE1"
    // - If attacker passes UserProfile, this check FAILS
    //
    // Attack scenario:
    // 1. Attacker passes UserProfile (discriminator = "PROFILE1")
    // 2. We check: "PROFILE1" == "VAULT_01" ?
    // 3. NO! Check fails.
    // 4. Return error, attack prevented!
    if data[0..8] != VAULT_DISCRIMINATOR {
        pinocchio::msg!("❌ Invalid discriminator - this is not a Vault!");
        pinocchio::msg!("❌ Expected: {:?}", VAULT_DISCRIMINATOR);
        pinocchio::msg!("❌ Got: {:?}", &data[0..8]);
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ Now we KNOW this is a Vault
    // Safe to read Vault-specific fields
    
    // ✅ CHECK #4: Verify authority
    let vault_authority = read_pubkey(&data, offsets::AUTHORITY);
    if authority.key() != &vault_authority {
        pinocchio::msg!("❌ Authority mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ CHECK #5: Verify not locked
    let is_locked = data[offsets::FLAGS] != 0;
    if is_locked {
        pinocchio::msg!("❌ Vault is locked");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ CHECK #6: Verify balance
    let balance = read_u64(&data, offsets::BALANCE);
    if balance < amount {
        pinocchio::msg!("❌ Insufficient balance");
        return Err(ProgramError::InsufficientFunds);
    }
    
    drop(data);
    
    // ✅ ALL CHECKS PASSED - Safe to proceed
    
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
    
    pinocchio::msg!("✅ SECURE: Withdrew {} lamports from verified Vault", amount);
    pinocchio::msg!("✅ Discriminator verified");
    
    Ok(())
}

/// ✅ Create a Vault with proper discriminator
pub fn create_vault(accounts: &[AccountInfo]) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    let mut data = vault.try_borrow_mut_data()?;
    
    // ✅ Write discriminator FIRST
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    
    // Write authority
    data[8..40].copy_from_slice(authority.key().as_ref());
    
    // Initialize balance to 0
    write_u64(&mut data, offsets::BALANCE, 0);
    
    // Not locked
    data[offsets::FLAGS] = 0;
    
    pinocchio::msg!("✅ Vault created with discriminator: {:?}", VAULT_DISCRIMINATOR);
    pinocchio::msg!("✅ Authority: {:?}", authority.key());
    
    Ok(())
}

/*
 * ============================================================================
 * PINOCCHIO DISCRIMINATOR BEST PRACTICES
 * ============================================================================
 *
 * 1. DEFINE UNIQUE DISCRIMINATORS
 *    ```rust
 *    pub const VAULT_DISCRIMINATOR: [u8; 8] = *b"VAULT_01";
 *    pub const USER_DISCRIMINATOR: [u8; 8] = *b"USER__01";
 *    pub const POOL_DISCRIMINATOR: [u8; 8] = *b"POOL__01";
 *    ```
 *    Use readable ASCII for debugging, or use hashes for security.
 *
 * 2. CHECK DISCRIMINATOR FIRST
 *    ```rust
 *    let data = account.try_borrow_data()?;
 *    if data[0..8] != EXPECTED_DISCRIMINATOR {
 *        return Err(ProgramError::InvalidAccountData);
 *    }
 *    // Now safe to read type-specific fields
 *    ```
 *
 * 3. WRITE DISCRIMINATOR ON CREATION
 *    ```rust
 *    let mut data = new_account.try_borrow_mut_data()?;
 *    data[0..8].copy_from_slice(&MY_DISCRIMINATOR);
 *    // Write remaining fields
 *    ```
 *
 * 4. USE UNIQUE LAYOUTS WHERE POSSIBLE
 *    Even with discriminators, consider making types have different sizes
 *    or field orders as defense in depth.
 *
 * ============================================================================
 * VERIFICATION ORDER
 * ============================================================================
 *
 * Always check in this order:
 *
 * 1. Signer verification (if required)
 * 2. Owner verification (is_owned_by)
 * 3. Discriminator verification (type check)
 * 4. Field-level validation
 * 5. Business logic
 *
 * Don't skip step 3! That's what this vulnerability is about.
 *
 * ============================================================================
 */
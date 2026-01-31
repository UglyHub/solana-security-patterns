//! # SECURE Implementation - Reinitialization Prevention
//!
//! ✅ This code demonstrates the CORRECT way to prevent reinitialization
//! in Pinocchio.
//!
//! ## Methods Demonstrated
//!
//! 1. Check `is_initialized` flag before writing
//! 2. Check discriminator (if non-zero, account is initialized)
//! 3. Check for non-default authority
//!
//! ## The Key Principle
//!
//! Always check BEFORE writing. If account shows signs of initialization,
//! reject the transaction.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, DEFAULT_PUBKEY, ID,
};

/// ✅ SECURE: Initialize with is_initialized flag check
///
/// ## Expected Accounts
///
/// | Index | Writable | Description    |
/// |-------|----------|----------------|
/// | 0     | Yes      | Vault account  |
/// | 1     | No       | Authority      |
///
/// ## Security Checks
///
/// 1. ✅ Authority signed
/// 2. ✅ Vault owned by program
/// 3. ✅ is_initialized flag is 0 (not yet initialized)
pub fn initialize_secure_flag(accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    // Check signer
    if !authority.is_signer() {
        pinocchio::msg!("❌ Authority must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Check owner
    if !vault.is_owned_by(&ID) {
        pinocchio::msg!("❌ Vault not owned by program");
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // Borrow data to check initialization
    let data = vault.try_borrow_data()?;
    
    // ✅ SECURITY CHECK: Verify not already initialized
    if data[offsets::IS_INITIALIZED] != 0 {
        pinocchio::msg!("❌ Error: Vault is already initialized");
        pinocchio::msg!("❌ Reinitialization attempt blocked!");
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    drop(data);
    
    // ✅ SAFE: Account is not initialized, proceed
    let mut data = vault.try_borrow_mut_data()?;
    
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[offsets::IS_INITIALIZED] = 1;  // ✅ Set flag FIRST
    data[offsets::AUTHORITY..offsets::AUTHORITY + 32]
        .copy_from_slice(authority.key().as_ref());
    write_u64(&mut data, offsets::BALANCE, 0);
    data[offsets::BUMP] = 0;
    
    pinocchio::msg!("✅ SECURE: Vault initialized");
    pinocchio::msg!("✅ Authority: {:?}", authority.key());
    pinocchio::msg!("✅ is_initialized flag prevents re-initialization");
    
    Ok(())
}

/// ✅ SECURE: Initialize with discriminator check
///
/// Uses discriminator presence to detect initialization.
/// If discriminator matches, account was already initialized.
pub fn initialize_secure_discriminator(accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    if !vault.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let data = vault.try_borrow_data()?;
    
    // ✅ SECURITY CHECK: If discriminator is already set, account is initialized
    //
    // This works because:
    // - New accounts have zeroed data
    // - Our discriminator is non-zero
    // - If discriminator matches, we wrote it previously
    if data[0..8] == VAULT_DISCRIMINATOR {
        pinocchio::msg!("❌ Error: Vault already has discriminator set");
        pinocchio::msg!("❌ Reinitialization attempt blocked!");
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    drop(data);
    
    // ✅ SAFE: Discriminator not set, account is fresh
    let mut data = vault.try_borrow_mut_data()?;
    
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[offsets::IS_INITIALIZED] = 1;
    data[offsets::AUTHORITY..offsets::AUTHORITY + 32]
        .copy_from_slice(authority.key().as_ref());
    write_u64(&mut data, offsets::BALANCE, 0);
    data[offsets::BUMP] = 0;
    
    pinocchio::msg!("✅ SECURE: Vault initialized (discriminator check)");
    
    Ok(())
}

/// ✅ SECURE: Initialize with authority check
///
/// Uses non-default authority to detect initialization.
pub fn initialize_secure_authority(accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    if !vault.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let data = vault.try_borrow_data()?;
    
    // ✅ SECURITY CHECK: If authority is non-zero, account was initialized
    let current_authority = read_pubkey(&data, offsets::AUTHORITY);
    
    if current_authority != DEFAULT_PUBKEY {
        pinocchio::msg!("❌ Error: Vault already has an authority");
        pinocchio::msg!("❌ Current authority: {:?}", current_authority);
        pinocchio::msg!("❌ Reinitialization attempt blocked!");
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    
    drop(data);
    
    // ✅ SAFE: Authority is zero/default, account is fresh
    let mut data = vault.try_borrow_mut_data()?;
    
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[offsets::IS_INITIALIZED] = 1;
    data[offsets::AUTHORITY..offsets::AUTHORITY + 32]
        .copy_from_slice(authority.key().as_ref());
    write_u64(&mut data, offsets::BALANCE, 0);
    data[offsets::BUMP] = 0;
    
    pinocchio::msg!("✅ SECURE: Vault initialized (authority check)");
    
    Ok(())
}

/// ✅ SECURE: Deposit to initialized vault
pub fn deposit_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    let data = vault.try_borrow_data()?;
    
    // Verify initialized
    if data[offsets::IS_INITIALIZED] == 0 {
        pinocchio::msg!("❌ Vault not initialized");
        return Err(ProgramError::UninitializedAccount);
    }
    
    // Verify authority
    let vault_authority = read_pubkey(&data, offsets::AUTHORITY);
    if authority.key() != &vault_authority {
        pinocchio::msg!("❌ Invalid authority");
        return Err(ProgramError::InvalidAccountData);
    }
    
    let current_balance = read_u64(&data, offsets::BALANCE);
    drop(data);
    
    // Update balance
    let mut data = vault.try_borrow_mut_data()?;
    let new_balance = current_balance
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    write_u64(&mut data, offsets::BALANCE, new_balance);
    
    pinocchio::msg!("✅ Deposited {} lamports", amount);
    pinocchio::msg!("✅ New balance: {}", new_balance);
    pinocchio::msg!("✅ Protected by initialization check");
    
    Ok(())
}

/*
 * ============================================================================
 * PINOCCHIO REINITIALIZATION PREVENTION CHECKLIST
 * ============================================================================
 *
 * For EVERY initialization function:
 *
 * □ 1. Choose a detection method:
 *      a) is_initialized flag (most explicit)
 *      b) Discriminator presence (if using discriminators)
 *      c) Non-default field values (works for pubkeys)
 *
 * □ 2. Check BEFORE writing any data:
 *      ```rust
 *      let data = account.try_borrow_data()?;
 *      if data[IS_INIT_OFFSET] != 0 {
 *          return Err(ProgramError::AccountAlreadyInitialized);
 *      }
 *      drop(data);
 *      ```
 *
 * □ 3. Set the detection marker FIRST when initializing:
 *      ```rust
 *      let mut data = account.try_borrow_mut_data()?;
 *      data[IS_INIT_OFFSET] = 1;  // Set flag first!
 *      // Then set other fields...
 *      ```
 *
 * □ 4. Document the initialization check in comments
 *
 * □ 5. Test that calling initialize twice fails
 *
 * ============================================================================
 * COMPARISON OF METHODS
 * ============================================================================
 *
 * | Method | Pros | Cons |
 * |--------|------|------|
 * | is_initialized flag | Explicit, clear | Uses 1 byte |
 * | Discriminator check | No extra space | Assumes discriminator non-zero |
 * | Non-default field | No extra space | Only works for some fields |
 *
 * Recommendation: Use is_initialized flag for clarity.
 *
 * ============================================================================
 */
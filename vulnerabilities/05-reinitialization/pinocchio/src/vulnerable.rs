//! # VULNERABLE Implementation - Reinitialization Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation writes to the vault account without checking if it
//! was already initialized. An attacker can call initialize multiple times
//! to overwrite the authority and take control.
//!
//! ## What's Missing
//!
//! ```rust
//! // This check is MISSING:
//! if data[offsets::IS_INITIALIZED] != 0 {
//!     return Err(ProgramError::AccountAlreadyInitialized);
//! }
//! ```

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    write_u64,
    offsets, VAULT_DISCRIMINATOR, ID,
};

/// ❌ VULNERABLE: Initialize without checking existing state
///
/// ## Expected Accounts
///
/// | Index | Writable | Description    |
/// |-------|----------|----------------|
/// | 0     | Yes      | Vault account  |
/// | 1     | No       | Authority      |
///
/// ## Security Flaw
///
/// No check for existing initialization - can be called multiple times!
pub fn initialize_vulnerable(accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    // Verify signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Verify owner (still vulnerable even with this check!)
    if !vault.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let mut data = vault.try_borrow_mut_data()?;
    
    // ❌ MISSING: Initialization check!
    //
    // We should check:
    // if data[offsets::IS_INITIALIZED] != 0 {
    //     return Err(ProgramError::AccountAlreadyInitialized);
    // }
    //
    // Or check discriminator:
    // if data[0..8] == VAULT_DISCRIMINATOR {
    //     return Err(ProgramError::AccountAlreadyInitialized);
    // }
    //
    // Without this check, anyone can overwrite existing data!
    
    // ❌ WRITES WITHOUT CHECKING - Overwrites existing data!
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[offsets::IS_INITIALIZED] = 1;
    data[offsets::AUTHORITY..offsets::AUTHORITY + 32]
        .copy_from_slice(authority.key().as_ref());
    write_u64(&mut data, offsets::BALANCE, 0);
    data[offsets::BUMP] = 0;
    
    pinocchio::msg!("⚠️ VULNERABLE: Vault initialized (or RE-initialized!)");
    pinocchio::msg!("⚠️ Authority set to: {:?}", authority.key());
    pinocchio::msg!("⚠️ No check for existing initialization!");
    
    Ok(())
}

/// ❌ VULNERABLE: Deposit that can be wiped by reinitialization
pub fn deposit_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    let mut data = vault.try_borrow_mut_data()?;
    
    // Read current balance
    let current_balance = read_u64(&data, offsets::BALANCE);
    
    // Update balance
    let new_balance = current_balance
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    write_u64(&mut data, offsets::BALANCE, new_balance);
    
    pinocchio::msg!("Deposited {} lamports", amount);
    pinocchio::msg!("New balance: {}", new_balance);
    pinocchio::msg!("⚠️ This balance can be WIPED by reinitialization!");
    
    Ok(())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/*
 * ============================================================================
 * ATTACK WALKTHROUGH
 * ============================================================================
 *
 * Step 1: Alice initializes her vault
 * ---------------------------------
 * initialize_vulnerable(vault, alice)
 * 
 * Vault state:
 * - authority: Alice
 * - balance: 0
 * - is_initialized: 1
 *
 * Step 2: Alice deposits 100 SOL
 * -----------------------------
 * deposit_vulnerable(vault, alice, 100 SOL)
 *
 * Vault state:
 * - authority: Alice
 * - balance: 100 SOL
 * - is_initialized: 1
 *
 * Step 3: Attacker reinitializes the vault!
 * ----------------------------------------
 * initialize_vulnerable(vault, attacker)
 *
 * Vault state AFTER attack:
 * - authority: ATTACKER ❌ (overwritten!)
 * - balance: 0 ❌ (reset!)
 * - is_initialized: 1
 *
 * Step 4: Attacker withdraws lamports
 * ----------------------------------
 * The vault account still has 100 SOL in lamports.
 * Attacker is now the authority.
 * Attacker withdraws everything.
 *
 * Result: Alice loses 100 SOL!
 *
 * ============================================================================
 */
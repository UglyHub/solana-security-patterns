//! # VULNERABLE Implementation - PDA Substitution Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation accepts any vault PDA without verifying it was derived
//! from the expected seeds. It only checks:
//! - Owner is this program ✓
//! - Discriminator matches ✓
//! - Authority matches signer ✓
//!
//! It does NOT check:
//! - Vault address == derive(["vault", authority], program_id) ✗
//!
//! An attacker can create their own vault and substitute it!

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, ID,
};

/// ❌ VULNERABLE: Withdraw without PDA verification
///
/// ## Expected Accounts
///
/// | Index | Writable | Description                    |
/// |-------|----------|--------------------------------|
/// | 0     | Yes      | Vault PDA (NOT VERIFIED!)      |
/// | 1     | No       | Authority (signer)             |
/// | 2     | Yes      | Destination                    |
///
/// ## Security Flaw
///
/// We verify authority matches vault.authority, but we don't verify
/// the vault was derived from ["vault", authority] seeds.
pub fn withdraw_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    let destination = &accounts[2];
    
    // Check signer
    if !authority.is_signer() {
        pinocchio::msg!("Authority must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Check owner
    if !vault.is_owned_by(&ID) {
        pinocchio::msg!("Vault not owned by program");
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let data = vault.try_borrow_data()?;
    
    // Check discriminator
    if data[..8] != VAULT_DISCRIMINATOR {
        pinocchio::msg!("Invalid discriminator");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Check authority matches
    let vault_authority = read_pubkey(&data, offsets::AUTHORITY);
    if authority.key() != &vault_authority {
        pinocchio::msg!("Authority mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ❌ MISSING: PDA verification!
    //
    // We should check:
    // let bump = data[offsets::BUMP];
    // let expected_pda = Pubkey::create_program_address(
    //     &[VAULT_SEED, authority.key().as_ref(), &[bump]],
    //     &ID
    // )?;
    // if vault.key() != &expected_pda {
    //     return Err(ProgramError::InvalidSeeds);
    // }
    //
    // Without this, attacker can pass ANY vault they control!
    
    let balance = read_u64(&data, offsets::BALANCE);
    if balance < amount {
        pinocchio::msg!("Insufficient balance");
        return Err(ProgramError::InsufficientFunds);
    }
    
    drop(data);
    
    // ❌ PROCEEDING WITH UNVERIFIED VAULT!
    
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
    pinocchio::msg!("⚠️ PDA seeds were NOT verified!");
    
    Ok(())
}

/*
 * ============================================================================
 * ATTACK SCENARIO
 * ============================================================================
 *
 * Protocol Design:
 * - Each user gets ONE vault at PDA["vault", user_pubkey]
 * - Users deposit and withdraw from their vault
 *
 * Attack:
 *
 * 1. Attacker creates vault at PDA["vault", attacker_pubkey]
 *    (This is a legitimate vault for the attacker)
 *
 * 2. Protocol has some function that:
 *    - Takes a vault account
 *    - Reads/writes data based on external state
 *
 * 3. Attacker calls vulnerable function with their vault
 *    - Owner check: ✓ (owned by program)
 *    - Discriminator: ✓ (is a vault)
 *    - Authority: ✓ (attacker is authority of attacker's vault)
 *    - PDA seeds: NOT CHECKED!
 *
 * 4. If function reads from external state expecting victim's vault,
 *    but actually modifies attacker's vault, state becomes inconsistent.
 *
 * Or more simply:
 *
 * If function should ONLY work with PDA["vault", signer]:
 * - Victim's vault: PDA["vault", victim]
 * - Attacker's vault: PDA["vault", attacker]
 * - These are DIFFERENT addresses
 * - Without PDA verification, protocol doesn't know which is which!
 *
 * ============================================================================
 */
//! # SECURE Implementation - Proper PDA Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify PDAs in Pinocchio.
//!
//! ## The Fix
//!
//! This implementation manually derives the expected PDA and compares it
//! to the actual account address:
//!
//! ```rust
//! let expected_pda = Pubkey::create_program_address(
//!     &[b"vault", authority.key().as_ref(), &[bump]],
//!     &program_id
//! )?;
//!
//! if vault.key() != &expected_pda {
//!     return Err(ProgramError::InvalidSeeds);
//! }
//! ```
//!
//! ## Why create_program_address vs find_program_address?
//!
//! - `find_program_address`: Searches for valid bump (expensive, ~10k CU)
//! - `create_program_address`: Uses provided bump (cheap, ~100 CU)
//!
//! We store the bump in the account and use `create_program_address`.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, VAULT_SEED, ID,
};

/// ✅ SECURE: Withdraw with PDA verification
///
/// ## Expected Accounts
///
/// | Index | Writable | Description                    |
/// |-------|----------|--------------------------------|
/// | 0     | Yes      | Vault PDA (VERIFIED!)          |
/// | 1     | No       | Authority (signer)             |
/// | 2     | Yes      | Destination                    |
///
/// ## Security Checks (in order)
///
/// 1. ✅ Authority signed
/// 2. ✅ Vault owned by this program
/// 3. ✅ Vault discriminator correct
/// 4. ✅ Vault PDA == derive(["vault", authority], program_id)
/// 5. ✅ Vault authority matches signer
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
        pinocchio::msg!("❌ Vault not owned by program");
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let data = vault.try_borrow_data()?;
    
    // ✅ CHECK #3: Verify discriminator
    if data[..8] != VAULT_DISCRIMINATOR {
        pinocchio::msg!("❌ Invalid discriminator");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Read bump from account (stored on initialization)
    let bump = data[offsets::BUMP];
    
    // ✅ CHECK #4: VERIFY PDA DERIVATION (THE KEY FIX!)
    //
    // Derive expected PDA from seeds + program_id
    // Compare to actual vault address
    //
    // Attack prevention:
    // - Expected: PDA(["vault", authority], program_id)
    // - Attacker's vault: PDA(["vault", attacker], program_id)
    // - If authority != attacker, these are DIFFERENT addresses
    // - Check fails, attack prevented!
    let seeds: &[&[u8]] = &[
        VAULT_SEED,
        authority.key().as_ref(),
        &[bump],
    ];
    
    let expected_pda = Pubkey::create_program_address(seeds, &ID)
        .map_err(|_| {
            pinocchio::msg!("❌ Failed to derive PDA");
            ProgramError::InvalidSeeds
        })?;
    
    if vault.key() != &expected_pda {
        pinocchio::msg!("❌ Invalid PDA - seeds don't match");
        pinocchio::msg!("❌ Expected: {:?}", expected_pda);
        pinocchio::msg!("❌ Got: {:?}", vault.key());
        return Err(ProgramError::InvalidSeeds);
    }
    
    // ✅ CHECK #5: Verify authority (belt and suspenders)
    let vault_authority = read_pubkey(&data, offsets::AUTHORITY);
    if authority.key() != &vault_authority {
        pinocchio::msg!("❌ Authority mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ CHECK #6: Verify balance
    let balance = read_u64(&data, offsets::BALANCE);
    if balance < amount {
        pinocchio::msg!("❌ Insufficient balance");
        return Err(ProgramError::InsufficientFunds);
    }
    
    drop(data);
    
    // ✅ ALL CHECKS PASSED - This is THE vault for this authority
    
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
    
    pinocchio::msg!("✅ SECURE: Withdrew {} lamports from verified vault", amount);
    pinocchio::msg!("✅ PDA verified: [\"vault\", authority, bump]");
    
    Ok(())
}

/// ✅ Initialize vault at correct PDA
pub fn initialize_vault(accounts: &[AccountInfo], bump: u8) -> ProgramResult {
    let vault = &accounts[0];
    let authority = &accounts[1];
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ✅ Verify PDA before writing
    let seeds: &[&[u8]] = &[
        VAULT_SEED,
        authority.key().as_ref(),
        &[bump],
    ];
    
    let expected_pda = Pubkey::create_program_address(seeds, &ID)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    
    if vault.key() != &expected_pda {
        pinocchio::msg!("❌ Vault address doesn't match expected PDA");
        return Err(ProgramError::InvalidSeeds);
    }
    
    let mut data = vault.try_borrow_mut_data()?;
    
    // Write discriminator
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    
    // Write authority
    data[8..40].copy_from_slice(authority.key().as_ref());
    
    // Initialize balance to 0
    write_u64(&mut data, offsets::BALANCE, 0);
    
    // ✅ Store bump for future verification (saves compute)
    data[offsets::BUMP] = bump;
    
    pinocchio::msg!("✅ Vault initialized at verified PDA");
    pinocchio::msg!("✅ Seeds: [\"vault\", {:?}, {}]", authority.key(), bump);
    
    Ok(())
}

/*
 * ============================================================================
 * PINOCCHIO PDA VERIFICATION CHECKLIST
 * ============================================================================
 *
 * For EVERY PDA account:
 *
 * □ 1. Define seed pattern in constants/documentation
 *      ```rust
 *      pub const VAULT_SEED: &[u8] = b"vault";
 *      // PDA = ["vault", user_pubkey, bump]
 *      ```
 *
 * □ 2. Store bump in account on initialization
 *      ```rust
 *      data[BUMP_OFFSET] = bump;
 *      ```
 *
 * □ 3. Verify PDA on every instruction that uses it
 *      ```rust
 *      let bump = data[BUMP_OFFSET];
 *      let expected = Pubkey::create_program_address(
 *          &[SEED, user.key().as_ref(), &[bump]],
 *          &program_id
 *      )?;
 *      if account.key() != &expected {
 *          return Err(ProgramError::InvalidSeeds);
 *      }
 *      ```
 *
 * □ 4. Document expected seeds in function comments
 *
 * ============================================================================
 * find_program_address vs create_program_address
 * ============================================================================
 *
 * find_program_address:
 * - Searches for valid bump (255 down to 0)
 * - Returns (pda, bump)
 * - EXPENSIVE: ~10,000 compute units
 * - Use: When you don't know the bump
 *
 * create_program_address:
 * - Uses exact seeds including bump
 * - Returns Result<Pubkey>
 * - CHEAP: ~100 compute units
 * - Use: When bump is stored in account
 *
 * Best practice:
 * 1. On init: Use find_program_address to get bump, store it
 * 2. On use: Read stored bump, use create_program_address
 *
 * ============================================================================
 */
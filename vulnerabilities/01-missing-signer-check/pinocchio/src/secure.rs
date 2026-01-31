//! # SECURE Implementation - Proper Signer Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify signers in Pinocchio.
//!
//! ## The Fix
//! 
//! This implementation explicitly calls `is_signer()` on the authority account
//! BEFORE performing any privileged actions. This ensures only the actual
//! holder of the private key can authorize withdrawals.
//!
//! ## Security Guarantees
//! 
//! 1. We call `authority.is_signer()` to verify cryptographic signature
//! 2. We verify the signer matches the vault's stored authority
//! 3. Both checks must pass before any funds are transferred
//! 4. Order matters: check signer FIRST, before any state reads
//!
//! ## Pinocchio vs Anchor
//! 
//! | Aspect | Anchor | Pinocchio |
//! |--------|--------|-----------|
//! | Check | `Signer<'info>` type | `is_signer()` method |
//! | When | Automatic at deserialization | Manual in instruction |
//! | Forget? | Compile error | Runtime vulnerability |

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, ID,
};

/// ✅ SECURE: Withdraw with proper signer verification
/// 
/// ## Expected Accounts
/// 
/// | Index | Writable | Signer | Description                    |
/// |-------|----------|--------|--------------------------------|
/// | 0     | Yes      | No     | Vault account                  |
/// | 1     | No       | YES!   | Authority (MUST sign!)         |
/// | 2     | Yes      | No     | Destination for funds          |
///
/// ## Security Checks (in order)
/// 
/// 1. ✅ Verify authority signed the transaction
/// 2. ✅ Verify vault discriminator (prevents type confusion)
/// 3. ✅ Verify vault is owned by this program
/// 4. ✅ Verify signer is the vault's authority
/// 5. ✅ Verify sufficient balance
pub fn withdraw_secure(
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    // === ACCOUNT PARSING ===
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    let destination = &accounts[2];
    
    // === SECURITY CHECK #1: SIGNER VERIFICATION ===
    // 
    // ✅ THIS IS THE CRITICAL FIX!
    // 
    // We check is_signer() FIRST, before any other logic.
    // This ensures the authority account actually signed the transaction.
    // 
    // How it works:
    // - The Solana runtime sets is_signer=true for accounts that signed
    // - This flag is cryptographically verified by the runtime
    // - We just need to check it!
    // 
    // Without the private key, an attacker CANNOT set is_signer=true.
    if !authority.is_signer() {
        pinocchio::msg!("❌ Error: Authority must sign the transaction");
        pinocchio::msg!("❌ Provided authority: {:?}", authority.key());
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // === SECURITY CHECK #2: VAULT OWNER ===
    // 
    // Verify the vault account is owned by this program.
    // Prevents attackers from passing fake accounts.
    if !vault.is_owned_by(&ID) {
        pinocchio::msg!("❌ Error: Vault not owned by this program");
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // === SECURITY CHECK #3: DISCRIMINATOR ===
    let vault_data = vault.try_borrow_data()?;
    
    if vault_data[..8] != VAULT_DISCRIMINATOR {
        pinocchio::msg!("❌ Error: Invalid vault discriminator");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // === SECURITY CHECK #4: AUTHORITY MATCH ===
    // 
    // Verify the SIGNER is the vault's designated authority.
    // We know they signed (check #1), now verify they're authorized.
    let vault_authority = read_pubkey(&vault_data, offsets::AUTHORITY);
    
    if authority.key() != &vault_authority {
        pinocchio::msg!("❌ Error: Signer is not the vault authority");
        pinocchio::msg!("❌ Expected: {:?}", vault_authority);
        pinocchio::msg!("❌ Got: {:?}", authority.key());
        return Err(ProgramError::InvalidAccountData);
    }
    
    // === SECURITY CHECK #5: BALANCE ===
    let balance = read_u64(&vault_data, offsets::BALANCE);
    
    if balance < amount {
        pinocchio::msg!("❌ Error: Insufficient funds");
        pinocchio::msg!("❌ Requested: {}, Available: {}", amount, balance);
        return Err(ProgramError::InsufficientFunds);
    }
    
    drop(vault_data);
    
    // === SAFE ZONE ===
    // 
    // ✅ At this point, we have verified:
    // 1. Authority signed the transaction (cryptographic proof)
    // 2. Vault is owned by this program (can't be fake)
    // 3. Vault has correct discriminator (correct type)
    // 4. Signer matches vault.authority (authorized user)
    // 5. Sufficient balance exists
    //
    // It is now SAFE to transfer funds.
    
    // Update vault balance
    let mut vault_data = vault.try_borrow_mut_data()?;
    write_u64(&mut vault_data, offsets::BALANCE, balance - amount);
    drop(vault_data);
    
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
    
    pinocchio::msg!("✅ SECURE: Withdrew {} lamports", amount);
    pinocchio::msg!("✅ Authorized by verified signer: {:?}", authority.key());
    
    Ok(())
}

/*
 * ============================================================================
 * PINOCCHIO SIGNER VERIFICATION CHECKLIST
 * ============================================================================
 * 
 * For EVERY function that requires authorization:
 * 
 * □ 1. Identify which accounts must sign
 *      - Who is authorizing this action?
 *      - Could be: authority, owner, admin, payer, etc.
 * 
 * □ 2. Check is_signer() FIRST
 *      - Before reading any data
 *      - Before any state changes
 *      ```rust
 *      if !authority.is_signer() {
 *          return Err(ProgramError::MissingRequiredSignature);
 *      }
 *      ```
 * 
 * □ 3. Verify signer identity
 *      - Signer must match expected pubkey
 *      ```rust
 *      if authority.key() != &expected_authority {
 *          return Err(ProgramError::InvalidAccountData);
 *      }
 *      ```
 * 
 * □ 4. Document signer requirements
 *      - In function comments
 *      - In account table
 * 
 * □ 5. Test both paths
 *      - Valid signer: should succeed
 *      - Invalid/missing signer: should fail
 * 
 * ============================================================================
 * COMPARISON: ANCHOR vs PINOCCHIO SIGNER CHECKS
 * ============================================================================
 * 
 * ANCHOR:
 * ```rust
 * #[derive(Accounts)]
 * pub struct Withdraw<'info> {
 *     #[account(has_one = authority)]
 *     pub vault: Account<'info, Vault>,
 *     pub authority: Signer<'info>,  // Automatic check!
 * }
 * ```
 * - Type system enforces signer
 * - Cannot compile without Signer type
 * - Check happens before instruction runs
 * 
 * PINOCCHIO:
 * ```rust
 * pub fn withdraw(accounts: &[AccountInfo]) -> ProgramResult {
 *     let authority = &accounts[1];
 *     
 *     // Manual check required!
 *     if !authority.is_signer() {
 *         return Err(ProgramError::MissingRequiredSignature);
 *     }
 *     // ...
 * }
 * ```
 * - Developer must remember to check
 * - No compile-time enforcement
 * - Check is in instruction logic
 * 
 * ============================================================================
 */
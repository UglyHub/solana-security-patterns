//! # VULNERABLE Implementation - Integer Overflow Attacks
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! Using direct arithmetic operators (+, -, *, /) without checked methods
//! allows values to wrap silently on overflow/underflow.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, ID,
};

/// ❌ VULNERABLE: Withdraw without underflow protection
pub fn withdraw_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let owner = &accounts[1];
    
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    if !vault.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    let data = vault.try_borrow_data()?;
    
    if data[..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let vault_owner = read_pubkey(&data, offsets::OWNER);
    if owner.key() != &vault_owner {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let balance = read_u64(&data, offsets::BALANCE);
    let total_withdrawn = read_u64(&data, offsets::TOTAL_WITHDRAWN);
    
    drop(data);
    
    // ❌ VULNERABILITY: No underflow check!
    //
    // If amount > balance:
    // - balance - amount wraps to huge number
    // - User gets billions of tokens!
    //
    // Example: 100 - 200 = 18,446,744,073,709,551,516
    let new_balance = balance - amount;
    
    // ❌ VULNERABILITY: No overflow check!
    let new_total = total_withdrawn + amount;
    
    // Write potentially corrupted values
    let mut data = vault.try_borrow_mut_data()?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    write_u64(&mut data, offsets::TOTAL_WITHDRAWN, new_total);
    
    pinocchio::msg!("⚠️ VULNERABLE: Withdrew {}", amount);
    pinocchio::msg!("⚠️ New balance: {} (may have underflowed!)", new_balance);
    
    Ok(())
}

/// ❌ VULNERABLE: Deposit without overflow protection
pub fn deposit_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let owner = &accounts[1];
    
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    let data = vault.try_borrow_data()?;
    let balance = read_u64(&data, offsets::BALANCE);
    let total_deposited = read_u64(&data, offsets::TOTAL_DEPOSITED);
    drop(data);
    
    // ❌ VULNERABILITY: No overflow check!
    //
    // If balance + amount > u64::MAX:
    // - Result wraps to small number
    // - User's balance becomes tiny!
    //
    // Example: u64::MAX + 1 = 0
    let new_balance = balance + amount;
    let new_total = total_deposited + amount;
    
    let mut data = vault.try_borrow_mut_data()?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    write_u64(&mut data, offsets::TOTAL_DEPOSITED, new_total);
    
    pinocchio::msg!("⚠️ VULNERABLE: Deposited {}", amount);
    pinocchio::msg!("⚠️ New balance: {} (may have overflowed!)", new_balance);
    
    Ok(())
}

/// ❌ VULNERABLE: Transfer between accounts
pub fn transfer_vulnerable(
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let from_vault = &accounts[0];
    let to_vault = &accounts[1];
    let owner = &accounts[2];
    
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Read balances
    let from_data = from_vault.try_borrow_data()?;
    let from_balance = read_u64(&from_data, offsets::BALANCE);
    drop(from_data);
    
    let to_data = to_vault.try_borrow_data()?;
    let to_balance = read_u64(&to_data, offsets::BALANCE);
    drop(to_data);
    
    // ❌ BOTH OPERATIONS VULNERABLE!
    let new_from = from_balance - amount;  // Can underflow
    let new_to = to_balance + amount;      // Can overflow
    
    // Write corrupted values
    let mut from_data = from_vault.try_borrow_mut_data()?;
    write_u64(&mut from_data, offsets::BALANCE, new_from);
    drop(from_data);
    
    let mut to_data = to_vault.try_borrow_mut_data()?;
    write_u64(&mut to_data, offsets::BALANCE, new_to);
    
    pinocchio::msg!("⚠️ VULNERABLE: Transferred {}", amount);
    
    Ok(())
}

/// ❌ VULNERABLE: Calculate fee with overflow
pub fn calculate_fee_vulnerable(amount: u64, fee_bps: u64) -> u64 {
    // ❌ VULNERABILITY: Multiplication can overflow!
    //
    // If amount is large, amount * fee_bps > u64::MAX
    // Result wraps to tiny number
    //
    // Attack: Use huge amount to pay tiny fee
    amount * fee_bps / 10000
}

/*
 * ============================================================================
 * DEMONSTRATION OF OVERFLOW VALUES
 * ============================================================================
 *
 * u64::MAX = 18,446,744,073,709,551,615
 *
 * UNDERFLOW EXAMPLES:
 * - 0 - 1 = u64::MAX = 18,446,744,073,709,551,615
 * - 100 - 101 = u64::MAX - 0 = 18,446,744,073,709,551,615
 * - 100 - 200 = u64::MAX - 99 = 18,446,744,073,709,551,516
 *
 * OVERFLOW EXAMPLES:
 * - u64::MAX + 1 = 0
 * - u64::MAX + 100 = 99
 * - (u64::MAX / 2) + (u64::MAX / 2) + 2 = 0
 *
 * MULTIPLICATION OVERFLOW:
 * - 10^10 * 10^10 = 10^20 (overflows u64 which max is ~1.8 * 10^19)
 * - Result wraps to: 10^20 mod (u64::MAX + 1)
 *
 * ============================================================================
 */
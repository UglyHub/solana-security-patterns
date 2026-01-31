//! # SECURE Implementation - Proper Arithmetic Safety
//!
//! ✅ This code demonstrates the CORRECT way to handle arithmetic
//! in Pinocchio programs.
//!
//! ## The Fix
//!
//! Use Rust's checked arithmetic methods:
//! - `checked_add()` returns `Option::None` on overflow
//! - `checked_sub()` returns `Option::None` on underflow
//! - `checked_mul()` returns `Option::None` on overflow
//! - `checked_div()` returns `Option::None` on division by zero
//!
//! Convert `None` to error using `ok_or()`:
//! ```rust
//! let result = a.checked_sub(b).ok_or(ProgramError::ArithmeticOverflow)?;
//! ```

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, ID,
};

/// ✅ SECURE: Withdraw with underflow protection
pub fn withdraw_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
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
        pinocchio::msg!("❌ Invalid owner");
        return Err(ProgramError::InvalidAccountData);
    }
    
    let balance = read_u64(&data, offsets::BALANCE);
    let total_withdrawn = read_u64(&data, offsets::TOTAL_WITHDRAWN);
    
    drop(data);
    
    // ✅ SECURE: checked_sub returns None if underflow
    //
    // If amount > balance:
    // - checked_sub returns None
    // - ok_or converts to InsufficientFunds error
    // - ? returns error, stopping execution
    // - No underflow occurs!
    let new_balance = balance
        .checked_sub(amount)
        .ok_or_else(|| {
            pinocchio::msg!("❌ Underflow prevented: {} - {}", balance, amount);
            ProgramError::InsufficientFunds
        })?;
    
    // ✅ SECURE: checked_add returns None if overflow
    let new_total = total_withdrawn
        .checked_add(amount)
        .ok_or_else(|| {
            pinocchio::msg!("❌ Overflow prevented in total_withdrawn");
            ProgramError::ArithmeticOverflow
        })?;
    
    // Safe to write verified values
    let mut data = vault.try_borrow_mut_data()?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    write_u64(&mut data, offsets::TOTAL_WITHDRAWN, new_total);
    
    pinocchio::msg!("✅ SECURE: Withdrew {} (underflow-protected)", amount);
    pinocchio::msg!("✅ New balance: {}", new_balance);
    
    Ok(())
}

/// ✅ SECURE: Deposit with overflow protection
pub fn deposit_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let owner = &accounts[1];
    
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    let data = vault.try_borrow_data()?;
    
    if data[..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let balance = read_u64(&data, offsets::BALANCE);
    let total_deposited = read_u64(&data, offsets::TOTAL_DEPOSITED);
    drop(data);
    
    // ✅ SECURE: checked_add returns None if overflow
    //
    // If balance + amount > u64::MAX:
    // - checked_add returns None
    // - ok_or converts to ArithmeticOverflow error
    // - No wrap-around occurs!
    let new_balance = balance
        .checked_add(amount)
        .ok_or_else(|| {
            pinocchio::msg!("❌ Overflow prevented: {} + {}", balance, amount);
            ProgramError::ArithmeticOverflow
        })?;
    
    let new_total = total_deposited
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    let mut data = vault.try_borrow_mut_data()?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    write_u64(&mut data, offsets::TOTAL_DEPOSITED, new_total);
    
    pinocchio::msg!("✅ SECURE: Deposited {} (overflow-protected)", amount);
    pinocchio::msg!("✅ New balance: {}", new_balance);
    
    Ok(())
}

/// ✅ SECURE: Transfer between accounts
pub fn transfer_secure(
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
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
    
    // ✅ SECURE: Both operations protected
    let new_from = from_balance
        .checked_sub(amount)
        .ok_or_else(|| {
            pinocchio::msg!("❌ Insufficient balance for transfer");
            ProgramError::InsufficientFunds
        })?;
    
    let new_to = to_balance
        .checked_add(amount)
        .ok_or_else(|| {
            pinocchio::msg!("❌ Recipient balance would overflow");
            ProgramError::ArithmeticOverflow
        })?;
    
    // Safe to write
    let mut from_data = from_vault.try_borrow_mut_data()?;
    write_u64(&mut from_data, offsets::BALANCE, new_from);
    drop(from_data);
    
    let mut to_data = to_vault.try_borrow_mut_data()?;
    write_u64(&mut to_data, offsets::BALANCE, new_to);
    
    pinocchio::msg!("✅ SECURE: Transferred {} (protected)", amount);
    
    Ok(())
}

/// ✅ SECURE: Calculate fee with overflow protection
pub fn calculate_fee_secure(amount: u64, fee_bps: u64) -> Result<u64, ProgramError> {
    // ✅ SECURE: Use checked_mul to catch overflow
    let numerator = amount
        .checked_mul(fee_bps)
        .ok_or_else(|| {
            pinocchio::msg!("❌ Fee calculation overflow: {} * {}", amount, fee_bps);
            ProgramError::ArithmeticOverflow
        })?;
    
    // Division can't overflow, but check for completeness
    let fee = numerator
        .checked_div(10000)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    pinocchio::msg!("✅ SECURE: Fee = {} (overflow-protected)", fee);
    
    Ok(fee)
}

/// ✅ SECURE: Calculate fee using u128 for large values
pub fn calculate_fee_u128(amount: u64, fee_bps: u64) -> Result<u64, ProgramError> {
    // ✅ SECURE: Use u128 for intermediate calculation
    // This handles amounts up to u64::MAX without overflow
    let numerator = (amount as u128)
        .checked_mul(fee_bps as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    
    let result = numerator / 10000u128;
    
    // ✅ SECURE: Verify result fits in u64
    if result > u64::MAX as u128 {
        pinocchio::msg!("❌ Fee result too large for u64");
        return Err(ProgramError::ArithmeticOverflow);
    }
    
    pinocchio::msg!("✅ SECURE: Fee (u128) = {}", result as u64);
    
    Ok(result as u64)
}

/// ✅ Initialize vault
pub fn initialize_vault(accounts: &[AccountInfo], bump: u8) -> ProgramResult {
    let vault = &accounts[0];
    let owner = &accounts[1];
    
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    let mut data = vault.try_borrow_mut_data()?;
    
    // Write all fields
    data[0..8].copy_from_slice(&VAULT_DISCRIMINATOR);
    data[offsets::OWNER..offsets::OWNER + 32].copy_from_slice(owner.key().as_ref());
    write_u64(&mut data, offsets::BALANCE, 0);
    write_u64(&mut data, offsets::TOTAL_DEPOSITED, 0);
    write_u64(&mut data, offsets::TOTAL_WITHDRAWN, 0);
    data[offsets::BUMP] = bump;
    
    pinocchio::msg!("✅ Vault initialized for: {:?}", owner.key());
    
    Ok(())
}

/*
 * ============================================================================
 * PINOCCHIO ARITHMETIC SAFETY CHECKLIST
 * ============================================================================
 *
 * For EVERY arithmetic operation:
 *
 * □ Addition: Use checked_add()
 *   ```rust
 *   let result = a.checked_add(b).ok_or(ProgramError::ArithmeticOverflow)?;
 *   ```
 *
 * □ Subtraction: Use checked_sub()
 *   ```rust
 *   let result = a.checked_sub(b).ok_or(ProgramError::InsufficientFunds)?;
 *   ```
 *
 * □ Multiplication: Use checked_mul() or u128
 *   ```rust
 *   let result = a.checked_mul(b).ok_or(ProgramError::ArithmeticOverflow)?;
 *   // OR
 *   let result = ((a as u128) * (b as u128)) as u64;  // If you verify fits
 *   ```
 *
 * □ Division: Use checked_div()
 *   ```rust
 *   let result = a.checked_div(b).ok_or(ProgramError::ArithmeticOverflow)?;
 *   ```
 *
 * □ Complex calculations: Break into steps, check each
 *   ```rust
 *   let step1 = a.checked_mul(b).ok_or(Error)?;
 *   let step2 = step1.checked_add(c).ok_or(Error)?;
 *   let result = step2.checked_div(d).ok_or(Error)?;
 *   ```
 *
 * ============================================================================
 * TESTING EDGE CASES
 * ============================================================================
 *
 * Always test with:
 * - 0
 * - 1
 * - u64::MAX - 1
 * - u64::MAX
 * - Values that cause exact overflow (MAX - current + 1)
 * - Values that cause exact underflow (current + 1)
 *
 * ============================================================================
 */
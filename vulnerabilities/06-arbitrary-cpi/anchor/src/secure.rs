//! # SECURE Implementation - Proper CPI Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify CPI targets in Anchor.
//!
//! ## The Fix
//!
//! This implementation uses `Program<'info, Token>` which automatically verifies:
//! 1. The account's key matches Token::id() (spl_token program)
//! 2. The account is executable
//!
//! An attacker CANNOT substitute a fake program because the key won't match!
//!
//! ## How Program<T> Works
//!
//! ```rust
//! pub token_program: Program<'info, Token>,
//! ```
//!
//! Anchor generates verification code:
//! ```rust
//! if token_program.key() != &Token::id() {
//!     return Err(ErrorCode::InvalidProgramId);
//! }
//! if !token_program.executable {
//!     return Err(ErrorCode::InvalidProgramExecutable);
//! }
//! ```

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use crate::{UserVault, CPIError};

/// ✅ SECURE: Withdraw with verified token program
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    /// User's vault tracking their balance
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ CPIError::InvalidAuthority
    )]
    pub vault: Account<'info, UserVault>,
    
    /// Token account to withdraw from (protocol's)
    /// Using Account<TokenAccount> also verifies it's a real token account
    #[account(mut)]
    pub token_from: Account<'info, TokenAccount>,
    
    /// Token account to withdraw to (user's)
    #[account(mut)]
    pub token_to: Account<'info, TokenAccount>,
    
    /// PDA authority over the token_from account
    /// CHECK: PDA derived from known seeds
    #[account(
        seeds = [b"authority"],
        bump
    )]
    pub token_authority: AccountInfo<'info>,
    
    /// Vault owner
    pub owner: Signer<'info>,
    
    /// ✅ SECURE: Program<Token> verifies this is the real Token Program!
    /// 
    /// Anchor automatically checks:
    /// - token_program.key() == spl_token::ID
    /// - token_program.executable == true
    ///
    /// If attacker passes FakeTokenProgram:
    /// - FakeTokenProgram.key() != spl_token::ID
    /// - Anchor rejects with InvalidProgramId
    /// - Attack prevented!
    pub token_program: Program<'info, Token>,
}

/// ✅ SECURE: Withdraw with CPI to verified Token Program
pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Check internal balance
    if vault.balance < amount {
        return Err(CPIError::InsufficientBalance.into());
    }
    
    // ✅ By this point, Anchor has verified:
    // - token_program.key() == Token::id() (spl_token)
    // - token_program is executable
    // - token_from and token_to are real TokenAccounts
    
    // Build CPI context
    let cpi_accounts = Transfer {
        from: ctx.accounts.token_from.to_account_info(),
        to: ctx.accounts.token_to.to_account_info(),
        authority: ctx.accounts.token_authority.to_account_info(),
    };
    
    // Get PDA signer seeds
    let seeds = &[b"authority".as_ref(), &[ctx.bumps.token_authority]];
    let signer_seeds = &[&seeds[..]];
    
    // ✅ SAFE: CPI to verified Token Program
    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );
    
    token::transfer(cpi_ctx, amount)?;
    
    // ✅ SAFE: Token Program verified, transfer actually happened
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(CPIError::ArithmeticOverflow)?;
    
    vault.total_withdrawn = vault.total_withdrawn
        .checked_add(amount)
        .ok_or(CPIError::ArithmeticOverflow)?;
    
    msg!("✅ SECURE: Withdrew {} tokens", amount);
    msg!("✅ Token program verified: {}", ctx.accounts.token_program.key());
    
    Ok(())
}

/// ✅ SECURE: Initialize vault
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = owner,
        space = UserVault::SIZE,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, UserVault>,
    
    /// Mint for this vault
    pub mint: Account<'info, anchor_spl::token::Mint>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.owner = ctx.accounts.owner.key();
    vault.mint = ctx.accounts.mint.key();
    vault.balance = 0;
    vault.total_withdrawn = 0;
    vault.bump = ctx.bumps.vault;
    
    msg!("✅ Vault initialized for owner: {}", vault.owner);
    Ok(())
}

/// ✅ SECURE: Deposit with verified token program
#[derive(Accounts)]
pub struct DepositSecure<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ CPIError::InvalidAuthority
    )]
    pub vault: Account<'info, UserVault>,
    
    #[account(mut)]
    pub token_from: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub token_to: Account<'info, TokenAccount>,
    
    pub owner: Signer<'info>,
    
    /// ✅ SECURE: Verified token program
    pub token_program: Program<'info, Token>,
}

pub fn deposit_secure(ctx: Context<DepositSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ CPI to verified Token Program
    let cpi_accounts = Transfer {
        from: ctx.accounts.token_from.to_account_info(),
        to: ctx.accounts.token_to.to_account_info(),
        authority: ctx.accounts.owner.to_account_info(),
    };
    
    let cpi_ctx = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
    );
    
    token::transfer(cpi_ctx, amount)?;
    
    // Update internal tracking
    vault.balance = vault.balance
        .checked_add(amount)
        .ok_or(CPIError::ArithmeticOverflow)?;
    
    msg!("✅ Deposited {} tokens", amount);
    Ok(())
}

/*
 * ============================================================================
 * ANCHOR PROGRAM TYPE VERIFICATION
 * ============================================================================
 *
 * When you use Program<'info, Token>:
 *
 * 1. Anchor looks up Token::id():
 *    ```rust
 *    impl anchor_lang::Id for Token {
 *        fn id() -> Pubkey {
 *            spl_token::ID  // The real Token Program ID
 *        }
 *    }
 *    ```
 *
 * 2. Anchor generates verification code:
 *    ```rust
 *    // Check program ID
 *    if token_program.key() != &Token::id() {
 *        return Err(ErrorCode::InvalidProgramId.into());
 *    }
 *    
 *    // Check executable
 *    if !token_program.executable {
 *        return Err(ErrorCode::InvalidProgramExecutable.into());
 *    }
 *    ```
 *
 * 3. Attack is prevented:
 *    - Attacker passes FakeTokenProgram
 *    - FakeTokenProgram.key() != spl_token::ID
 *    - Verification fails
 *    - Transaction rejected
 *
 * ============================================================================
 * COMMON PROGRAM TYPES IN ANCHOR
 * ============================================================================
 *
 * | Type | Program |
 * |------|---------|
 * | Program<'info, System> | System Program |
 * | Program<'info, Token> | SPL Token |
 * | Program<'info, Token2022> | Token Extensions |
 * | Program<'info, AssociatedToken> | ATA Program |
 *
 * ============================================================================
 * WHEN TO USE WHAT
 * ============================================================================
 *
 * AccountInfo / UncheckedAccount:
 * - For accounts you DON'T invoke
 * - For accounts where you only check pubkey/lamports
 * - ⚠️ NEVER for CPI targets
 *
 * Program<'info, T>:
 * - For ALL CPI targets
 * - Provides automatic verification
 * - Type-safe CPI
 *
 * ============================================================================
 */
//! # SECURE Implementation - Proper PDA Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify PDAs in Anchor.
//!
//! ## The Fix
//!
//! This implementation uses Anchor's `seeds` and `bump` constraints to
//! automatically verify PDAs were derived from expected seeds:
//!
//! ```rust
//! #[account(
//!     seeds = [b"vault", authority.key().as_ref()],
//!     bump = vault.bump
//! )]
//! ```
//!
//! ## How It Works
//!
//! Anchor generates code that:
//! 1. Derives expected PDA from seeds + program_id
//! 2. Compares expected PDA to actual account address
//! 3. Fails if they don't match
//!
//! Attacker's vault (derived from different seeds) will NEVER match!

use anchor_lang::prelude::*;
use crate::{Vault, Config, PDAError};

/// ✅ SECURE: Withdraw with PDA seed verification
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    /// ✅ SECURE: Seeds constraint verifies PDA derivation
    /// 
    /// Anchor verifies:
    /// 1. derive(["vault", authority.key()], program_id) == vault.key()
    /// 2. vault.authority == authority.key() (has_one)
    /// 3. vault.bump matches stored bump (for efficiency)
    ///
    /// Attack prevention:
    /// - Attacker's vault: derive(["vault", attacker], program_id)
    /// - Expected vault: derive(["vault", victim], program_id)
    /// - These are DIFFERENT addresses!
    /// - Anchor rejects with ConstraintSeeds error
    #[account(
        mut,
        seeds = [Vault::SEED_PREFIX, authority.key().as_ref()],
        bump = vault.bump,
        has_one = authority @ PDAError::InvalidAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    /// Authority who owns this vault
    pub authority: Signer<'info>,
    
    /// CHECK: Any account can receive funds
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

/// ✅ SECURE: Withdraw with verified PDA
pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ By this point, Anchor has verified:
    // 1. vault.key() == PDA(["vault", authority.key()], program_id)
    // 2. vault.authority == authority.key()
    // 3. authority has signed
    //
    // This is THE vault for this authority - guaranteed!
    
    if vault.balance < amount {
        return Err(PDAError::InsufficientBalance.into());
    }
    
    let vault_lamports = vault.to_account_info().lamports();
    if vault_lamports < amount {
        return Err(PDAError::InsufficientBalance.into());
    }
    
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(PDAError::ArithmeticOverflow)?;
    
    **vault.to_account_info().try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(PDAError::ArithmeticOverflow)?;
    
    let dest_lamports = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(amount)
        .ok_or(PDAError::ArithmeticOverflow)?;
    
    msg!("✅ SECURE: Withdrew {} lamports from verified vault", amount);
    msg!("✅ PDA seeds verified: [\"vault\", authority]");
    
    Ok(())
}

/// ✅ SECURE: Read config with PDA verification
#[derive(Accounts)]
pub struct ReadConfigSecure<'info> {
    /// ✅ SECURE: Verify config is THE global config
    /// 
    /// Only one valid config exists: PDA(["config"], program_id)
    /// Any fake config will fail this check.
    #[account(
        seeds = [Config::SEED_PREFIX],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
}

/// ✅ SECURE: Get fee from verified config
pub fn get_fee_secure(ctx: Context<ReadConfigSecure>) -> Result<u16> {
    let config = &ctx.accounts.config;
    
    // ✅ SAFE: This is THE global config
    msg!("✅ Reading fee from VERIFIED config: {} bps", config.fee_bps);
    
    Ok(config.fee_bps)
}

/// ✅ Initialize vault with correct PDA
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = Vault::SIZE,
        seeds = [Vault::SEED_PREFIX, authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.bump = ctx.bumps.vault;  // Store bump for future verification
    
    msg!("✅ Vault initialized at verified PDA");
    msg!("✅ Seeds: [\"vault\", {}]", vault.authority);
    msg!("✅ Bump: {}", vault.bump);
    
    Ok(())
}

/// ✅ Initialize global config
#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = Config::SIZE,
        seeds = [Config::SEED_PREFIX],
        bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize_config(ctx: Context<InitializeConfig>, fee_bps: u16) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.admin = ctx.accounts.admin.key();
    config.fee_bps = fee_bps;
    config.paused = false;
    config.bump = ctx.bumps.config;
    
    msg!("✅ Config initialized at verified PDA");
    msg!("✅ Seeds: [\"config\"]");
    msg!("✅ Fee: {} bps", fee_bps);
    
    Ok(())
}

/*
 * ============================================================================
 * HOW ANCHOR SEED VERIFICATION WORKS
 * ============================================================================
 *
 * When you write:
 * ```rust
 * #[account(
 *     seeds = [b"vault", authority.key().as_ref()],
 *     bump = vault.bump
 * )]
 * pub vault: Account<'info, Vault>,
 * ```
 *
 * Anchor generates (simplified):
 * ```rust
 * // Derive expected PDA
 * let expected_pda = Pubkey::create_program_address(
 *     &[b"vault", authority.key().as_ref(), &[vault.bump]],
 *     program_id
 * )?;
 *
 * // Compare to actual address
 * if vault.key() != expected_pda {
 *     return Err(ErrorCode::ConstraintSeeds);
 * }
 * ```
 *
 * ============================================================================
 * BUMP HANDLING
 * ============================================================================
 *
 * Option 1: Store bump in account (recommended)
 * ```rust
 * bump = vault.bump  // Uses stored bump (cheap)
 * ```
 *
 * Option 2: Let Anchor find bump
 * ```rust
 * bump  // Anchor calls find_program_address (expensive ~10k CU)
 * ```
 *
 * Best practice: Store bump on init, use stored bump on subsequent calls.
 *
 * ============================================================================
 * COMMON SEED PATTERNS
 * ============================================================================
 *
 * User-specific account:
 * seeds = [b"account", user.key().as_ref()]
 *
 * Global singleton:
 * seeds = [b"config"]
 *
 * Relationship (e.g., user's position in pool):
 * seeds = [b"position", pool.key().as_ref(), user.key().as_ref()]
 *
 * Counter-based (sequential IDs):
 * seeds = [b"item", &counter.to_le_bytes()]
 *
 * ============================================================================
 */
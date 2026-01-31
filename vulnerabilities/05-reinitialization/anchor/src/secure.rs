//! # SECURE Implementation - Reinitialization Prevention
//!
//! ✅ This code demonstrates the CORRECT way to prevent reinitialization.
//!
//! ## Methods Demonstrated
//!
//! 1. Using `init` constraint (not `init_if_needed`)
//! 2. Explicit `is_initialized` flag check
//! 3. Checking for non-default values
//!
//! ## Why These Work
//!
//! - `init`: Creates account via System Program, fails if exists
//! - `is_initialized` flag: Explicit check before writing
//! - Non-default check: If authority is set, account was initialized

use anchor_lang::prelude::*;
use crate::{Vault, SecureVault, Config, ReinitError};

/// ✅ SECURE: Initialize using `init` constraint
/// 
/// The `init` constraint:
/// 1. Calls System Program to create account
/// 2. Allocates space
/// 3. Assigns ownership to this program
/// 4. FAILS if account already exists
#[derive(Accounts)]
pub struct InitializeSecure1<'info> {
    /// ✅ SECURE: `init` fails if account already exists
    #[account(
        init,  // ✅ NOT init_if_needed!
        payer = authority,
        space = Vault::SIZE,
        seeds = [b"vault", authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

/// ✅ SECURE: Initialize with `init` constraint
pub fn initialize_secure_1(ctx: Context<InitializeSecure1>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ SAFE: `init` guarantees this is a fresh account
    // If someone tries to call this twice, Anchor rejects with:
    // "Error: Account already initialized"
    
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.bump = ctx.bumps.vault;
    
    msg!("✅ SECURE: Vault initialized with `init` constraint");
    msg!("✅ Authority: {}", vault.authority);
    msg!("✅ This cannot be called again for this PDA");
    
    Ok(())
}

/// ✅ SECURE: Initialize with explicit flag check
#[derive(Accounts)]
pub struct InitializeSecure2<'info> {
    /// Using mut instead of init - we'll check manually
    #[account(mut)]
    pub vault: Account<'info, SecureVault>,
    
    pub authority: Signer<'info>,
}

/// ✅ SECURE: Initialize with is_initialized flag
pub fn initialize_secure_2(ctx: Context<InitializeSecure2>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ SECURITY CHECK: Verify not already initialized
    if vault.is_initialized {
        msg!("❌ Error: Vault is already initialized");
        return Err(ReinitError::AlreadyInitialized.into());
    }
    
    // ✅ SAFE: Account is not initialized
    vault.is_initialized = true;  // ✅ Set flag FIRST
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.bump = 0;
    
    msg!("✅ SECURE: Vault initialized with flag check");
    msg!("✅ is_initialized flag prevents re-initialization");
    
    Ok(())
}

/// ✅ SECURE: Initialize with non-default value check
#[derive(Accounts)]
pub struct InitializeSecure3<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

/// ✅ SECURE: Initialize by checking for default values
pub fn initialize_secure_3(ctx: Context<InitializeSecure3>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ SECURITY CHECK: If authority is set, account was initialized
    if vault.authority != Pubkey::default() {
        msg!("❌ Error: Vault already has an authority");
        return Err(ReinitError::AlreadyInitialized.into());
    }
    
    // ✅ SAFE: Authority is default (zeroed), account is fresh
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.bump = 0;
    
    msg!("✅ SECURE: Vault initialized with default-value check");
    
    Ok(())
}

/// ✅ SECURE: Config initialization with flag
#[derive(Accounts)]
pub struct InitializeConfigSecure<'info> {
    /// ✅ Using `init` for singleton config
    #[account(
        init,
        payer = admin,
        space = Config::SIZE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(mut)]
    pub admin: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

/// ✅ SECURE: Config initialization
pub fn initialize_config_secure(
    ctx: Context<InitializeConfigSecure>,
    fee_bps: u16,
) -> Result<()> {
    let config = &mut ctx.accounts.config;
    
    // ✅ SAFE: `init` ensures this is first initialization
    config.admin = ctx.accounts.admin.key();
    config.fee_bps = fee_bps;
    config.is_paused = false;
    config.is_initialized = true;
    config.bump = ctx.bumps.config;
    
    msg!("✅ SECURE: Config initialized");
    msg!("✅ Admin: {}", config.admin);
    msg!("✅ Fee: {} bps", fee_bps);
    msg!("✅ `init` constraint prevents re-initialization");
    
    Ok(())
}

/// Withdraw from securely initialized vault
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(
        mut,
        seeds = [b"vault", authority.key().as_ref()],
        bump = vault.bump,
        has_one = authority @ ReinitError::InvalidAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Destination
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    if vault.balance < amount {
        return Err(ReinitError::InsufficientBalance.into());
    }
    
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(ReinitError::ArithmeticOverflow)?;
    
    let vault_lamports = vault.to_account_info().lamports();
    **vault.to_account_info().try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(ReinitError::ArithmeticOverflow)?;
    
    let dest_lamports = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(amount)
        .ok_or(ReinitError::ArithmeticOverflow)?;
    
    msg!("✅ Withdrew {} lamports", amount);
    Ok(())
}

/*
 * ============================================================================
 * INIT VS INIT_IF_NEEDED
 * ============================================================================
 *
 * `init`:
 * - Creates account via System Program
 * - Allocates space and sets owner
 * - FAILS if account already exists
 * - ✅ SAFE for initialization
 *
 * `init_if_needed`:
 * - Creates account if it doesn't exist
 * - Does nothing if account exists
 * - Lets your code run either way
 * - ⚠️ DANGEROUS if you overwrite data
 *
 * When is `init_if_needed` safe?
 * - When re-running with same values is idempotent
 * - When you add explicit checks for already-initialized state
 * - When the account is a PDA that can't be controlled by others
 *
 * Example of SAFE `init_if_needed`:
 * ```rust
 * #[account(
 *     init_if_needed,
 *     seeds = [b"profile", user.key().as_ref()],
 *     bump,
 *     payer = user,
 *     space = Profile::SIZE
 * )]
 * pub profile: Account<'info, Profile>,
 * pub user: Signer<'info>,
 * 
 * // In handler:
 * if profile.is_initialized {
 *     // Don't overwrite, just return
 *     return Ok(());
 * }
 * // Else initialize...
 * ```
 *
 * ============================================================================
 * BEST PRACTICES
 * ============================================================================
 *
 * 1. Prefer `init` over `init_if_needed`
 *
 * 2. If using `init_if_needed`, always check state:
 *    ```rust
 *    if account.is_initialized {
 *        return Ok(());  // Or return error
 *    }
 *    ```
 *
 * 3. Use `is_initialized` flag for explicit tracking
 *
 * 4. For PDAs, combine `init` with seeds for one-time creation
 *
 * 5. Never allow authority to be overwritten after initialization
 *
 * ============================================================================
 */
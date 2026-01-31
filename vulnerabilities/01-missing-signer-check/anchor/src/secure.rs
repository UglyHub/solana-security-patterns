//! # SECURE Implementation - Proper Signer Verification
//!
//! ✅ This code demonstrates the CORRECT way to verify signers in Anchor.
//!
//! ## The Fix
//! 
//! This implementation uses `Signer<'info>` for the authority account.
//! Anchor automatically verifies that this account has signed the transaction
//! BEFORE your instruction code runs.
//!
//! ## Security Guarantees
//! 
//! 1. The `Signer<'info>` type ensures `account.is_signer == true`
//! 2. The `has_one = authority` constraint ensures the signer matches vault.authority
//! 3. Combined, these guarantee ONLY the true authority can withdraw
//!
//! ## How Signer<'info> Works
//! 
//! When Anchor deserializes accounts, it checks the `is_signer` flag on the
//! underlying `AccountInfo`. If the account hasn't signed, Anchor returns an
//! error BEFORE your instruction code ever runs.
//!
//! Error message: "Error: unknown signer: <pubkey>"

use anchor_lang::prelude::*;
use crate::{Vault, VaultError};

/// ✅ SECURE: Withdraw instruction accounts with proper signer verification
/// 
/// The key security feature is using `Signer<'info>` for the authority.
/// This type AUTOMATICALLY verifies that the account signed the transaction.
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    /// The vault to withdraw from
    /// 
    /// The `has_one = authority` constraint verifies that:
    /// `vault.authority == authority.key()`
    /// 
    /// Combined with `Signer<'info>`, this ensures:
    /// 1. The authority account SIGNED the transaction
    /// 2. The signer IS the vault's designated authority
    #[account(
        mut,
        has_one = authority @ VaultError::InvalidAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    /// ✅ SECURE: Using Signer type enforces signature verification
    /// 
    /// Anchor automatically checks `authority.is_signer == true`
    /// If the account hasn't signed, the transaction fails with:
    /// "Error: unknown signer: <pubkey>"
    /// 
    /// This happens during account deserialization, BEFORE our code runs.
    /// An attacker CANNOT bypass this check.
    pub authority: Signer<'info>,
    
    /// Where to send the withdrawn lamports
    /// 
    /// CHECK: Any account can receive lamports
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

/// ✅ SECURE: Withdraw function with proper authorization
/// 
/// ## Security Analysis
/// 
/// By the time this function runs, Anchor has ALREADY verified:
/// 1. `authority.is_signer == true` (enforced by `Signer<'info>` type)
/// 2. `authority.key() == vault.authority` (enforced by `has_one` constraint)
/// 
/// An attacker CANNOT call this function without the authority's private key.
/// 
/// ## Attack Prevention
/// 
/// If Bob tries to withdraw from Alice's vault:
/// - Bob passes Alice's pubkey as authority
/// - But Bob cannot SIGN as Alice (no private key)
/// - Anchor rejects: "Error: unknown signer"
/// - Transaction fails, funds are safe!
pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Get current vault balance
    let vault_lamports = vault.to_account_info().lamports();
    
    // Check sufficient funds
    if vault_lamports < amount {
        return Err(VaultError::InsufficientFunds.into());
    }
    
    if vault.balance < amount {
        return Err(VaultError::InsufficientFunds.into());
    }
    
    // ✅ SECURE SECTION ✅
    // 
    // At this point, Anchor has ALREADY verified:
    // ✓ authority.is_signer == true (Signer<'info> type)
    // ✓ authority.key() == vault.authority (has_one constraint)
    //
    // ATTACK PREVENTION:
    // 1. Attacker cannot forge a signature (cryptographically impossible)
    // 2. Without valid signature, Anchor rejects before we reach this code
    // 3. Funds are safe!
    
    // Update internal balance tracking
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    
    // Transfer lamports from vault to destination
    **vault.to_account_info().try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    
    let dest_lamports = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;
    
    msg!("✅ SECURE: Withdrew {} lamports", amount);
    msg!("✅ Authorized by verified signer: {}", ctx.accounts.authority.key());
    
    Ok(())
}

/// Initialize a vault (secure version)
#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    #[account(
        init,
        payer = authority,
        space = Vault::SIZE,
    )]
    pub vault: Account<'info, Vault>,
    
    /// Authority must sign to create their vault
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn initialize_secure(ctx: Context<InitializeSecure>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.bump = 0;
    
    msg!("✅ Vault initialized with authority: {}", vault.authority);
    msg!("✅ Only this authority can withdraw (signature required)");
    Ok(())
}

/* 
 * ============================================================================
 * SECURITY COMPARISON SUMMARY
 * ============================================================================
 * 
 * VULNERABLE (UncheckedAccount):
 * ```rust
 * pub authority: UncheckedAccount<'info>,
 * // + constraint checking pubkey only
 * ```
 * - ❌ No signature verification
 * - ❌ Anyone can pass any pubkey
 * - ❌ Attacker doesn't need private key
 * 
 * SECURE (Signer):
 * ```rust
 * pub authority: Signer<'info>,
 * // + has_one constraint
 * ```
 * - ✅ Automatic signature verification
 * - ✅ Must sign with private key
 * - ✅ Cryptographically secure
 * 
 * ============================================================================
 * BEST PRACTICES
 * ============================================================================
 * 
 * 1. ALWAYS use `Signer<'info>` for authority accounts
 * 
 * 2. Combine with `has_one` to link signer to stored authority:
 *    ```rust
 *    #[account(has_one = authority)]
 *    pub vault: Account<'info, Vault>,
 *    pub authority: Signer<'info>,
 *    ```
 * 
 * 3. NEVER use `UncheckedAccount` for accounts that authorize actions
 * 
 * 4. If you must use `UncheckedAccount`, manually check `is_signer`:
 *    ```rust
 *    require!(ctx.accounts.authority.is_signer, ErrorCode::NotSigner);
 *    ```
 *    But prefer `Signer<'info>` - it's harder to forget!
 * 
 * ============================================================================
 */
//! # SECURE Implementation - Proper Type Verification
//!
//! ✅ This code demonstrates the CORRECT way to prevent type cosplay in Anchor.
//!
//! ## The Fix
//!
//! This implementation uses `Account<'info, Vault>` which automatically verifies:
//! 1. The discriminator matches Vault (bytes 0-8)
//! 2. The data deserializes correctly to a Vault struct
//!
//! An attacker CANNOT pass a UserProfile because its discriminator is different!
//!
//! ## How It Works
//!
//! - Vault discriminator: SHA256("account:Vault")[0..8]
//! - UserProfile discriminator: SHA256("account:UserProfile")[0..8]
//! - These are different! (collision is astronomically unlikely)
//!
//! When attacker passes UserProfile:
//! 1. Anchor reads bytes 0-8 (UserProfile discriminator)
//! 2. Compares to expected Vault discriminator
//! 3. MISMATCH! Transaction fails.
//! 4. Attack prevented!

use anchor_lang::prelude::*;
use crate::{Vault, TypeCosplayError};

/// ✅ SECURE: Withdraw with proper type verification
/// 
/// Using `Account<'info, Vault>` ensures Anchor verifies:
/// 1. Discriminator matches Vault (auto-generated hash)
/// 2. Owner is this program
/// 3. Data deserializes to Vault struct
#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    /// ✅ SECURE: Account<T> verifies discriminator automatically
    /// 
    /// When an attacker tries to pass a UserProfile:
    /// - Anchor reads discriminator from bytes 0-8
    /// - Compares to Vault's expected discriminator
    /// - UserProfile discriminator ≠ Vault discriminator
    /// - Transaction fails with AccountDiscriminatorMismatch
    /// - Attack prevented!
    #[account(
        mut,
        has_one = authority @ TypeCosplayError::InvalidAuthority,
        constraint = !vault.is_locked @ TypeCosplayError::VaultLocked
    )]
    pub vault: Account<'info, Vault>,
    
    /// Authority must sign
    pub authority: Signer<'info>,
    
    /// Destination for withdrawn funds
    /// CHECK: Any account can receive lamports
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

/// ✅ SECURE: Withdraw with automatic discriminator verification
///
/// By the time this function runs, Anchor has ALREADY verified:
/// 1. Account discriminator matches Vault ✓
/// 2. Account owner is this program ✓
/// 3. Data deserializes to Vault ✓
/// 4. authority matches vault.authority (has_one) ✓
/// 5. vault.is_locked is false (constraint) ✓
pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ✅ SAFE: This is GUARANTEED to be a real Vault
    // Anchor verified the discriminator before we got here
    
    if vault.balance < amount {
        return Err(TypeCosplayError::InsufficientBalance.into());
    }
    
    // Get actual lamports in account
    let vault_lamports = vault.to_account_info().lamports();
    if vault_lamports < amount {
        return Err(TypeCosplayError::InsufficientBalance.into());
    }
    
    // Update balance
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(TypeCosplayError::ArithmeticOverflow)?;
    
    // Transfer lamports
    **vault.to_account_info().try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(TypeCosplayError::ArithmeticOverflow)?;
    
    let dest_lamports = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(amount)
        .ok_or(TypeCosplayError::ArithmeticOverflow)?;
    
    msg!("✅ SECURE: Withdrew {} lamports from verified Vault", amount);
    msg!("✅ Discriminator verified by Anchor");
    
    Ok(())
}

/// Initialize a Vault securely
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = Vault::SIZE,
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
    vault.is_locked = false;
    
    msg!("✅ Vault initialized with authority: {}", vault.authority);
    msg!("✅ Discriminator automatically added by Anchor");
    
    Ok(())
}

/*
 * ============================================================================
 * HOW ANCHOR DISCRIMINATORS WORK
 * ============================================================================
 *
 * When you define:
 * ```rust
 * #[account]
 * pub struct Vault { ... }
 * ```
 *
 * Anchor generates:
 * ```rust
 * impl Vault {
 *     pub const DISCRIMINATOR: [u8; 8] = [...]; // SHA256("account:Vault")[0..8]
 * }
 *
 * impl AccountSerialize for Vault {
 *     fn try_serialize(&self, writer: &mut &mut [u8]) -> Result<()> {
 *         // Write discriminator FIRST
 *         writer[0..8].copy_from_slice(&Self::DISCRIMINATOR);
 *         // Then write data
 *         ...
 *     }
 * }
 *
 * impl AccountDeserialize for Vault {
 *     fn try_deserialize(buf: &mut &[u8]) -> Result<Self> {
 *         // Check discriminator FIRST
 *         if buf[0..8] != Self::DISCRIMINATOR {
 *             return Err(ErrorCode::AccountDiscriminatorMismatch);
 *         }
 *         // Then deserialize data
 *         ...
 *     }
 * }
 * ```
 *
 * ============================================================================
 * DISCRIMINATOR VALUES
 * ============================================================================
 *
 * Each account type gets a unique discriminator:
 *
 * Vault: sha256("account:Vault")[0..8]
 *        = [211, 8, 232, 43, 2, 152, 117, 119] (example)
 *
 * UserProfile: sha256("account:UserProfile")[0..8]
 *              = [142, 45, 33, 218, 87, 156, 21, 8] (example)
 *
 * These are DIFFERENT, so type confusion is detected!
 *
 * Collision probability: 1 in 2^64 ≈ 1 in 18 quintillion
 * (Effectively impossible)
 *
 * ============================================================================
 * DEFENSE SUMMARY
 * ============================================================================
 *
 * | Attack | Defense |
 * |--------|---------|
 * | Pass UserProfile as Vault | Discriminator mismatch → REJECTED |
 * | Copy Vault discriminator | Can't, account is owned by program |
 * | Create fake Vault | Only this program can create Vaults |
 * | Modify existing UserProfile | Wrong discriminator → REJECTED |
 *
 * ============================================================================
 */
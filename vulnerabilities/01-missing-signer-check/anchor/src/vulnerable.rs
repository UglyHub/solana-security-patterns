//! # VULNERABLE Implementation - Missing Signer Check
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//! 
//! This implementation uses `UncheckedAccount<'info>` for the authority account
//! instead of `Signer<'info>`. This means anyone can pass any pubkey as the
//! authority without actually signing the transaction.
//!
//! ## Attack Scenario
//! 
//! 1. Alice creates a vault with herself as authority and deposits 100 SOL
//! 2. Bob discovers Alice's vault address on-chain
//! 3. Bob reads the vault data and finds Alice's pubkey stored as authority
//! 4. Bob calls `withdraw_vulnerable` passing:
//!    - Alice's vault account
//!    - Alice's pubkey as authority (but Bob doesn't have Alice's private key!)
//!    - Bob's wallet as destination
//! 5. The program only checks if the pubkey MATCHES, not if Alice SIGNED
//! 6. Bob steals all of Alice's funds!
//!
//! ## Why It Works
//! 
//! The program confuses IDENTITY (whose pubkey?) with AUTHORIZATION (did they approve?).
//! Checking the pubkey only verifies WHO should be able to withdraw,
//! not WHETHER they actually authorized THIS specific withdrawal.

use anchor_lang::prelude::*;
use crate::{Vault, VaultError};

/// ❌ VULNERABLE: Withdraw instruction accounts
/// 
/// The critical flaw is using `UncheckedAccount` for authority.
/// This type performs NO verification that the account signed the transaction.
#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    /// The vault to withdraw from
    /// 
    /// We check that vault.authority matches the provided authority pubkey,
    /// but this is NOT sufficient - we need to verify they SIGNED!
    #[account(
        mut,
        constraint = vault.authority == authority.key() @ VaultError::InvalidAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    /// ❌ VULNERABILITY: Using UncheckedAccount instead of Signer!
    /// 
    /// `UncheckedAccount` is just a wrapper around `AccountInfo` that tells
    /// Anchor "I know what I'm doing, don't check anything."
    /// 
    /// The `/// CHECK:` comment is REQUIRED by Anchor when using UncheckedAccount.
    /// But our "check" (comparing pubkeys) is INSUFFICIENT for security!
    /// 
    /// CHECK: We verify pubkey matches vault.authority - BUT THIS IS NOT ENOUGH!
    /// We are NOT verifying that this account actually SIGNED the transaction.
    pub authority: UncheckedAccount<'info>,
    
    /// Where to send the withdrawn lamports
    /// 
    /// CHECK: Any account can receive lamports, no validation needed
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

/// ❌ VULNERABLE: Withdraw function without proper signer verification
/// 
/// ## The Problem
/// 
/// This function will succeed for ANYONE who knows the vault authority's pubkey.
/// They don't need the private key - they just pass the pubkey and steal funds!
/// 
/// ## What's Missing
/// 
/// We never call `authority.is_signer` or use `Signer<'info>` type.
/// The constraint `vault.authority == authority.key()` only checks that the
/// pubkey MATCHES - it does NOT verify that the owner of that pubkey SIGNED.
pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Get current vault balance (lamports stored in the account)
    let vault_lamports = vault.to_account_info().lamports();
    
    // Check there are sufficient funds
    if vault_lamports < amount {
        return Err(VaultError::InsufficientFunds.into());
    }
    
    // Check balance tracking
    if vault.balance < amount {
        return Err(VaultError::InsufficientFunds.into());
    }
    
    // ❌ VULNERABLE SECTION ❌
    // 
    // At this point, we've only verified:
    // ✓ vault.authority == authority.key() (the pubkey matches)
    // 
    // We have NOT verified:
    // ✗ authority.is_signer (did they actually sign?)
    //
    // ATTACK VECTOR:
    // 1. Attacker reads vault.authority from on-chain data (it's public!)
    // 2. Attacker creates transaction with that pubkey as "authority"
    // 3. Attacker does NOT sign with that keypair (they don't have it)
    // 4. This code runs anyway because we never checked is_signer!
    // 5. Attacker steals all funds
    
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
    
    msg!("⚠️ VULNERABLE: Withdrew {} lamports", amount);
    msg!("⚠️ WARNING: This withdrawal may have been unauthorized!");
    
    Ok(())
}

/// Initialize a vault (for testing purposes)
#[derive(Accounts)]
pub struct InitializeVulnerable<'info> {
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

pub fn initialize_vulnerable(ctx: Context<InitializeVulnerable>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    vault.bump = 0;
    
    msg!("Vault initialized with authority: {}", vault.authority);
    Ok(())
}
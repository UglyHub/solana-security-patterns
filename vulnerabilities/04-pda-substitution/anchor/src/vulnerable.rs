//! # VULNERABLE Implementation - PDA Substitution Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation accepts any vault account without verifying it was
//! derived from the expected seeds. An attacker can:
//!
//! 1. Create their own vault PDA with different seeds
//! 2. Pass that vault where a specific user's vault is expected
//! 3. Bypass intended access controls
//!
//! ## Attack Scenario
//!
//! Protocol intends: Each user has vault at PDA["vault", user_pubkey]
//! 
//! Attack:
//! 1. Attacker creates vault at PDA["vault", attacker_pubkey]
//! 2. Attacker sets themselves as authority
//! 3. Attacker calls function expecting victim's vault
//! 4. Passes their own vault instead
//! 5. Authority check passes (attacker is authority of attacker's vault)
//! 6. Protocol state corrupted or funds stolen

use anchor_lang::prelude::*;
use crate::{Vault, Config, PDAError};

/// ❌ VULNERABLE: Withdraw without PDA seed verification
#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    /// ❌ VULNERABILITY: No seeds constraint!
    /// 
    /// We verify:
    /// - has_one = authority (vault.authority == authority.key())
    /// 
    /// We DON'T verify:
    /// - This vault was derived from ["vault", authority.key()]
    /// 
    /// Attacker can pass ANY vault where they're the authority!
    #[account(
        mut,
        has_one = authority @ PDAError::InvalidAuthority
    )]
    pub vault: Account<'info, Vault>,
    
    /// Signer attempting withdrawal
    pub authority: Signer<'info>,
    
    /// CHECK: Any account can receive funds
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

/// ❌ VULNERABLE: Withdraw function
///
/// This function verifies the signer is the vault's authority, but doesn't
/// verify the vault is THE CORRECT vault for this user.
pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ MISSING CHECK!
    //
    // We should verify:
    // let expected_pda = Pubkey::find_program_address(
    //     &[Vault::SEED_PREFIX, ctx.accounts.authority.key().as_ref()],
    //     ctx.program_id
    // );
    // require!(vault.key() == expected_pda.0, PDAError::InvalidPDA);
    //
    // Without this, attacker can pass any vault they control!
    
    // These checks are NOT sufficient:
    // ✓ vault.authority == authority.key() (has_one constraint)
    // ✓ authority signed the transaction
    // ✗ vault is THE vault for this authority (MISSING!)
    
    if vault.balance < amount {
        return Err(PDAError::InsufficientBalance.into());
    }
    
    // Get actual lamports
    let vault_lamports = vault.to_account_info().lamports();
    if vault_lamports < amount {
        return Err(PDAError::InsufficientBalance.into());
    }
    
    // Update balance
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(PDAError::ArithmeticOverflow)?;
    
    // Transfer lamports
    **vault.to_account_info().try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(PDAError::ArithmeticOverflow)?;
    
    let dest_lamports = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(amount)
        .ok_or(PDAError::ArithmeticOverflow)?;
    
    msg!("⚠️ VULNERABLE: Withdrew {} lamports", amount);
    msg!("⚠️ PDA seeds were NOT verified!");
    
    Ok(())
}

/// ❌ VULNERABLE: Read config without seed verification
#[derive(Accounts)]
pub struct ReadConfigVulnerable<'info> {
    /// ❌ VULNERABILITY: No seeds constraint for config!
    /// 
    /// Attacker can create fake config at different PDA
    /// and pass it here to manipulate protocol behavior.
    pub config: Account<'info, Config>,
}

/// ❌ VULNERABLE: Get fee from potentially fake config
pub fn get_fee_vulnerable(ctx: Context<ReadConfigVulnerable>) -> Result<u16> {
    // ❌ DANGER: This config might be attacker-controlled!
    let config = &ctx.accounts.config;
    
    msg!("⚠️ Reading fee from UNVERIFIED config: {} bps", config.fee_bps);
    msg!("⚠️ This config PDA was NOT verified!");
    
    Ok(config.fee_bps)
}

/*
 * ============================================================================
 * EXPLOIT SCENARIOS
 * ============================================================================
 *
 * SCENARIO 1: Vault Substitution
 * -----------------------------
 * 
 * Setup:
 * - Alice has vault at PDA["vault", alice_pubkey] with 100 SOL
 * - Protocol tracks that Alice deposited 100 SOL
 *
 * Attack:
 * - Attacker creates vault at PDA["vault", attacker_pubkey]
 * - Attacker deposits 1 SOL (or uses flash loan)
 * - Attacker calls withdraw_vulnerable with:
 *   - vault: attacker's vault
 *   - authority: attacker
 *   - amount: 100 SOL (somehow referencing Alice's deposit record)
 * 
 * Result: Protocol confused about which vault to debit
 *
 * SCENARIO 2: Config Manipulation
 * ------------------------------
 *
 * Setup:
 * - Protocol has config at PDA["config"] with fee = 100 bps (1%)
 *
 * Attack:
 * - Attacker creates fake config at PDA["config", "fake"]
 * - Sets fee = 0 bps in fake config
 * - Attacker calls protocol function passing fake config
 * - Protocol reads 0% fee instead of 1%
 *
 * Result: Attacker pays no fees
 *
 * ============================================================================
 */
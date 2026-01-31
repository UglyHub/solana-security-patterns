//! # VULNERABLE Implementation - Reinitialization Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation allows an already-initialized account to be initialized
//! again, overwriting the existing authority with a new one.
//!
//! ## Attack Scenario
//!
//! 1. Alice initializes vault: authority = Alice
//! 2. Alice deposits 100 SOL (balance = 100)
//! 3. Attacker calls initialize again: authority = Attacker
//! 4. Vault now has: authority = Attacker, balance = 0 (or unchanged)
//! 5. Attacker is now the authority!
//!
//! ## Vulnerable Patterns Demonstrated
//!
//! 1. Using `init_if_needed` without proper checks
//! 2. Manual initialization without checking existing state

use anchor_lang::prelude::*;
use crate::{Vault, Config, ReinitError};

/// ❌ VULNERABLE: Initialize using init_if_needed
/// 
/// `init_if_needed` will:
/// - Create account if it doesn't exist
/// - Do nothing if it already exists (but let your code run!)
/// 
/// Your code then OVERWRITES the existing data!
#[derive(Accounts)]
pub struct InitializeVulnerable1<'info> {
    /// ❌ DANGEROUS: init_if_needed allows code to run on existing account
    #[account(
        init_if_needed,
        payer = authority,
        space = Vault::SIZE,
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

/// ❌ VULNERABLE: Initialize with init_if_needed
pub fn initialize_vulnerable_1(ctx: Context<InitializeVulnerable1>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ NO CHECK if already initialized!
    // This code runs even if vault already exists and has data
    
    // ❌ OVERWRITES existing authority!
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;  // ❌ RESETS balance!
    vault.bump = 0;
    
    msg!("⚠️ VULNERABLE: Vault initialized (or RE-initialized!)");
    msg!("⚠️ Authority set to: {}", vault.authority);
    
    Ok(())
}

/// ❌ VULNERABLE: Initialize without any protection
/// 
/// This pattern just writes to an existing account without checks
#[derive(Accounts)]
pub struct InitializeVulnerable2<'info> {
    /// Account that may already have data
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
}

/// ❌ VULNERABLE: Direct overwrite of existing data
pub fn initialize_vulnerable_2(ctx: Context<InitializeVulnerable2>) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // ❌ MISSING CHECK:
    // if vault.authority != Pubkey::default() {
    //     return Err(ReinitError::AlreadyInitialized.into());
    // }
    
    // ❌ OVERWRITES whatever was there!
    vault.authority = ctx.accounts.authority.key();
    vault.balance = 0;
    
    msg!("⚠️ VULNERABLE: Overwrote vault data without checking!");
    
    Ok(())
}

/// ❌ VULNERABLE: Config initialization without protection
#[derive(Accounts)]
pub struct InitializeConfigVulnerable<'info> {
    #[account(
        init_if_needed,
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

/// ❌ VULNERABLE: Config can be reinitialized
pub fn initialize_config_vulnerable(
    ctx: Context<InitializeConfigVulnerable>,
    fee_bps: u16,
) -> Result<()> {
    let config = &mut ctx.accounts.config;
    
    // ❌ Even though this is a PDA, init_if_needed lets us overwrite!
    // The PDA exists, but we can change its data
    
    // ❌ OVERWRITES admin - attacker becomes admin!
    config.admin = ctx.accounts.admin.key();
    config.fee_bps = fee_bps;  // ❌ Attacker sets fees
    config.is_paused = false;
    config.is_initialized = true;
    config.bump = ctx.bumps.config;
    
    msg!("⚠️ VULNERABLE: Config initialized/reinitialized");
    msg!("⚠️ Admin set to: {}", config.admin);
    msg!("⚠️ Fee set to: {} bps", fee_bps);
    
    Ok(())
}

/*
 * ============================================================================
 * EXPLOIT WALKTHROUGH
 * ============================================================================
 *
 * ATTACK 1: Vault Authority Takeover
 * ----------------------------------
 *
 * // Setup: Alice creates and funds vault
 * await program.methods
 *     .initializeVulnerable1()
 *     .accounts({ vault: vaultPda, authority: alice })
 *     .rpc();
 * 
 * await program.methods
 *     .deposit(new BN(100_000_000_000))  // 100 SOL
 *     .accounts({ vault: vaultPda, authority: alice })
 *     .rpc();
 *
 * // Attack: Attacker reinitializes the same vault
 * await program.methods
 *     .initializeVulnerable1()
 *     .accounts({ vault: vaultPda, authority: attacker })  // ❌ Different authority!
 *     .rpc();
 *
 * // Result: vault.authority is now attacker!
 * // Attacker can withdraw all funds
 *
 * ATTACK 2: Config Admin Takeover
 * -------------------------------
 *
 * // Setup: Protocol deploys with legitimate admin
 * await program.methods
 *     .initializeConfigVulnerable(100)  // 1% fee
 *     .accounts({ config: configPda, admin: legitimateAdmin })
 *     .rpc();
 *
 * // Attack: Anyone calls initialize again
 * await program.methods
 *     .initializeConfigVulnerable(0)  // 0% fee!
 *     .accounts({ config: configPda, admin: attacker })
 *     .rpc();
 *
 * // Result: 
 * // - Attacker is now admin
 * // - Protocol fees reduced to 0
 * // - Attacker controls the protocol!
 *
 * ============================================================================
 */
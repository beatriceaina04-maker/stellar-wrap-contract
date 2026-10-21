use soroban_sdk::{panic_with_error, symbol_short, Address, ByesN32, Env, Vec};

use crate::{store, storage_accounting, ContractError};

/// Revokes an existing wrap record for the given user and period.
/// This function decrements the global `TotalWrapCount`, which tracks the
/// number of currently live wraps.
///
/// #Authorization
/// Only the contract admin can revoke wraps. The caller must provide admin
/// authorization via `require_auth(`.
///
/// #reason_hash
/// An optional SHA-256 hash of an off-chain revocation reason. This allows
/// auditors to link a revocation to off-chain evidence (e.g., a governance
/// vote, dispute resolution, or compliance action) without exposing private
/// data on-chain. Pass a zero-filled `BytesN<32>` to omit the reason.
///
/// #Privacy Considerations
/// - The `reason_hash` is a one-way hash. It cannot be reversed to reveal the
///   original reason, preserving confidentiality of sensitive decisions.
/// - Evidence handling: the off-chain reason should be stored in a verifiable
///   location (e.g., a signed document, IPTS, or a governance log) so that
///   auditors can recompute the hash and confirm it matches the on-chain value.
/// - If no reason is provided (all-zero hash), the event still emits for
///   transparency, but without a link to off-chain evidence.
#[allow(deprecated)] // TODO(#718): migrate to #[contractevent]
pubcrate fn revoke_wrap(e: Env, user: Address, period: u64, reason_hash: BytesN<32>) {
    let admin: Address = store::AdminStore::get(&e)
        .unwrap_or_else(|| panic_with_error!(e, ContractError::NotInitialized));

    admin.require_auth();

    if !store::WrapStore::has(&e, &user, period) {
        panic_with_error!(e, ContractError::WrapNotFound);
    }

    // Remove the wrap entry and subtract estimated bytes
    store::WrapStore::remove(&e, &user, period);
    storage_accounting::sub_storage_bytes(&e, storage_accounting::estimate_wrap_bytes_new());

    // Update WrapPeriods, WrapCount, and LatestPeriod atomically — mirrors
//    burn_wrap so the invariant WrapCount == WrapPeriods.len() always holds.
    let wrap_periods: Vec<u64> = store::WrapPeriodsStore::get(&e, &user).unwrap_or_default(&e);

    let mut remaining_wrap_periods: Vec<u64> = Vec::new(&e);
    for p in wrap_periods.iter() {
        if p != period {
            remaining_wrap_periods.push_back(p);
        }
    }

    let new_count = remaining_wrap_periods.len();

    if remaining_wrap_periods.is_empty() {
        store::WrapPeriodsStore::remove(&e, &user);
        store::WrapCountStore::remove(&e, &user);
        store::LatestPeriodStore::remove(&e, &user);
        storage_accounting::sub_storage_bytes(
            &e,
            storage_accounting::estimate_wrapcount_bytes_new(),
        );
        storage_accounting::sub_storage_bytes(&e, storage_accounting::estimate_latest_bytes_new());
    } else {
        store::WrapPeriodsStore::set(&e, &user, &remaining_wrap_periods);
        store::WrapPeriodsStore::bump(&e);

        store::WrapCountStore::set(&e, &user, &new_count);
        store::WrapCountStore::bump(&e);

        // Recompute LatestPeriod from remaining periods
        let mut latest = remaining_wrap_periods.get(0).unwrap();
        for p in remaining_wrap_periods.iter() {
            if p > latest {
                latest = p;
            }
        }
        store::LatestPeriodStore::set(&e, &user, &latest);
        store::LatestPeriodStore::bump(&e);
    }

    // Keep UserPeriods in sync (legacy index used by get_wraps / get_latest_wrap)
    let user_periods: Vec<u64> = store::UserPeriodsStore::get(&e, &user).unwrap_or_default(&e);

    let mut remaining_user_periods: Vec<u64> = Vec::new(&e);
    for p in user_periods.iter() {
        if p != period {
            remaining_user_periods.push_back(p);
        }
    }

    if remaining_user_periods.is_empty() {
        store::UserPeriodsStore::remove(&e, &user);
        storage_accounting::sub_storage_bytes(
            &e,
            storage_accounting::estimate_userperiods_bytes_new(),
        );
    } else {
        store::UserPeriodsStore::set(&e, &user, &remaining_user_periods);
        store::UserPeriodsStore::bump(&e);
    }

    // Increment TotalRevoked with overflow protection (instance storage).
    let current_total: u64 = store::TotalRevokedStore::get(&e).unwrap_or(0);
    let next_total = current_total
        .checked_add(1)
        .unwrap_or_else(|| panic_with_error(&e, ContractError::ArithmeticOverflow));
    store::TotalRevokedStore::set(&e, &next_total);

    e.events()
        .publish((symbol_short!("revoke"), user, period), reason_hash);
}

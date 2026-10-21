/// Shared helpers for removing a wrap record and unwinding all associated
/// per-user state. Both `revoke_wrap` and `burn_wrap` (and the source-side of
/// `transfer_wrap`) delegate to `remove_wrap_record` so that every entrypoint
/// produces an identical state delta for the same `(user, period)`.

use soroban_sdk::{panic_with_error, Address, Env};

use crate::store;
use crate::storage_types::WrapState;
use crate::{storage_accounting, ContractError};

/// Remove the wrap record for `(user, period)` and unwind every piece of
/// per-user bookkeeping:
///
/// 1. Verify the wrap exists — panic with `WrapNotFound` if not.
/// 2. Remove the wrap record from persistent storage.
/// 3. Subtract estimated wrap bytes from the storage-accounting counter.
/// 4. Decrement the per-user wrap counter.
///    - If the count reaches zero, remove the key and subtract the
///      corresponding accounting bytes.
/// 5. Clear the latest period when the removed period was the
///    stored latest (no recompute; let the next mint set a new one).
/// 6. Remove `period` from the user periods index.
///    - Remove the key entirely when the list becomes empty.
/// 7. Remove `period` from the wrap periods index (the transfer index).
///    - Remove the key entirely when the list becomes empty.
/// 8. Decrement the global total wrap counter.
/// 9. Call `mint::update_last_updated` to record the state-change timestamp.
///
/// The caller is responsible for:
/// - Authorization (admin check for revoke, owner check for burn
us).
/// - Emitting the appropriate event.
/// - Any operation-specific bookkeeping (e.g. `TotalRevoked` for revoke).
pub(crate) fn remove_wrap_record(e: &Env, user: &Address, period: u64) {
    // 1. Guard: wrap must exist.
    if !store::WrapStore::has(e, user, period) {
        panic_with_error!(e, ContractError::WrapNotFound);
    }

    // Guard: cannot remove a bridged-out record.
    let record: crate::WrapRecord = store::WrapStore::load(e, user, period);
    if record.lifecycle.state == WrapState::Bridged {
        panic_with_error!(e, ContractError::InvalidStateTransition);
    }

    // 2. Remove the wrap record.
    store::WrapStore::remove(e, user, period);

    // 3. Storage accounting: subtract the wrap entry bytes.
    storage_accounting::sub_storage_bytes(e, storage_accounting::estimate_wrap_bytes_new());

    // 4. Decrement the per-user wrap counter.
    let current_count = store::WrapCountStore::get(e, user);
    if current_count > 0 {
        let next_count = current_count - 1;
        if next_count == 0 {
            store::WrapCountStore::remove(e, user);
            storage_accounting::sub_storage_bytes(
                e,
                storage_accounting::estimate_wrapcount_bytes_new(),
            );
        } else {
            store::WrapCountStore::set(e, user, next_count);
        }
    }

    // 5. Clear the latest period if it pointed at the removed period.
    if store::LatestPeriodStore::get(e, user) == Some(period) {
        store::LatestPeriodStore::remove(e, user);
    }

    // 6. Remove `period` from the user periods index.
    remove_from_user_periods(e, user, period);

    // 7. Remove `period` from the wrap periods index (transfer index).
    remove_from_wrap_periods(e, user, period);

    // 8. Decrement the global total wrap counter.
    let current_total = store::TotalWrapCountStore::get(e);
    if current_total > 0 {
        store::TotalWrapCountStore::set(e, current_total - 1);
    }

    // 9. Update the last-updated timestamp.
    crate::mint::update_last_updated(e, user);
}

/// Remove `period` from the user periods index.
/// Removes the entire key when the list becomes empty.
fn remove_from_user_periods(e: &Env, user: &Address, period: u64) {
    let mut periods = store::UserPeriodsStore::get(e, user);

    let mut found_index: Option<u32> = None;
    for (i, p) in periods.iter().enumerate() {
        if p == period {
            found_index = Some(i as u32);
            break;
        }
    }

    if let Some(idx) = found_index {
        periods.remove(idx);
        if periods.is_empty() {
            store::UserPeriodsStore::remove(e, user);
        } else {
            store::UserPeriodsStore::set(e, user, &periods);
        }
    }
}

/// Remove `period` from the wrap periods index (the transfer index).
/// Removes the entire key when the list becomes empty.
pub(crate) fn remove_from_wrap_periods(e: &Env, user: &Address, period: u64) {
    let mut periods = store::WrapPeriodsStore::get(e, user);

    let mut found_index: Option<u32> = None;
    for (i, p) in periods.iter().enumerate() {
        if p == period {
            found_index = Some(i as u32);
            break;
        }
    }

    if let Some(idx) = found_index {
        periods.remove(idx);
        if periods.is_empty() {
            store::WrapPeriodsStore::remove(e, user);
        } else {
            store::WrapPeriodsStore::set(e, user, &periods);
        }
    }
}

//! Read-only query helpers for the wrap contract.
//!
//! This module centralises the storage reads used by the contract's public
//! query entry points. It exposes helpers for fetching individual wrap
//! records, paginated and full listings of a user's wraps, aggregate wrap
//! summaries, token-style balance/count queries, and contract metadata such
//! as the transfer-fee configuration, admin address, admin public key, and
//! overall contract health.
//!
//! All functions here are side-effect free: they only read from persistent or
//! instance storage and never mutate contract state.

use soroban_sdk::{Address, Bytes, BytesN, Env, String, Symbol, Vec};

use crate::store::{self, WrapStore};
use crate::{ContractHealth, InvariantReport, TransferFeeConfig, WrapRecord, WrapSummary};

pub(crate) fn get_wrap(e: Env, user: Address, period: u64) -> Option<WrapRecord> {
    WrapStore::get(&e, &user, period)
}

pub(crate) fn get_mint_timestamp(e: Env, user: Address, period: u64) -> Option<u64> {
    let wrap: Option<WrapRecord> = WrapStore::get(&e, &user, period);
    wrap.map(|r| r.timestamp)
}

/// Return the ledger timestamp of the user's most recent state change via a
/// successful mint or revoke, or `None` if the user has never minted or had a
/// wrap revoked.
pub(crate) fn get_last_updated(e: Env, user: Address) -> Option<u64> {
    store::LastUpdatedStore::get(&e, &user)
}

/// Returns the number of active wrap records for the user.
///
/// Under the hood, this retrieves the `u32` wrap record counter (`DataKey::WrapCount`)
/// and casts it to `i128` to satisfy the standard token interface return signature.
/// The return value represents a count of discrete wrap records, not a fungible token balance.
pub(crate) fn balance_of(e: Env, user: Address) -> i128 {
    store::WrapCountStore::get(&e, &user) as i128
}

pub(crate) fn total_wrap_count(e: Env) -> u32 {
    store::TotalWrapCountStore::get(&e)
}

/// Verifies that `data` matches the SHA-256 hash committed for `(user, period)`.
///
/// Looks up `DataKey::Wrap(user, period)` in persistent storage, computes
/// `SHA-256(data)`, and compares the result to [`WrapRecord::data_hash`].
/// Returns `true` only when the record exists **and** the hashes are equal.
/// Returns `false` for a missing record, a tampered payload, or any mismatch.
///
/// This function is pure read — it never writes storage and requires no auth.
pub(crate) fn verify_data(e: Env, user: Address, period: u64, data: Bytes) -> bool {
    let wrap: Option<WrapRecord> = WrapStore::get(&e, &user, period);
    wrap.is_some_and(|record| {
        let computed_hash = e.crypto().sha256(&data);
        let computed_hash = BytesN::from_array(&e, &computed_hash.to_array());
        record.data_hash == computed_hash
    })
}

pub(crate) fn get_latest_wrap(e: Env, user: Address) -> Option<WrapRecord> {
    if let Some(period) = store::LatestPeriodStore::get(&e, &user) {
        if let Some(wrap) = WrapStore::get(&e, &user, period) {
            return Some(wrap);
        }
    }

    // Fallback: Scan UserPeriods to find the latest wrap.
    // This is kept as a legacy-data safety net in case LatestPeriod becomes stale
    // due to corruption or migration issues. Under normal operation, LatestPeriod
    // should always be recomputed correctly during revoke/burn, so this fallback
    // should not be triggered.
    let periods: soroban_sdk::Vec<u64> = store::UserPeriodsStore::get(&e, &user)?;
    let mut latest: Option<WrapRecord> = None;

    for index in 0..periods.len() {
        if let Some(period) = periods.get(index) {
            if let Some(wrap) = WrapStore::get(&e, &user, period) {
                let is_newer = match latest.as_ref() {
                    None => true,
                    Some(current) => wrap.period > current.period,
                };
                if is_newer {
                    latest = Some(wrap);
                }
            }
        }
    }

    latest
}

pub(crate) fn get_wraps(
    e: Env,
    user: Address,
    start: u32,
    limit: u32,
) -> soroban_sdk::Vec<WrapRecord> {
    let mut results = soroban_sdk::Vec::new(&e);

    if let Some(periods) = store::UserPeriodsStore::get(&e, &user) {
        let len = periods.len();
        if start < len {
            let end = core::cmp::min(start.saturating_add(limit), len);
            for i in start..end {
                if let Some(period) = periods.get(i) {
                    if let Some(wrap) = WrapStore::get(&e, &user, period) {
                        results.push_back(wrap);
                    }
                }
            }
        }
    }

    results
}

/// Returns every wrap record owned by `user` in a single call.
///
/// This is a convenience wrapper around [`get_wraps`] that requests all records
/// without pagination. It is intended for bounded queries of at most
/// [`MAX_QUERY_RESULTS`] (200) records. Callers with larger datasets should use
/// the paginated [`get_wraps`] instead to stay within Soroban resource limits.
///
/// **Note:** This bound is not yet enforced; the current implementation still
/// passes `limit = u32::MAX` to [`get_wraps`].
pub(crate) fn get_all_wraps_for_user(e: Env, user: Address) -> soroban_sdk::Vec<WrapRecord> {
    // Fetch all wraps by using the maximum possible range.
    get_wraps(e, user, 0, u32::MAX)
}

/// Returns an aggregate summary of a user's active wraps across all periods.
///
/// Returns `None` if the user has no active wraps.
///
/// The summary includes:
/// - `total_wraps`: count of active wrap records
/// - `periods`: all period IDs (YYYYMM) for active wraps
/// - `archetypes`: unique archetype symbols across all active wraps
/// - `first_period`: the earliest period with an active wrap
/// - `latest_period`: the latest period with an active wrap
pub(crate) fn get_wrap_summary(e: Env, user: Address) -> Option<WrapSummary> {
    let periods: soroban_sdk::Vec<u64> = store::WrapPeriodsStore::get(&e, &user)?;

    if periods.is_empty() {
        return None;
    }

    let mut total_wraps: u32 = 0;
    let mut archetypes: Vec<Symbol> = Vec::new(&e);
    let mut first_period: u64 = u64::MAX;
    let mut latest_period: u64 = 0;

    for i in 0..periods.len() {
        if let Some(period) = periods.get(i) {
            if let Some(wrap) = WrapStore::get(&e, &user, period) {
                total_wraps += 1;

                if period < first_period {
                    first_period = period;
                }
                if period > latest_period {
                    latest_period = period;
                }

                if !archetypes.contains(&wrap.archetype) {
                    archetypes.push_back(wrap.archetype);
                }
            }
        }
    }

    if total_wraps == 0 {
        return None;
    }

    Some(WrapSummary {
        total_wraps,
        periods,
        archetypes,
        first_period,
        latest_period,
    })
}

/// Return the configured transfer-fee configuration, or `None` if unset.
pub(crate) fn get_transfer_fee(e: Env) -> Option<TransferFeeConfig> {
    store::TransferFeeStore::get(&e)
}

pub(crate) fn health(e: Env) -> ContractHealth {
    let has_admin = store::AdminStore::has(&e);
    let has_signing_key = store::AdminPubKeyStore::has(&e);

    ContractHealth {
        initialized: has_admin,
        has_admin,
        has_signing_key,
    }
}

pub(crate) fn get_admin(e: Env) -> Option<Address> {
    store::AdminStore::get(&e)
}

/// Return the configured Ed25519 admin public key, or `None` before `initialize`.
///
/// Operators use this to confirm which off-chain signing key is live without
/// inspecting raw instance storage. The value is a public verification key only;
/// it does not reveal private key material. Prefer this over reading storage
/// directly when building ops/monitoring tooling.
pub(crate) fn get_admin_pubkey(e: Env) -> Option<BytesN<32>> {
    store::AdminPubKeyStore::get(&e)
}

/// Return the contract semantic version string (`MAJOR.MINOR.PATCH`).
///
/// Derived from `Cargo.toml` package version at compile time via
/// `CARGO_PKG_VERSION`, so this value can never drift from the package version.
/// Bump it in the same release that ships a WASM upgrade so clients can detect
/// which interface they are talking to after `upgrade()`.
pub(crate) fn version(e: Env) -> String {
    String::from_str(&e, env!("CARGO_PKG_VERSION"))
}

/// Cheap existence check for `(user, period)` without loading a `WrapRecord`.
///
/// Prefer `has_wrap` when callers only need a boolean (indexing, gating UI).
/// Use `get_wrap` when the full record (timestamp, archetype, hash, FSM) is
/// required.
pub(crate) fn has_wrap(e: Env, user: Address, period: u64) -> bool {
    WrapStore::has(&e, &user, period)
}

pub(crate) fn total_revoked(e: Env) -> u64 {
    store::TotalRevokedStore::get(&e)
}

pub(crate) fn name(e: Env) -> String {
    store::NameStore::get(&e).unwrap_or_else(|| String::from_str(&e, "Stellar Wrap Registry"))
}

pub(crate) fn symbol(e: Env) -> String {
    store::SymbolStore::get(&e).unwrap_or_else(|| String::from_str(&e, "WRAP"))
}

/// Returns `0` because wrap records represent discrete, indivisible registry entries with
/// no fractional units.
pub(crate) fn decimals(_e: Env) -> u32 {
    0
}

pub(crate) fn contract_version(e: Env) -> u32 {
    store::ContractVersionStore::get(&e)
}

/// Returns the storage schema version.
///
/// The schema version is set at contract initialization and indicates which
/// storage layout/schema is active. It starts at `1` for the initial schema.
/// Future upgrades that change the storage layout should increment this version
/// as part of their migration logic (see `admin::migrate`).
pub(crate) fn schema_version(e: Env) -> u32 {
    store::SchemaVersionStore::get(&e)
}

pub const MAX_QUERY_RESULTS: u32 = 100;

pub(crate) fn check_user_invariants(e: Env, user: Address) -> InvariantReport {
    let wrap_count: u32 = store::WrapCountStore::get(&e, &user);

    let user_periods: soroban_sdk::Vec<u64> =
        store::UserPeriodsStore::get(&e, &user).unwrap_or_else(|| soroban_sdk::Vec::new(&e));
    let user_periods_len = user_periods.len();

    let wrap_periods: soroban_sdk::Vec<u64> =
        store::WrapPeriodsStore::get(&e, &user).unwrap_or_else(|| soroban_sdk::Vec::new(&e));
    let wrap_periods_len = wrap_periods.len();

    let latest_period: Option<u64> = store::LatestPeriodStore::get(&e, &user);

    let mut max_user_period: Option<u64> = None;
    let mut live_wraps_found = 0;

    let scan_len = core::cmp::min(user_periods_len, MAX_QUERY_RESULTS);
    for i in 0..scan_len {
        if let Some(p) = user_periods.get(i) {
            max_user_period = Some(core::cmp::max(max_user_period.unwrap_or(0), p));
            if WrapStore::has(&e, &user, p) {
                live_wraps_found += 1;
            }
        }
    }

    let all_user_periods_live = if scan_len > 0 {
        live_wraps_found == scan_len
    } else {
        true
    };
    let balance = balance_of(e.clone(), user.clone()) as u32;

    InvariantReport {
        wrap_count_match_user_periods: wrap_count == user_periods_len,
        wrap_count_match_wrap_periods: wrap_count == wrap_periods_len,
        latest_period_matches_max: latest_period == max_user_period,
        all_user_periods_live,
        balance_matches_wrap_count: balance == wrap_count,
        wrap_count,
        user_periods_len,
        wrap_periods_len,
        latest_period,
        max_user_period,
        live_wraps_found,
        balance,
    }
}

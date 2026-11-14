//! Budgets shared by the instances of a cluster (`scope: cluster` on `rate_limit` and `quota`,
//! ADR-0031), on the request path's side: no I/O and no waiting.
//!
//! Each key's budget `L` for a window is claimed from a shared store in parts. An instance
//! admits a request while what it admitted in the window (`used`) is below what it claimed
//! (`granted`) plus a headroom `c = max(1, ⌈L × h / (100 × N)⌉)` (`h` the headroom percentage,
//! `N` the instances it knows of), and asks for more as soon as its headroom is being used.
//! Claims are sent by a background task (`rdock-cluster`), never by the request.
//!
//! A key an instance sees for the first time in a window has no answer from the store yet: until
//! its first claim returns, the instance admits up to its fair share `s = ⌈L / N⌉` (not just `c`,
//! which refused a browser's parallel requests with 429 for a store round trip; review finding
//! M4), and when the answer comes, what it admitted beyond the grant is added to the store's
//! count (a *forced* claim), exactly as after an outage.
//!
//! **The bound.** The store never grants more than `L` in non-forced claims. Each instance admits
//! at most `max(c, s)` beyond what it was granted: while the key is new to it at most `s` in all;
//! after that `c` beyond its claims, its forced claim being at most `s − 1 − c` when its first
//! claim was granted in full, and the key being exhausted (no headroom) when it was not. So the
//! cluster admits at most **`L + N × max(c, ⌈L / N⌉)`** per key and window (with `h` at most 100,
//! `c ≤ ⌈L / N⌉`, so this is `L + N × ⌈L / N⌉`, about `2 × L`), and only when instances meet a key
//! for the first time after the others used it up; a key whose requests keep coming to the same
//! instances stays within `L + N × c`. The bound assumes every instance counts the same `N`;
//! see `bound` for clock skew.
//!
//! While the store is away an instance admits up to `max(granted, ⌈L / N⌉)` (fallback
//! `share`) or `L` (fallback `instance`) against its own count; when the store returns, what it
//! admitted beyond its claims is added to the store's count (a *forced* claim) so the cluster's
//! total stays true.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use crate::quota::Window;

/// Keys tracked per budget before new ones share one overflow counter.
pub const MAX_KEYS: usize = 100_000;

/// The key every request uses once a budget tracks [`MAX_KEYS`] keys of the current window.
pub const OVERFLOW_KEY: &str = "~overflow";

/// How a budget's windows are cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    /// Fixed windows of this length from the Unix epoch (`rate_limit`'s `period`).
    Fixed(Duration),
    /// Calendar windows in UTC (`quota`).
    Calendar(Window),
}

impl WindowKind {
    /// The window holding `now_ms` (Unix milliseconds): start and end, in milliseconds.
    #[must_use]
    pub fn bounds(self, now_ms: u64) -> (u64, u64) {
        match self {
            Self::Fixed(length) => {
                let length = u64::try_from(length.as_millis()).unwrap_or(u64::MAX).max(1);
                let start = now_ms - now_ms % length;
                (start, start.saturating_add(length))
            }
            Self::Calendar(window) => {
                let (start, end) = window.bounds(i64::try_from(now_ms / 1000).unwrap_or(0));
                let ms = |s: i64| u64::try_from(s).unwrap_or(0).saturating_mul(1000);
                (ms(start), ms(end))
            }
        }
    }
}

/// The outcome of [`Budget::take`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Take {
    /// Admitted.
    Allowed {
        /// Requests the cluster has left in the window, as far as this instance knows.
        remaining: u64,
        /// Seconds until the window ends.
        reset: u64,
    },
    /// Refused: the budget is used up (as far as this instance can tell).
    Exceeded {
        /// Seconds until the window ends.
        reset: u64,
    },
}

/// A claim the background task should send.
#[derive(Debug, Clone)]
pub struct Claim {
    /// The budget.
    pub budget: Arc<Budget>,
    /// The key within it.
    pub key: String,
    /// The window's start and end (Unix milliseconds).
    pub window: (u64, u64),
    /// How much to claim.
    pub amount: u64,
    /// The key's limit `L` in that window.
    pub limit: u64,
    /// Add `amount` whatever the total (what was admitted while the store was away).
    pub forced: bool,
}

#[derive(Debug)]
struct KeyState {
    window: (u64, u64),
    limit: u64,
    used: u64,
    granted: u64,
    /// The store's total for the key, as last answered.
    total: u64,
    /// A claim for this key is queued or in flight.
    asked: bool,
    /// A claim for this key in this window has been answered (until then the key is new to
    /// this instance and admits up to the fair share).
    answered: bool,
    /// The store answered that nothing is left: do not ask again this window unless forced.
    exhausted: bool,
}

#[derive(Debug)]
struct Inner {
    budgets: Mutex<HashMap<String, Weak<Budget>>>,
    pending: Mutex<Vec<Claim>>,
    notify: tokio::sync::Notify,
    /// A background task sends claims; without one, budgets count per instance.
    attached: AtomicBool,
    store_up: AtomicBool,
    members: AtomicU64,
    headroom_percent: AtomicU32,
    fallback_instance: AtomicBool,
}

/// The process-wide registry of shared budgets; it outlives configurations so a reload keeps
/// what was claimed.
#[derive(Debug, Clone)]
pub struct SharedLimits {
    inner: Arc<Inner>,
}

impl Default for SharedLimits {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                budgets: Mutex::new(HashMap::new()),
                pending: Mutex::new(Vec::new()),
                notify: tokio::sync::Notify::new(),
                attached: AtomicBool::new(false),
                store_up: AtomicBool::new(false),
                members: AtomicU64::new(1),
                headroom_percent: AtomicU32::new(10),
                fallback_instance: AtomicBool::new(false),
            }),
        }
    }
}

/// One shared budget (a middleware), with its keys.
#[derive(Debug)]
pub struct Budget {
    id: String,
    kind: WindowKind,
    keys: Mutex<HashMap<String, KeyState>>,
    inner: Arc<Inner>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn ceil_div(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { a.div_ceil(b) }
}

/// The headroom `c = max(1, ⌈L × h / (100 × N)⌉)`.
#[must_use]
pub fn headroom(limit: u64, percent: u32, members: u64) -> u64 {
    let numerator = u128::from(limit) * u128::from(percent);
    let denominator = 100 * u128::from(members.max(1));
    u64::try_from(numerator.div_ceil(denominator))
        .unwrap_or(u64::MAX)
        .max(1)
}

/// The fair share `s = ⌈L / N⌉`: what an instance admits for a key new to it until its first
/// claim returns, and while the store is away (fallback `share`).
#[must_use]
pub fn share(limit: u64, members: u64) -> u64 {
    ceil_div(limit, members.max(1))
}

/// The documented bound, `L + N × max(c, ⌈L / N⌉)`: the most a cluster of `members` instances
/// admits per key and window for a limit `limit` with `percent` headroom while the store
/// answers (see the module documentation).
///
/// It assumes every instance counts `members`. An instance whose count is lower (it joined
/// moments ago, or a member's heartbeat stopped changing) uses a larger `c` and `s`; the bound
/// then holds with each instance's own `max(c, s)` summed. Clocks do not change the count: a
/// member counts while its heartbeat keeps changing, by the reader's monotonic clock. A clock
/// that differs from the others by less than the store's window margin (60 s) moves the
/// instant an instance changes windows, not the count of a window: totals are removed only a
/// minute after a window ended.
#[must_use]
pub fn bound(limit: u64, percent: u32, members: u64) -> u64 {
    let members = members.max(1);
    limit.saturating_add(
        members.saturating_mul(headroom(limit, percent, members).max(share(limit, members))),
    )
}

impl SharedLimits {
    /// Sets the headroom percentage and the fallback (`true`: the whole limit per instance).
    pub fn configure(&self, headroom_percent: u8, fallback_instance: bool) {
        self.inner
            .headroom_percent
            .store(u32::from(headroom_percent), Ordering::Relaxed);
        self.inner
            .fallback_instance
            .store(fallback_instance, Ordering::Relaxed);
    }

    /// Marks that a background task sends claims (until then budgets count per instance).
    pub fn attach(&self) {
        self.inner.attached.store(true, Ordering::SeqCst);
    }

    /// Whether a background task sends claims.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.inner.attached.load(Ordering::SeqCst)
    }

    /// Whether the store answered last time.
    #[must_use]
    pub fn store_up(&self) -> bool {
        self.inner.store_up.load(Ordering::SeqCst)
    }

    /// Records whether the store answers. On recovery, every key that admitted beyond its
    /// claims queues a forced claim of the difference.
    pub fn set_store_up(&self, up: bool) {
        let was = self.inner.store_up.swap(up, Ordering::SeqCst);
        if up && !was {
            for budget in self.budgets() {
                budget.reconcile();
            }
            self.inner.notify.notify_one();
        }
    }

    /// The number of instances sharing the budgets (at least 1).
    #[must_use]
    pub fn members(&self) -> u64 {
        self.inner.members.load(Ordering::Relaxed).max(1)
    }

    /// Records how many instances share the budgets.
    pub fn set_members(&self, members: u64) {
        self.inner.members.store(members.max(1), Ordering::Relaxed);
    }

    /// The budget `id` (a key-safe name), created on first use. A budget whose window kind
    /// changed (a new `period` or `window`) starts again.
    #[must_use]
    pub fn budget(&self, id: &str, kind: WindowKind) -> Arc<Budget> {
        let mut budgets = self
            .inner
            .budgets
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = budgets.get(id).and_then(Weak::upgrade)
            && existing.kind == kind
        {
            return existing;
        }
        let budget = Arc::new(Budget {
            id: id.to_owned(),
            kind,
            keys: Mutex::new(HashMap::new()),
            inner: self.inner.clone(),
        });
        budgets.insert(id.to_owned(), Arc::downgrade(&budget));
        budgets.retain(|_, b| b.strong_count() > 0);
        budget
    }

    /// The live budgets.
    #[must_use]
    pub fn budgets(&self) -> Vec<Arc<Budget>> {
        self.inner
            .budgets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter_map(Weak::upgrade)
            .collect()
    }

    /// Takes the queued claims.
    #[must_use]
    pub fn drain(&self) -> Vec<Claim> {
        std::mem::take(
            &mut *self
                .inner
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Waits until a claim is queued (or the store recovered).
    pub async fn wanted(&self) {
        self.inner.notify.notified().await;
    }
}

impl Budget {
    /// The budget's id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether a background task shares this budget; without one the caller counts per
    /// instance.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.inner.attached.load(Ordering::SeqCst)
    }

    /// How its windows are cut.
    #[must_use]
    pub fn kind(&self) -> WindowKind {
        self.kind
    }

    /// Admits or refuses one request for `key` with limit `limit`, now.
    pub fn take(&self, key: &str, limit: u64) -> Take {
        self.take_at(key, limit, now_ms())
    }

    /// [`Budget::take`] at `now_ms` (Unix milliseconds).
    pub fn take_at(&self, key: &str, limit: u64, now_ms: u64) -> Take {
        let window = self.kind.bounds(now_ms);
        let reset = ceil_div(window.1.saturating_sub(now_ms), 1000).max(1);
        let inner = &self.inner;
        let members = inner.members.load(Ordering::Relaxed).max(1);
        let percent = inner.headroom_percent.load(Ordering::Relaxed);
        let up = inner.store_up.load(Ordering::SeqCst);
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        let key = if keys.contains_key(key) || keys.len() < MAX_KEYS {
            key
        } else {
            keys.retain(|_, k| k.window.1 > now_ms);
            if keys.len() < MAX_KEYS {
                key
            } else {
                OVERFLOW_KEY
            }
        };
        let state = keys.entry(key.to_owned()).or_insert(KeyState {
            window,
            limit,
            used: 0,
            granted: 0,
            total: 0,
            asked: false,
            answered: false,
            exhausted: false,
        });
        if state.window != window {
            *state = KeyState {
                window,
                limit,
                used: 0,
                granted: 0,
                total: 0,
                asked: false,
                answered: false,
                exhausted: false,
            };
        }
        state.limit = limit;
        let allowance = if up && state.exhausted {
            // The store said nothing is left: no headroom beyond what was granted.
            state.granted
        } else if up && !state.answered {
            // New to this instance: the fair share until the first claim returns.
            state
                .granted
                .saturating_add(headroom(limit, percent, members))
                .max(share(limit, members))
        } else if up {
            state
                .granted
                .saturating_add(headroom(limit, percent, members))
        } else if inner.fallback_instance.load(Ordering::Relaxed) {
            limit
        } else {
            state.granted.max(share(limit, members))
        };
        let admitted = state.used < allowance;
        if admitted {
            state.used += 1;
        }
        // Keep `headroom` claimed ahead of use while the store answers.
        let c = headroom(limit, percent, members);
        let want = if up && !state.asked && !state.exhausted {
            state.used.saturating_add(c).saturating_sub(state.granted)
        } else {
            0
        };
        if want > 0 {
            state.asked = true;
        }
        drop(keys);
        if want > 0 {
            match self.arc() {
                Some(budget) => {
                    inner
                        .pending
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(Claim {
                            budget,
                            key: key.to_owned(),
                            window,
                            amount: want,
                            limit,
                            forced: false,
                        });
                    inner.notify.notify_one();
                }
                None => self.failed(key, window),
            }
        }
        self.outcome(admitted, key, limit, reset)
    }

    fn outcome(&self, admitted: bool, key: &str, limit: u64, reset: u64) -> Take {
        if !admitted {
            return Take::Exceeded { reset };
        }
        let keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        let remaining = keys.get(key).map_or(0, |k| {
            let elsewhere = k.total.saturating_sub(k.granted);
            limit.saturating_sub(elsewhere.saturating_add(k.used))
        });
        Take::Allowed { remaining, reset }
    }

    /// This budget as an `Arc` (through the registry, which holds it while it is in use).
    fn arc(&self) -> Option<Arc<Self>> {
        self.inner
            .budgets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.id)
            .and_then(Weak::upgrade)
            .filter(|b| std::ptr::eq(Arc::as_ptr(b), self))
    }

    /// Records the store's answer to a claim: `granted` of what was asked, the key's total
    /// after it, whether the claim was forced. A claim for a window that has passed is
    /// dropped. The first answer for a key reconciles what was admitted beyond it while the
    /// key was new (a forced claim of the difference).
    pub fn granted(
        &self,
        key: &str,
        window: (u64, u64),
        granted: u64,
        total: u64,
        asked: u64,
        forced: bool,
    ) {
        let mut reconcile = None;
        {
            let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(state) = keys.get_mut(key)
                && state.window == window
            {
                state.granted = state.granted.saturating_add(granted);
                state.total = state.total.max(total);
                state.asked = false;
                state.exhausted = if forced {
                    total >= state.limit
                } else {
                    granted < asked && total >= state.limit
                };
                if !state.answered {
                    state.answered = true;
                    if state.used > state.granted {
                        state.asked = true;
                        reconcile = Some((state.used - state.granted, state.limit));
                    }
                }
            }
        }
        if let Some((amount, limit)) = reconcile {
            match self.arc() {
                Some(budget) => {
                    self.inner
                        .pending
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(Claim {
                            budget,
                            key: key.to_owned(),
                            window,
                            amount,
                            limit,
                            forced: true,
                        });
                    self.inner.notify.notify_one();
                }
                None => self.failed(key, window),
            }
        }
    }

    /// A claim failed (the store is away): it may be asked again.
    pub fn failed(&self, key: &str, window: (u64, u64)) {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(state) = keys.get_mut(key)
            && state.window == window
        {
            state.asked = false;
        }
    }

    /// Queues a forced claim for every key of the current window that admitted beyond its
    /// claims (while the store was away).
    fn reconcile(&self) {
        let Some(this) = self.arc() else {
            return;
        };
        let now = now_ms();
        let mut claims = Vec::new();
        {
            let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
            keys.retain(|_, k| k.window.1 > now);
            for (key, state) in keys.iter_mut() {
                state.exhausted = false;
                if state.used > state.granted && !state.asked {
                    state.asked = true;
                    claims.push(Claim {
                        budget: this.clone(),
                        key: key.clone(),
                        window: state.window,
                        amount: state.used - state.granted,
                        limit: state.limit,
                        forced: true,
                    });
                }
            }
        }
        self.inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(claims);
    }

    /// What this instance admitted and claimed for `key` in the current window (tests and the
    /// admin view).
    #[must_use]
    pub fn usage(&self, key: &str) -> Option<(u64, u64)> {
        let keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        keys.get(key).map(|k| (k.used, k.granted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_800_000_000_000;

    /// Grants claims in order against one shared total, as a store would.
    struct Store {
        total: HashMap<String, u64>,
    }

    impl Store {
        fn serve(&mut self, limits: &SharedLimits) {
            for claim in limits.drain() {
                let total = self.total.entry(claim.key.clone()).or_default();
                let grant = if claim.forced {
                    claim.amount
                } else {
                    claim.amount.min(claim.limit.saturating_sub(*total))
                };
                *total += grant;
                claim.budget.granted(
                    &claim.key,
                    claim.window,
                    grant,
                    *total,
                    claim.amount,
                    claim.forced,
                );
            }
        }
    }

    fn instance(percent: u8, members: u64) -> (SharedLimits, Arc<Budget>) {
        let limits = SharedLimits::default();
        limits.configure(percent, false);
        limits.attach();
        limits.set_members(members);
        limits.set_store_up(true);
        let budget = limits.budget("q", WindowKind::Fixed(Duration::from_secs(60)));
        (limits, budget)
    }

    #[test]
    fn the_headroom_and_the_bound() {
        assert_eq!(headroom(30, 10, 3), 1);
        assert_eq!(headroom(1000, 10, 4), 25);
        assert_eq!(headroom(1000, 0, 4), 1);
        assert_eq!(share(30, 3), 10);
        assert_eq!(share(31, 3), 11);
        // L + N × max(c, ⌈L / N⌉).
        assert_eq!(bound(30, 10, 3), 60);
        assert_eq!(bound(1000, 10, 4), 2000);
        assert_eq!(bound(7, 0, 3), 7 + 3 * 3);
        assert_eq!(bound(30, 10, 1), 60);
    }

    /// Review finding M4: a key new to an instance is not refused after `c` requests while its
    /// first claim is on its way; up to the fair share is admitted, and what passed the grant
    /// is then added to the store's count.
    #[test]
    fn a_new_key_admits_the_fair_share_until_its_first_claim_returns() {
        let (limits, budget) = instance(10, 3);
        let admitted = (0..20)
            .filter(|_| matches!(budget.take_at("k", 60, T), Take::Allowed { .. }))
            .count();
        assert_eq!(admitted, 20, "⌈60 / 3⌉ before any answer, not c = 2");
        assert!(matches!(budget.take_at("k", 60, T), Take::Exceeded { .. }));
        // One claim was sent (1 + c); its answer reconciles the other 17 as a forced claim.
        let mut claims = limits.drain();
        assert_eq!(claims.len(), 1);
        let first = claims.remove(0);
        assert_eq!(first.amount, 3);
        assert!(!first.forced);
        budget.granted("k", first.window, 3, 3, 3, false);
        let forced = limits.drain();
        assert_eq!(forced.len(), 1);
        assert!(forced[0].forced);
        assert_eq!(forced[0].amount, 17);
        budget.granted("k", forced[0].window, 17, 20, 17, true);
        assert_eq!(budget.usage("k"), Some((20, 20)));
        // From now on the headroom rule: c = 2 more before the next claim returns.
        let more = (0..10)
            .filter(|_| matches!(budget.take_at("k", 60, T), Take::Allowed { .. }))
            .count();
        assert_eq!(more, 2);
    }

    /// A key new to an instance after the others used the whole budget: the instance admits at
    /// most its share, and the store's answer (nothing left) leaves it exhausted, even after
    /// its forced claim.
    #[test]
    fn a_new_key_on_a_used_up_budget_stops_at_the_share() {
        let (limits, budget) = instance(10, 3);
        let admitted = (0..30)
            .filter(|_| matches!(budget.take_at("k", 30, T), Take::Allowed { .. }))
            .count();
        assert_eq!(admitted, 10);
        let first = limits.drain().remove(0);
        budget.granted("k", first.window, 0, 30, first.amount, false);
        let forced = limits.drain().remove(0);
        assert_eq!(forced.amount, 10);
        budget.granted("k", forced.window, 10, 40, 10, true);
        assert!(matches!(budget.take_at("k", 30, T), Take::Exceeded { .. }));
        assert!(limits.drain().is_empty(), "exhausted: nothing asked again");
    }

    /// The worst case: every instance's claims are answered only after it used its whole
    /// headroom, in every order. The cluster never admits more than
    /// `L + N × max(c, ⌈L / N⌉)`.
    #[test]
    fn the_cluster_never_admits_more_than_the_bound() {
        for (limit, percent, n) in [(30u64, 10u8, 3u64), (100, 10, 4), (1000, 25, 5), (7, 0, 3)] {
            let instances: Vec<_> = (0..n).map(|_| instance(percent, n)).collect();
            let mut store = Store {
                total: HashMap::new(),
            };
            let mut admitted = 0u64;
            for round in 0..usize::try_from(limit * 3).unwrap() {
                for (i, (limits, budget)) in instances.iter().enumerate() {
                    // Each instance takes a burst before the store answers its claims.
                    for _ in 0..=(round + i) % 4 {
                        if matches!(budget.take_at("k", limit, T), Take::Allowed { .. }) {
                            admitted += 1;
                        }
                    }
                    if (round + i).is_multiple_of(3) {
                        store.serve(limits);
                    }
                }
            }
            for (limits, _) in &instances {
                store.serve(limits);
            }
            let ceiling = bound(limit, u32::from(percent), n);
            assert!(
                admitted <= ceiling,
                "L={limit} h={percent} N={n}: admitted {admitted} > {ceiling}"
            );
            assert!(admitted >= limit, "L={limit}: admitted only {admitted}");
        }
    }

    #[test]
    fn a_new_window_starts_again() {
        let (limits, budget) = instance(10, 1);
        let mut store = Store {
            total: HashMap::new(),
        };
        for _ in 0..20 {
            let _ = budget.take_at("k", 5, T);
            store.serve(&limits);
        }
        assert!(matches!(budget.take_at("k", 5, T), Take::Exceeded { .. }));
        store.total.clear();
        assert!(matches!(
            budget.take_at("k", 5, T + 60_000),
            Take::Allowed { .. }
        ));
    }

    #[test]
    fn without_the_store_an_instance_admits_its_share_then_reconciles() {
        let limits = SharedLimits::default();
        limits.configure(10, false);
        limits.attach();
        limits.set_members(3);
        let budget = limits.budget("q", WindowKind::Fixed(Duration::from_secs(60)));
        let admitted = (0..50)
            .filter(|_| matches!(budget.take_at("k", 30, T), Take::Allowed { .. }))
            .count();
        assert_eq!(admitted, 10, "⌈30 / 3⌉ while the store is away");
        assert!(
            limits.drain().is_empty(),
            "no claims while the store is away"
        );
        // The store returns: the ten admitted are added to its count.
        limits.set_store_up(true);
        let claims = limits.drain();
        assert_eq!(claims.len(), 1);
        assert!(claims[0].forced);
        assert_eq!(claims[0].amount, 10);
        // Fallback `instance`: the whole limit.
        let limits = SharedLimits::default();
        limits.configure(10, true);
        let budget = limits.budget("q", WindowKind::Fixed(Duration::from_secs(60)));
        let admitted = (0..50)
            .filter(|_| matches!(budget.take_at("k", 30, T), Take::Allowed { .. }))
            .count();
        assert_eq!(admitted, 30);
    }

    #[test]
    fn calendar_windows() {
        let kind = WindowKind::Calendar(Window::Hour);
        let (start, end) = kind.bounds(T + 1234);
        assert_eq!(end - start, 3_600_000);
        assert!(start <= T + 1234 && T + 1234 < end);
        let fixed = WindowKind::Fixed(Duration::from_millis(1500));
        assert_eq!(fixed.bounds(3001), (3000, 4500));
    }
}

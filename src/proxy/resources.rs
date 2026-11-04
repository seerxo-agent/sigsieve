//! Process-local admission; clients behind a forwarded socket share these bounds.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::Limits;
use crate::socket;

const TOKEN: u128 = 1_000_000_000;
const RECENT_SIGNATURES: usize = 256;
const DUPLICATE_WINDOW: Duration = Duration::from_secs(300);

pub(super) struct Budget {
    credit: u128,
    capacity: u128,
    rate: u32,
    updated: Instant,
}

impl Budget {
    pub(super) fn new(burst: u32, rate: u32, now: Instant) -> Self {
        Self {
            credit: u128::from(burst) * TOKEN,
            capacity: u128::from(burst) * TOKEN,
            rate,
            updated: now,
        }
    }

    pub(super) fn take(&mut self, now: Instant) -> bool {
        let refill = now
            .saturating_duration_since(self.updated)
            .as_nanos()
            .saturating_mul(u128::from(self.rate));
        self.credit = self.credit.saturating_add(refill).min(self.capacity);
        self.updated = self.updated.max(now);
        if self.credit < TOKEN {
            return false;
        }
        self.credit -= TOKEN;
        true
    }
}

struct State {
    requests: Budget,
    connections: Budget,
    signatures: Budget,
    recent: VecDeque<([u8; 32], Instant)>,
    active: usize,
    queue: VecDeque<u64>,
    next: u64,
}

pub(super) struct Resources {
    state: Mutex<State>,
    changed: Condvar,
    parallel: usize,
    queued: usize,
}

impl Resources {
    pub(super) fn new(limits: &Limits) -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(State {
                requests: Budget::new(limits.request_rate, limits.request_rate, now),
                connections: Budget::new(limits.connection_rate, limits.connection_rate, now),
                signatures: Budget::new(
                    limits.max_clients.min(u32::MAX as usize) as u32,
                    limits.signing_rate,
                    now,
                ),
                recent: VecDeque::new(),
                active: 0,
                queue: VecDeque::new(),
                next: 0,
            }),
            changed: Condvar::new(),
            parallel: limits.max_upstream,
            queued: limits.max_clients,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn request(&self) -> bool {
        self.lock().requests.take(Instant::now())
    }
    pub(super) fn connection(&self) -> bool {
        self.lock().connections.take(Instant::now())
    }

    /// Admit one signature. A destination-bound attempt is remembered by its
    /// verified (session id, key) pair, so a recorded session cannot obtain
    /// another signature for the same key by changing the user name or the
    /// RSA algorithm (F-47); the flags were already excluded. Legitimate OpenSSH clients sign at
    /// most once per session and key.
    pub(super) fn signature(&self, bound: Option<(&[u8], &[u8])>) -> bool {
        let digest = bound.map(|(session_id, key)| session_key_digest(session_id, key));
        self.signature_at(digest, Instant::now())
    }

    fn signature_at(&self, digest: Option<[u8; 32]>, now: Instant) -> bool {
        let mut state = self.lock();
        state
            .recent
            .retain(|(_, at)| now.saturating_duration_since(*at) < DUPLICATE_WINDOW);
        if digest.is_some_and(|d| state.recent.iter().any(|(old, _)| old == &d))
            || !state.signatures.take(now)
        {
            return false;
        }
        if let Some(digest) = digest {
            if state.recent.len() == RECENT_SIGNATURES {
                state.recent.pop_front();
            }
            // Remember attempts, including upstream failures; never cache signatures or retry.
            state.recent.push_back((digest, now));
        }
        true
    }

    pub(super) fn acquire(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<Permit<'_>> {
        let mut state = self.lock();
        socket::time_left(deadline, cancelled)?;
        if state.queue.len() >= self.queued {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "upstream request queue full",
            ));
        }
        let ticket = state.next;
        state.next = state.next.wrapping_add(1);
        state.queue.push_back(ticket);
        loop {
            let left = match socket::time_left(deadline, cancelled) {
                Ok(left) => left,
                Err(e) => {
                    state.queue.retain(|id| *id != ticket);
                    self.changed.notify_all();
                    return Err(e);
                }
            };
            if state.queue.front() == Some(&ticket) && state.active < self.parallel {
                state.queue.pop_front();
                state.active += 1;
                self.changed.notify_all();
                return Ok(Permit(self));
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, left.min(Duration::from_millis(100)))
                .unwrap_or_else(|e| e.into_inner());
            state = next;
        }
    }
}

/// Length-prefixed, so no two distinct pairs share an encoding.
fn session_key_digest(session_id: &[u8], key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [session_id, key] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

pub(super) struct Permit<'a>(&'a Resources);
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.lock().active -= 1;
        self.0.changed.notify_all();
    }
}

pub(super) struct LogWindow {
    since: Instant,
    emitted: u32,
    suppressed: u64,
}

impl LogWindow {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            since: now,
            emitted: 0,
            suppressed: 0,
        }
    }

    pub(super) fn finish(&mut self) -> u64 {
        std::mem::take(&mut self.suppressed)
    }

    /// Return the previous window's suppressed count when emitting a detail line.
    pub(super) fn admit(&mut self, now: Instant) -> Option<u64> {
        let mut suppressed = 0;
        if now.saturating_duration_since(self.since) >= Duration::from_secs(1) {
            self.since = now;
            self.emitted = 0;
            suppressed = std::mem::take(&mut self.suppressed);
        }
        if self.emitted == 16 {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.emitted += 1;
        Some(suppressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_refill_without_exceeding_the_burst() {
        let now = Instant::now();
        let mut budget = Budget::new(2, 4, now);
        assert!(budget.take(now));
        assert!(budget.take(now));
        assert!(!budget.take(now));
        assert!(!budget.take(now + Duration::from_millis(249)));
        assert!(budget.take(now + Duration::from_millis(250)));
        assert!(!budget.take(now + Duration::from_millis(250)));
        let later = now + Duration::from_secs(60);
        assert!(budget.take(later));
        assert!(budget.take(later));
        assert!(!budget.take(later));
        let mut reordered = Budget::new(1, 1, now);
        assert!(reordered.take(now));
        assert!(reordered.take(now + Duration::from_secs(1)));
        assert!(!reordered.take(now));
        assert!(!reordered.take(now + Duration::from_secs(1)));
    }

    #[test]
    fn duplicate_attempts_are_bounded_expire_and_are_instance_local() {
        let limits = Limits {
            max_clients: 1000,
            signing_rate: 1000,
            ..Limits::default()
        };
        let resources = Resources::new(&limits);
        let now = Instant::now();
        assert!(resources.signature_at(Some([7; 32]), now));
        assert!(!resources.signature_at(Some([7; 32]), now));
        assert!(Resources::new(&limits).signature_at(Some([7; 32]), now));
        assert!(resources.signature_at(Some([7; 32]), now + DUPLICATE_WINDOW));
        for i in 0u32..300 {
            assert!(resources.signature_at(
                Some(Sha256::digest(i.to_be_bytes()).into()),
                now + DUPLICATE_WINDOW
            ));
        }
        assert_eq!(resources.lock().recent.len(), RECENT_SIGNATURES);
        assert!(resources.signature_at(
            Some(Sha256::digest(0u32.to_be_bytes()).into()),
            now + DUPLICATE_WINDOW
        ));
        assert!(resources.signature_at(None, now + DUPLICATE_WINDOW));
        assert!(resources.signature_at(None, now + DUPLICATE_WINDOW));
    }

    #[test]
    fn one_destination_bound_signature_per_session_and_key() {
        let limits = Limits {
            max_clients: 1000,
            signing_rate: 1000,
            ..Limits::default()
        };
        let resources = Resources::new(&limits);
        assert!(resources.signature(Some((b"s1", b"key-a"))));
        // Same session and key: refused, whatever else the request said.
        assert!(!resources.signature(Some((b"s1", b"key-a"))));
        // Another key in the same session (publickey,publickey), and the same
        // key in another session (reconnect), are each admitted once.
        assert!(resources.signature(Some((b"s1", b"key-b"))));
        assert!(resources.signature(Some((b"s2", b"key-a"))));
        assert!(!resources.signature(Some((b"s2", b"key-a"))));
        // Length prefixes: moving bytes between the fields is a new pair.
        assert!(resources.signature(Some((b"s1k", b"ey-a"))));
        assert_ne!(
            session_key_digest(b"ab", b"c"),
            session_key_digest(b"a", b"bc")
        );
        // Unbound signing is not deduplicated.
        assert!(resources.signature(None));
        assert!(resources.signature(None));
    }

    #[test]
    fn refused_for_budget_is_not_remembered() {
        let resources = Resources::new(&Limits {
            max_clients: 1,
            signing_rate: 1,
            ..Limits::default()
        });
        let now = Instant::now(); // after the budget's own start
        let d = Some(session_key_digest(b"s1", b"key-a"));
        let other = Some(session_key_digest(b"s1", b"key-b"));
        assert!(resources.signature_at(other, now));
        // Budget empty: refused, and the pair is not consumed by the refusal.
        assert!(!resources.signature_at(d, now));
        assert!(resources.signature_at(d, now + Duration::from_secs(1)));
        assert!(!resources.signature_at(d, now + Duration::from_secs(2)));
    }

    #[test]
    fn concurrent_attempts_for_one_session_and_key_admit_exactly_one() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        let resources = Arc::new(Resources::new(&Limits {
            max_clients: 1000,
            signing_rate: 1000,
            ..Limits::default()
        }));
        let barrier = Arc::new(Barrier::new(16));
        let admitted: usize = (0..16)
            .map(|_| {
                let (r, b) = (Arc::clone(&resources), Arc::clone(&barrier));
                thread::spawn(move || {
                    b.wait();
                    r.signature(Some((b"s1", b"key-a")))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap() as usize)
            .sum();
        assert_eq!(admitted, 1);
    }

    #[test]
    fn logging_bounds_details_and_aggregates_suppression() {
        let now = Instant::now();
        let mut window = LogWindow::new(now);
        for _ in 0..16 {
            assert_eq!(window.admit(now), Some(0));
        }
        for _ in 0..10000 {
            assert_eq!(window.admit(now), None);
        }
        assert_eq!(window.admit(now + Duration::from_secs(1)), Some(10000));
        assert_eq!(window.admit(now + Duration::from_secs(1)), Some(0));
    }

    #[test]
    fn queue_deadline_cancellation_and_drop_release_capacity() {
        let resources = Resources::new(&Limits {
            max_upstream: 1,
            ..Limits::default()
        });
        let stop = AtomicBool::new(false);
        let first = resources
            .acquire(Instant::now() + Duration::from_secs(1), &stop)
            .unwrap();
        assert!(resources
            .acquire(Instant::now() + Duration::from_millis(20), &stop)
            .is_err());
        assert!(resources.lock().queue.is_empty());
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(resources
            .acquire(Instant::now() + Duration::from_secs(1), &stop)
            .is_err());
        drop(first);
        assert_eq!(resources.lock().active, 0);
        stop.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(resources
            .acquire(Instant::now() + Duration::from_secs(1), &stop)
            .is_ok());
    }

    #[test]
    fn upstream_queue_is_fifo_and_concurrency_is_bounded() {
        use std::sync::{mpsc, Arc};
        use std::thread;
        let resources = Arc::new(Resources::new(&Limits {
            max_upstream: 1,
            ..Limits::default()
        }));
        let stop = AtomicBool::new(false);
        let first = resources
            .acquire(Instant::now() + Duration::from_secs(5), &stop)
            .unwrap();
        let (tx, rx) = mpsc::channel();
        let mut workers = Vec::new();
        for id in 0..4 {
            let worker_resources = Arc::clone(&resources);
            let tx = tx.clone();
            workers.push(thread::spawn(move || {
                let _permit = worker_resources
                    .acquire(
                        Instant::now() + Duration::from_secs(5),
                        &AtomicBool::new(false),
                    )
                    .unwrap();
                assert_eq!(worker_resources.lock().active, 1);
                tx.send(id).unwrap();
            }));
            let start = Instant::now();
            while resources.lock().queue.len() != id + 1 {
                assert!(start.elapsed() < Duration::from_secs(2));
                thread::yield_now();
            }
        }
        drop(first);
        for id in 0..4 {
            assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), id);
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(resources.lock().active, 0);
        assert!(resources.lock().queue.is_empty());
    }
}

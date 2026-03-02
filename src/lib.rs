use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Duration, Utc};
use log::info;
use serde::{Deserialize, Serialize};
use std::time::{Duration as StdDuration, Instant};

pub const DEFAULT_HASH_LEN: usize = 32;
pub const DEFAULT_PEPPER_LEN: usize = 16;
pub const DEFAULT_SALT_LEN: usize = 16;
pub const DEFAULT_SESSION_LEN: usize = 32;

/// Serde helpers: hex array
#[derive(Clone, Serialize, Deserialize)]
pub struct HashConfig<const PEPPER_LEN: usize = DEFAULT_PEPPER_LEN> {
    #[serde(with = "serde_hex_array")]
    pub pepper: [u8; PEPPER_LEN],
    pub memory_kib: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

pub mod serde_hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    #[inline]
    pub fn bytes_to_hex<const N: usize>(bytes: &[u8; N]) -> String {
        let mut out = String::with_capacity(N * 2);
        for b in bytes {
            use core::fmt::Write;
            let _ = write!(&mut out, "{:02x}", b);
        }
        out
    }

    #[inline]
    pub fn hex_to_bytes<const N: usize>(s: &str) -> Result<[u8; N], String> {
        if s.len() != N * 2 {
            return Err(format!("expected {} bytes hex, got {}", N, s.len() / 2));
        }
        let mut out = [0u8; N];
        for i in 0..N {
            let idx = i * 2;
            out[i] = u8::from_str_radix(&s[idx..idx + 2], 16)
                .map_err(|e| format!("invalid hex: {}", e))?;
        }
        Ok(out)
    }

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let out = bytes_to_hex(bytes);
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D, const N: usize>(d: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        hex_to_bytes::<N>(&s).map_err(serde::de::Error::custom)
    }
}

pub mod serde_hex_array_vec {
    use super::serde_hex_array::{bytes_to_hex, hex_to_bytes};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    // Vec<[u8; N]> <-> Vec<String(hex)>
    pub fn serialize<S, const N: usize>(items: &Vec<[u8; N]>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for it in items {
            let hex = bytes_to_hex(it);
            seq.serialize_element(&hex)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, const N: usize>(d: D) -> Result<Vec<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_strings: Vec<String> = Deserialize::deserialize(d)?;
        let mut out = Vec::with_capacity(hex_strings.len());
        for hex_string in hex_strings {
            let bytes = hex_to_bytes::<N>(&hex_string).map_err(serde::de::Error::custom)?;
            out.push(bytes);
        }
        Ok(out)
    }
}

/// Hash benchmarking and config generation
impl<const PEPPER_LEN: usize> HashConfig<PEPPER_LEN> {
    pub fn benchmark(target_ms: u64) -> Self {
        info!("Benchmarking HashConfig parameters...");
        let test_password = "benchmark_password";
        let salt = [0u8; 16];
        let target_duration = StdDuration::from_millis(target_ms);

        info!(
            "Benchmark assumptions: target_duration={:?}, test_password='{}', salt={:?}",
            target_duration, test_password, salt
        );

        let pepper = Self::generate_random_pepper();
        info!("Generated random pepper for benchmark");

        let best_memory = Self::binary_search_param(
            target_duration,
            |memory| {
                let params = Params::new(memory, 3, 1, Some(32)).expect("argon2 params for memory");
                let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                let start = Instant::now();
                let mut out = [0u8; 32];
                let mut adv = Vec::new();
                adv.extend_from_slice(&salt);
                adv.extend_from_slice(&pepper);
                hasher
                    .hash_password_into(test_password.as_bytes(), &adv, &mut out)
                    .expect("hash during memory benchmark");
                start.elapsed()
            },
            32768,
            1048576,
        );

        let best_time = Self::binary_search_param(
            target_duration,
            |time| {
                let params =
                    Params::new(best_memory, time, 1, Some(32)).expect("argon2 params for time");
                let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                let start = Instant::now();
                let mut out = [0u8; 32];
                let mut adv = Vec::new();
                adv.extend_from_slice(&salt);
                adv.extend_from_slice(&pepper);
                hasher
                    .hash_password_into(test_password.as_bytes(), &adv, &mut out)
                    .expect("hash during time benchmark");
                start.elapsed()
            },
            1,
            10,
        );

        let best_lanes = Self::binary_search_param(
            target_duration,
            |lanes| {
                let params = Params::new(best_memory, best_time, lanes, Some(32))
                    .expect("argon2 params for lanes");
                let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                let start = Instant::now();
                let mut out = [0u8; 32];
                let mut adv = Vec::new();
                adv.extend_from_slice(&salt);
                adv.extend_from_slice(&pepper);
                hasher
                    .hash_password_into(test_password.as_bytes(), &adv, &mut out)
                    .expect("hash during lanes benchmark");
                start.elapsed()
            },
            1,
            8,
        );

        let best_config = Self {
            pepper,
            memory_kib: best_memory,
            time_cost: best_time,
            lanes: best_lanes,
        };

        let params = Params::new(best_memory, best_time, best_lanes, Some(32))
            .expect("argon2 params for final measurement");
        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let start = Instant::now();
        let mut out = [0u8; 32];
        let mut adv = Vec::new();
        adv.extend_from_slice(&salt);
        adv.extend_from_slice(&best_config.pepper);
        hasher
            .hash_password_into(test_password.as_bytes(), &adv, &mut out)
            .expect("hash during final benchmark");
        let final_duration = start.elapsed();

        info!(
            "Best HashConfig: memory={} KiB, time={}, lanes={}, duration={:?}",
            best_config.memory_kib, best_config.time_cost, best_config.lanes, final_duration
        );
        best_config
    }

    fn generate_random_pepper() -> [u8; PEPPER_LEN] {
        let mut bytes = [0u8; PEPPER_LEN];
        getrandom::fill(&mut bytes).expect("generate random pepper");
        bytes
    }

    fn binary_search_param<F>(target: StdDuration, measure: F, min: u32, max: u32) -> u32
    where
        F: Fn(u32) -> StdDuration,
    {
        let mut low = min;
        let mut high = max;
        let mut best = min;
        let mut best_diff = StdDuration::from_secs(1000);

        while low <= high {
            let mid = low + (high - low) / 2;
            let duration = measure(mid);
            let diff = if duration > target {
                duration - target
            } else {
                target - duration
            };

            if diff < best_diff {
                best = mid;
                best_diff = diff;
            }

            if duration < target {
                low = mid + 1;
            } else {
                if mid == 0 {
                    break;
                }
                high = mid - 1;
            }
        }

        best
    }
}

/// KV trait
pub trait KVTrait<K, V>
where
    K: ?Sized,
{
    fn get(&self, key: &K) -> Option<V>;
    fn set(&self, key: &K, value: V);
    fn contains(&self, key: &K) -> bool;
    fn delete(&self, key: &K) -> bool;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionValue<const SESSION_LEN: usize> {
    #[serde(with = "serde_hex_array")]
    pub session_key: [u8; SESSION_LEN],
    pub linked_accounts_cache: Vec<Box<str>>,
    pub last_time: DateTime<Utc>,
    pub created_time: DateTime<Utc>,
    pub primary_account: Option<Box<str>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccountValue<const SALT_LEN: usize, const HASH_LEN: usize, const SESSION_LEN: usize> {
    #[serde(with = "serde_hex_array")]
    pub password_hash: [u8; HASH_LEN],
    #[serde(with = "serde_hex_array")]
    pub salt: [u8; SALT_LEN],
    pub last_time: DateTime<Utc>,
    #[serde(with = "serde_hex_array_vec")]
    pub authed_linked_sessions: Vec<[u8; SESSION_LEN]>,
}

/// Fast Lock
mod account_lock {
    use ahash::AHasher;
    use parking_lot::{Mutex, MutexGuard};
    use std::hash::{Hash, Hasher};

    // SHARDS must be power of two for bitmask
    pub struct AccountLocks<const SHARDS: usize> {
        locks: [Mutex<()>; SHARDS],
    }

    impl<const SHARDS: usize> AccountLocks<SHARDS> {
        pub fn new() -> Self {
            debug_assert!(SHARDS.is_power_of_two());
            Self {
                locks: std::array::from_fn(|_| Mutex::new(())),
            }
        }

        #[inline]
        fn shard_for_username(username: &str) -> usize {
            let mut h = AHasher::default();
            username.hash(&mut h);
            (h.finish() as usize) & (SHARDS - 1)
        }

        #[inline]
        pub fn lock_account<'a>(&'a self, username: &str) -> MutexGuard<'a, ()> {
            let idx = Self::shard_for_username(username);
            self.locks[idx].lock()
        }
    }
}


/// Main AuthManager
/// - sessions はキャッシュ扱い。必要なら verify して primary_account を落とす。
/// - account 側が正。session はキャッシュ更新
pub struct AuthManager<
    S,
    A,
    const SESSION_LEN: usize = DEFAULT_SESSION_LEN,
    const HASH_LEN: usize = DEFAULT_HASH_LEN,
    const PEPPER_LEN: usize = DEFAULT_PEPPER_LEN,
    const SALT_LEN: usize = DEFAULT_SALT_LEN,
    const ACCOUNT_LOCK_SHARDS: usize = 4096,
> where
    S: KVTrait<[u8; SESSION_LEN], SessionValue<SESSION_LEN>> + Send + Sync,
    A: KVTrait<str, AccountValue<SALT_LEN, HASH_LEN, SESSION_LEN>> + Send + Sync,
{
    // NOTE: これらを pub にすると、AuthManager を介さない更新で整合が壊れる可能性が上がる
    pub sessions: S,
    pub accounts: A,

    pub session_timeout: Duration,
    pub account_timeout: Duration,
    pub password_hasher: Argon2<'static>,
    pub pepper: [u8; PEPPER_LEN],

    account_locks: account_lock::AccountLocks<ACCOUNT_LOCK_SHARDS>,
}

impl<
    S,
    A,
    const SESSION_LEN: usize,
    const HASH_LEN: usize,
    const PEPPER_LEN: usize,
    const SALT_LEN: usize,
    const ACCOUNT_LOCK_SHARDS: usize,
> AuthManager<S, A, SESSION_LEN, HASH_LEN, PEPPER_LEN, SALT_LEN, ACCOUNT_LOCK_SHARDS>
where
    S: KVTrait<[u8; SESSION_LEN], SessionValue<SESSION_LEN>> + Send + Sync,
    A: KVTrait<str, AccountValue<SALT_LEN, HASH_LEN, SESSION_LEN>> + Send + Sync,
{
    pub fn new(
        sessions: S,
        accounts: A,
        session_timeout: Duration,
        account_timeout: Duration,
        hash_config: HashConfig<PEPPER_LEN>,
    ) -> Self {
        Self {
            sessions,
            accounts,
            session_timeout,
            account_timeout,
            password_hasher: Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(
                    hash_config.memory_kib,
                    hash_config.time_cost,
                    hash_config.lanes,
                    Some(HASH_LEN),
                )
                .expect("argon2 hash params"),
            ),
            pepper: hash_config.pepper,
            account_locks: account_lock::AccountLocks::new(),
        }
    }

    /// session_id はランダム生成。衝突したらリトライ。
    pub fn create_session(&self) -> [u8; SESSION_LEN] {
        let session_id = Self::generate_session();
        if self.sessions.contains(&session_id) {
            return self.create_session();
        }
        let session_value = SessionValue::<SESSION_LEN> {
            session_key: session_id,
            linked_accounts_cache: Vec::new(),
            last_time: Utc::now(),
            created_time: Utc::now(),
            primary_account: None,
        };
        self.sessions.set(&session_id, session_value);
        session_id
    }

    pub fn delete_session(&self, session_id: &[u8; SESSION_LEN]) -> bool {
        self.sessions.delete(session_id)
    }

    /// ガード入り
    /// Noneならcreate sessionするなりするとよい
    pub fn get_and_verify_session(
        &self,
        session_id: &[u8; SESSION_LEN],
    ) -> Option<SessionValue<SESSION_LEN>> {
        if let Some(mut session) = self.update_or_gc_session(session_id) {
            if let Some(primary) = session.primary_account.clone() {
                // auth_verify の正は account 側
                if !self.auth_verify(session_id, &primary) {
                    session.primary_account = None;
                    // sessionはキャッシュ。ここで set するのはベストエフォート
                    self.sessions.set(session_id, session.clone());
                }
            }
            return Some(session);
        }
        None
    }

    pub fn update_or_gc_session(
        &self,
        session_id: &[u8; SESSION_LEN],
    ) -> Option<SessionValue<SESSION_LEN>> {
        if let Some(mut session) = self.gc_sessions(session_id) {
            session.last_time = Utc::now();
            self.sessions.set(session_id, session.clone());
            return Some(session);
        }
        None
    }

    pub fn gc_sessions(&self, session_id: &[u8; SESSION_LEN]) -> Option<SessionValue<SESSION_LEN>> {
        if let Some(session) = self.sessions.get(session_id) {
            let now = Utc::now();
            if now - session.last_time > self.session_timeout {
                let _ = self.delete_session(session_id);
                return None;
            }
            Some(session)
        } else {
            None
        }
    }

    pub fn set_primary_account(&self, session_id: &[u8; SESSION_LEN], username: &str) -> bool {
        // primary_account はヒントなので verify 必須
        if self.auth_verify(session_id, username) {
            if let Some(mut session) = self.sessions.get(session_id) {
                session.primary_account = Some(username.into());
                self.sessions.set(session_id, session);
                return true;
            }
        }
        false
    }

    pub fn add_account(&self, username: &str, password: &str) {
        let _g = self.account_locks.lock_account(username);

        let salt = Self::generate_random_salt();
        let password_hash = self.hash_password(password, &salt);
        let account_value = AccountValue::<SALT_LEN, HASH_LEN, SESSION_LEN> {
            password_hash,
            salt,
            last_time: Utc::now(),
            authed_linked_sessions: Vec::new(),
        };
        self.accounts.set(username, account_value);
    }

    pub fn delete_account(&self, username: &str) -> bool {
        let _g = self.account_locks.lock_account(username);

        // session側はキャッシュ扱いなので、この掃除はベストエフォート
        if let Some(account) = self.accounts.get(username) {
            for session_id in &account.authed_linked_sessions {
                if let Some(mut session_value) = self.sessions.get(session_id) {
                    session_value
                        .linked_accounts_cache
                        .retain(|a| a.as_ref() != username);
                    if session_value.primary_account.as_deref() == Some(username) {
                        session_value.primary_account = None;
                    }
                    self.sessions.set(session_id, session_value);
                }
            }
            self.accounts.delete(username)
        } else {
            false
        }
    }

    pub fn get_account(
        &self,
        username: &str,
    ) -> Option<AccountValue<SALT_LEN, HASH_LEN, SESSION_LEN>> {
        self.accounts.get(username)
    }

    pub fn auth_login(
        &self,
        session_id: &[u8; SESSION_LEN],
        username: &str,
        password: &str,
    ) -> bool {
        let _g = self.account_locks.lock_account(username);

        if let Some(mut account) = self.accounts.get(username) {
            let expected_hash = self.hash_password(password, &account.salt);
            if expected_hash != account.password_hash {
                return false;
            }

            // account側が正。ここだけ確実に更新する
            if !account.authed_linked_sessions.contains(session_id) {
                account.authed_linked_sessions.push(*session_id);
                account.last_time = Utc::now();
                self.accounts.set(username, account);
            }

            // session側はキャッシュ更新（ベストエフォート）
            if let Some(mut session) = self.sessions.get(session_id) {
                if !session
                    .linked_accounts_cache
                    .iter()
                    .any(|a| a.as_ref() == username)
                {
                    session.linked_accounts_cache.push(username.into());
                }
                self.sessions.set(session_id, session);
            }

            return true;
        }
        false
    }

    /// 認可
    pub fn auth_verify(&self, session_id: &[u8; SESSION_LEN], username: &str) -> bool {
        if let Some(account) = self.accounts.get(username) {
            account.authed_linked_sessions.contains(session_id)
        } else {
            false
        }
    }

    /// logout は account 側だけ更新
    pub fn auth_logout(&self, session_id: &[u8; SESSION_LEN], username: &str) -> bool {
        let _g = self.account_locks.lock_account(username);

        if let Some(mut account) = self.accounts.get(username) {
            let before = account.authed_linked_sessions.len();
            account.authed_linked_sessions.retain(|s| s != session_id);
            let changed = account.authed_linked_sessions.len() != before;
            if changed {
                account.last_time = Utc::now();
                self.accounts.set(username, account);
            }
            return changed;
        }
        false
    }

    fn hash_password(&self, password: &str, salt: &[u8; SALT_LEN]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        let mut adv = Vec::with_capacity(SALT_LEN + PEPPER_LEN);
        adv.extend_from_slice(salt);
        adv.extend_from_slice(&self.pepper);
        self.password_hasher
            .hash_password_into(password.as_bytes(), &adv, &mut out)
            .expect("argon2 hash_password_into");
        out
    }

    fn generate_random_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).expect("generate random salt");
        salt
    }

    fn generate_session() -> [u8; SESSION_LEN] {
        let mut session_id = [0u8; SESSION_LEN];
        getrandom::fill(&mut session_id).expect("generate random session ID");
        session_id
    }
}
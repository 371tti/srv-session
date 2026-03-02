use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Duration, Utc};
use log::{debug, info};
use std::time::{Duration as StdDuration, Instant};

pub const DEFAULT_HASH_LEN: usize = 32;
pub const DEFAULT_PEPPER_LEN: usize = 16;
pub const DEFAULT_SALT_LEN: usize = 16;
pub const DEFAULT_SESSION_LEN: usize = 32;

#[derive(Clone)]
pub struct HashConfig<const PEPPER_LEN: usize = DEFAULT_PEPPER_LEN> {
    pub pepper: [u8; PEPPER_LEN],
    pub memory_kib: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

impl<const PEPPER_LEN: usize> serde::Serialize for HashConfig<PEPPER_LEN> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("HashConfig", 4)?;
        let mut hex_pepper = String::with_capacity(PEPPER_LEN * 2);
        for b in &self.pepper {
            use std::fmt::Write;
            write!(&mut hex_pepper, "{:02x}", b).unwrap();
        }
        state.serialize_field("pepper", &hex_pepper)?;
        state.serialize_field("memory_kib", &self.memory_kib)?;
        state.serialize_field("time_cost", &self.time_cost)?;
        state.serialize_field("lanes", &self.lanes)?;
        state.end()
    }
}

impl<'de, const PEPPER_LEN: usize> serde::Deserialize<'de> for HashConfig<PEPPER_LEN> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct HashConfigHelper {
            pepper: String,
            memory_kib: u32,
            time_cost: u32,
            lanes: u32,
        }
        let helper = HashConfigHelper::deserialize(deserializer)?;
        let s = helper.pepper.as_str();
        if s.len() != PEPPER_LEN * 2 {
            return Err(serde::de::Error::invalid_length(
                s.len() / 2,
                &format!("expected {} bytes for pepper", PEPPER_LEN).as_str(),
            ));
        }
        let mut pepper = [0u8; PEPPER_LEN];
        for (i, byte) in pepper.iter_mut().enumerate() {
            let idx = i * 2;
            *byte = u8::from_str_radix(&s[idx..idx + 2], 16).map_err(serde::de::Error::custom)?;
        }
        Ok(HashConfig {
            pepper,
            memory_kib: helper.memory_kib,
            time_cost: helper.time_cost,
            lanes: helper.lanes,
        })
    }
}

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
                let duration = start.elapsed();
                debug!("Memory {} KiB: duration={:?}", memory, duration);
                duration
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
                let duration = start.elapsed();
                debug!("Time {}: duration={:?}", time, duration);
                duration
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
                let duration = start.elapsed();
                debug!("Lanes {}: duration={:?}", lanes, duration);
                duration
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

/// DBへの直接アクセスはやめてください
/// キャッシュなどの階層構造を実装し、できる限りレイテンシを減らす実装をしてください
/// DashMapとかがおすすめ
pub trait KVTrait<K, V>
where
    K: ?Sized,
{
    fn get(&self, key: &K) -> Option<V>;
    fn set(&self, key: &K, value: V);
    fn contains(&self, key: &K) -> bool;
    fn delete(&self, key: &K) -> bool;
}

/// セッションのデータ構造
pub struct SessionValue<const SESSION_LEN: usize> {
    pub session_key: [u8; SESSION_LEN],
    pub linked_accounts: Vec<Box<str>>,
    pub last_time: DateTime<Utc>,
    pub created_time: DateTime<Utc>,
}

/// アカウントのデータ構造
pub struct AccountValue<const SALT_LEN: usize, const HASH_LEN: usize, const SESSION_LEN: usize> {
    pub password_hash: [u8; HASH_LEN],
    pub salt: [u8; SALT_LEN],
    pub last_time: DateTime<Utc>,
    pub linked_sessions: Vec<[u8; SESSION_LEN]>,
}

/// 認証マネージャー
pub struct AuthManager<
    S,
    A,
    const SESSION_LEN: usize = DEFAULT_SESSION_LEN,
    const HASH_LEN: usize = DEFAULT_HASH_LEN,
    const PEPPER_LEN: usize = DEFAULT_PEPPER_LEN,
    const SALT_LEN: usize = DEFAULT_SALT_LEN,
> where
    S: KVTrait<[u8; SESSION_LEN], SessionValue<SESSION_LEN>> + Send + Sync,
    A: KVTrait<str, AccountValue<SALT_LEN, HASH_LEN, SESSION_LEN>> + Send + Sync,
{
    pub sessions: S,
    pub accounts: A,
    pub session_timeout: Duration,
    pub account_timeout: Duration,
    pub password_hasher: Argon2<'static>,
    pub pepper: [u8; PEPPER_LEN],
}

impl<
    S,
    A,
    const SESSION_LEN: usize,
    const HASH_LEN: usize,
    const PEPPER_LEN: usize,
    const SALT_LEN: usize,
> AuthManager<S, A, SESSION_LEN, HASH_LEN, PEPPER_LEN, SALT_LEN>
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
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(
                    hash_config.memory_kib,
                    hash_config.time_cost,
                    hash_config.lanes,
                    Some(HASH_LEN),
                )
                .expect("argon2 hash params"),
            ),
            pepper: hash_config.pepper,
        }
    }

    /// 新しいセッションを追加
    pub fn create_session(&self) -> [u8; SESSION_LEN] {
        let session_id = Self::generate_session();
        if self.sessions.contains(&session_id) {
            return self.create_session(); // Regenerate if collision occurs
        }
        let session_value = SessionValue::<SESSION_LEN> {
            session_key: session_id,
            linked_accounts: Vec::new(),
            last_time: Utc::now(),
            created_time: Utc::now(),
        };
        self.sessions.set(&session_id, session_value);
        session_id
    }

    /// セッションを削除
    pub fn delete_session(&self, session_id: &[u8; SESSION_LEN]) -> bool {
        if let Some(session) = self.sessions.get(session_id) {
            for account in session.linked_accounts {
                if let Some(mut account_value) = self.accounts.get(&account) {
                    account_value.linked_sessions.retain(|s| s != session_id);
                    self.accounts.set(&account, account_value);
                }
            }
            self.sessions.delete(session_id)
        } else {
            false
        }
    }

    /// セッションを取得
    pub fn get_session(&self, session_id: &[u8; SESSION_LEN]) -> Option<SessionValue<SESSION_LEN>> {
        self.sessions.get(session_id)
    }

    /// 新しいアカウントを追加
    pub fn add_account(&self, username: &str, password: &str) {
        let salt = Self::generate_random_salt();
        let password_hash = self.hash_password(password, &salt);
        let account_value = AccountValue::<SALT_LEN, HASH_LEN, SESSION_LEN> {
            password_hash,
            salt,
            last_time: Utc::now(),
            linked_sessions: Vec::new(),
        };
        self.accounts.set(username, account_value);
    }

    /// アカウントを削除
    pub fn delete_account(&self, username: &str) -> bool {
        if let Some(account) = self.accounts.get(username) {
            for session_id in account.linked_sessions {
                if let Some(mut session_value) = self.sessions.get(&session_id) {
                    session_value
                        .linked_accounts
                        .retain(|a| a.as_ref() != username);
                    self.sessions.set(&session_id, session_value);
                }
            }
            self.accounts.delete(username)
        } else {
            false
        }
    }

    /// アカウントを取得
    pub fn get_account(
        &self,
        username: &str,
    ) -> Option<AccountValue<SALT_LEN, HASH_LEN, SESSION_LEN>> {
        self.accounts.get(username)
    }

    /// セッションを検査して、期限切れなら削除
    pub fn check_and_gc_session(
        &self,
        session_id: &[u8; SESSION_LEN],
    ) -> Option<SessionValue<SESSION_LEN>> {
        if let Some(session) = self.sessions.get(session_id) {
            let now = Utc::now();
            if now - session.last_time > self.session_timeout {
                self.delete_session(session_id);
                return Some(session);
            }
        }
        None
    }

    /// ログイン処理
    pub fn auth_login(
        &self,
        session_id: &[u8; SESSION_LEN],
        username: &str,
        password: &str,
    ) -> bool {
        if let Some(account) = self.accounts.get(username) {
            let expected_hash = self.hash_password(password, &account.salt);
            if expected_hash == account.password_hash
                && let Some(session) = self.sessions.get(session_id)
            {
                return self.link_account_to_session(username, session_id, account, session);
            }
        }
        false
    }

    /// ログアウト処理
    pub fn auth_logout(&self, session_id: &[u8; SESSION_LEN], username: &str) -> bool {
        if let Some(account) = self.accounts.get(username) {
            if let Some(session) = self.sessions.get(session_id) {
                return self.unlink_account_from_session(username, session_id, account, session);
            }
        }
        false
    }

    /// セッションとアカウントをリンク
    pub fn link_account_to_session(
        &self,
        username: &str,
        session_id: &[u8; SESSION_LEN],
        mut account: AccountValue<SALT_LEN, HASH_LEN, SESSION_LEN>,
        mut session: SessionValue<SESSION_LEN>,
    ) -> bool {
        account.linked_sessions.push(*session_id);
        session.linked_accounts.push(username.into());
        self.accounts.set(username, account);
        self.sessions.set(session_id, session);
        true
    }

    /// セッションとアカウントのリンクを解除
    pub fn unlink_account_from_session(
        &self,
        username: &str,
        session_id: &[u8; SESSION_LEN],
        mut account: AccountValue<SALT_LEN, HASH_LEN, SESSION_LEN>,
        mut session: SessionValue<SESSION_LEN>,
    ) -> bool {
        account.linked_sessions.retain(|s| s != session_id);
        session.linked_accounts.retain(|a| a.as_ref() != username);
        self.accounts.set(username, account);
        self.sessions.set(session_id, session);
        true
    }

    fn hash_password(&self, password: &str, salt: &[u8; SALT_LEN]) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        let mut adv = Vec::new();
        adv.extend_from_slice(salt);
        adv.extend_from_slice(&self.pepper);
        self.password_hasher
            .hash_password_into(password.as_bytes(), &adv, &mut out)
            .unwrap();
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

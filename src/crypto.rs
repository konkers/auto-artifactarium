use std::collections::HashMap;

use rand_mt::Mt64;
use tracing::{debug, info, instrument, trace, warn};

use crate::bytes_as_hex;
use crate::cs_rand::Random;

#[instrument(skip_all)]
pub fn decrypt_command(key: &[u8], encrypted: &mut [u8]) {
    trace!(data = bytes_as_hex(encrypted), "before decryption");

    for i in 0..encrypted.len() {
        encrypted[i] ^= key[i % key.len()];
    }

    trace!(data = bytes_as_hex(encrypted), "after decryption");
}

pub fn lookup_initial_key(initial_keys: &HashMap<u16, Vec<u8>>, bytes: &[u8]) -> Option<Vec<u8>> {
    let version = u16::from_be_bytes(bytes[..2].try_into().unwrap()) ^ 0x4567;

    // attempt to fetch from user provided initial keys, otherwise use our own baked-in ones
    let key = initial_keys.get(&version).cloned();
    match key {
        Some(key) => {
            info!(version, "found initial decryption key");
            Some(key)
        }
        None => {
            info!(version, "didn't find decryption key");
            None
        }
    }
}

pub const KEY_LEN: usize = 4096;

/// Recover the session key from a command body whose contents are already known.
///
/// The key repeats every [`KEY_LEN`] bytes, so a long command carries it dozens
/// of times over. The anti-cheat Lua shell body measures 167875 bytes and has
/// been observed byte-identical across client processes and devices, giving 41
/// copies of the key — the frame around it grows with `client_sequence_id`, so
/// the body is matched up from the trailer instead of by frame length.
///
/// Every key byte needs a majority among the copies it appears in; a body that
/// differs from the stored one leaves its region without one, and the candidate
/// is rejected rather than half-recovered.
pub fn key_from_known_body(known_body: &[u8], frame: &[u8]) -> Option<Vec<u8>> {
    const TAIL_LEN: usize = 2;
    let start = frame.len().checked_sub(TAIL_LEN + known_body.len())?;
    if known_body.len() < KEY_LEN * 2 {
        return None;
    }
    let body = &frame[start..start + known_body.len()];

    let mut votes = vec![[0u16; 256]; KEY_LEN];
    for (i, (a, b)) in known_body.iter().zip(body.iter()).enumerate() {
        votes[(start + i) % KEY_LEN][(*a ^ *b) as usize] += 1;
    }

    let mut key = Vec::with_capacity(KEY_LEN);
    for tally in &votes {
        let (winner, count) = tally
            .iter()
            .enumerate()
            .max_by_key(|(_, count)| **count)
            .map(|(byte, count)| (byte as u8, *count))
            .unwrap();
        let copies = tally.iter().sum::<u16>();
        if count * 2 <= copies {
            return None;
        }
        key.push(winner);
    }
    Some(key)
}

pub fn new_key_from_seed(seed: u64) -> Vec<u8> {
    // mersenne twister generator
    let mut first = Mt64::new(seed);
    let mut generator = Mt64::new(first.next_u64());

    let _ = generator.next_u64(); // skip first number

    let mut key = Vec::with_capacity(512);
    for _ in 0..512 {
        for b in generator.next_u64().to_be_bytes() {
            key.push(b);
        }
    }
    key
}

pub fn guess(seed: i64, server_seed: u64, depth: i32, data: Vec<u8>) -> Option<Vec<u8>> {
    // Attempt to generate the key.
    let mut generator = Random::seeded(seed as i32);
    for _ in 0..depth {
        let client_seed = generator.next_safe_uint64();

        let seed = client_seed ^ server_seed;
        let key = new_key_from_seed(seed);

        let mut clone = data.clone();
        decrypt_command(&key, &mut clone);

        if clone[0] == 0x45
            && clone[1] == 0x67
            && clone[clone.len() - 2] == 0x89
            && clone[clone.len() - 1] == 0xAB
        {
            debug!("Found encryption key seed: {seed}");
            return Some(key);
        }
    }

    None
}

pub fn bruteforce(sent_time: u64, server_seed: u64, data: Vec<u8>) -> Option<(u64, Vec<u8>)> {
    debug!("Running bruteforce loop.");
    // Generate new seeds.
    for i in 0..3000i64 {
        let offset = if i % 2 == 0 { i / 2 } else { -(i - 1) / 2 };
        let time = sent_time as i64 + offset; // This will act as the seed.

        if let Some(key) = guess(time, server_seed, 5, data.clone()) {
            return Some((time as u64, key));
        }
    }
    warn!("Unable to find the encryption key seed.");
    None
}

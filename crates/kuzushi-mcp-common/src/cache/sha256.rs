pub(crate) fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = initial_hash_state();
    for chunk in padded_sha256_message(data).chunks_exact(64) {
        compress_chunk(&mut state, chunk, &K);
    }
    hash_state_bytes(&state)
}

fn initial_hash_state() -> [u32; 8] {
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ]
}

fn padded_sha256_message(data: &[u8]) -> Vec<u8> {
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    msg
}

fn compress_chunk(state: &mut [u32; 8], chunk: &[u8], round_keys: &[u32; 64]) {
    let schedule = message_schedule(chunk);
    let mut working = *state;
    for i in 0..64 {
        let (next_a, next_e) = compression_round(working, schedule[i], round_keys[i]);
        working = [
            next_a, working[0], working[1], working[2], next_e, working[4], working[5], working[6],
        ];
    }
    for (state_word, working_word) in state.iter_mut().zip(working) {
        *state_word = state_word.wrapping_add(working_word);
    }
}

fn message_schedule(chunk: &[u8]) -> [u32; 64] {
    let mut schedule = [0u32; 64];
    for (i, slot) in schedule.iter_mut().enumerate().take(16) {
        let off = i * 4;
        *slot = u32::from_be_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
    }
    for i in 16..64 {
        schedule[i] = schedule[i - 16]
            .wrapping_add(schedule_sigma0(schedule[i - 15]))
            .wrapping_add(schedule[i - 7])
            .wrapping_add(schedule_sigma1(schedule[i - 2]));
    }
    schedule
}

fn compression_round(state: [u32; 8], schedule_word: u32, round_key: u32) -> (u32, u32) {
    let [a, b, c, d, e, f, g, h] = state;
    let temp1 = h
        .wrapping_add(compression_sigma1(e))
        .wrapping_add(choose(e, f, g))
        .wrapping_add(round_key)
        .wrapping_add(schedule_word);
    let temp2 = compression_sigma0(a).wrapping_add(majority(a, b, c));
    (temp1.wrapping_add(temp2), d.wrapping_add(temp1))
}

fn schedule_sigma0(word: u32) -> u32 {
    word.rotate_right(7) ^ word.rotate_right(18) ^ (word >> 3)
}

fn schedule_sigma1(word: u32) -> u32 {
    word.rotate_right(17) ^ word.rotate_right(19) ^ (word >> 10)
}

fn compression_sigma0(word: u32) -> u32 {
    word.rotate_right(2) ^ word.rotate_right(13) ^ word.rotate_right(22)
}

fn compression_sigma1(word: u32) -> u32 {
    word.rotate_right(6) ^ word.rotate_right(11) ^ word.rotate_right(25)
}

fn choose(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn hash_state_bytes(state: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// kp_aes.h —— 极简 AES-128 解密（ECB 单块），仅用于解出 DSP 参数表
// 只依赖 <stdint.h> / <string.h>，不调用任何系统库，行为在各 iOS 版本上一致。
// 已与 openssl aes-128-ecb 逐字节对拍。
#ifndef KP_AES_H
#define KP_AES_H

#include <stdint.h>
#include <string.h>

static uint8_t kpa_sbox[256];
static uint8_t kpa_isbox[256];
static int     kpa_ready = 0;

static uint8_t kpa_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static uint8_t kpa_pow(uint8_t a, int n) {
    uint8_t r = 1;
    while (n > 0) {
        if (n & 1) r = kpa_mul(r, a);
        a = kpa_mul(a, a);
        n >>= 1;
    }
    return r;
}

static uint8_t kpa_rotl8(uint8_t x, int s) {
    return (uint8_t)((x << s) | (x >> (8 - s)));
}

static void kpa_init(void) {
    if (kpa_ready) return;
    for (int x = 0; x < 256; x++) {
        uint8_t inv = (x == 0) ? 0 : kpa_pow((uint8_t)x, 254);
        uint8_t s = inv ^ kpa_rotl8(inv, 1) ^ kpa_rotl8(inv, 2)
                        ^ kpa_rotl8(inv, 3) ^ kpa_rotl8(inv, 4) ^ 0x63;
        kpa_sbox[x] = s;
        kpa_isbox[s] = (uint8_t)x;
    }
    kpa_ready = 1;
}

static void kpa_expand(const uint8_t key[16], uint8_t rk[176]) {
    uint8_t rc = 1;
    memcpy(rk, key, 16);
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4];
        memcpy(t, rk + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t tmp = t[0];
            t[0] = kpa_sbox[t[1]] ^ rc;
            t[1] = kpa_sbox[t[2]];
            t[2] = kpa_sbox[t[3]];
            t[3] = kpa_sbox[tmp];
            rc = kpa_mul(rc, 2);
        }
        rk[i + 0] = rk[i - 16 + 0] ^ t[0];
        rk[i + 1] = rk[i - 16 + 1] ^ t[1];
        rk[i + 2] = rk[i - 16 + 2] ^ t[2];
        rk[i + 3] = rk[i - 16 + 3] ^ t[3];
    }
}

static void kpa_add_round_key(uint8_t s[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void kpa_inv_shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    memcpy(t, s, 16);
    // 状态按列存储：s[r + 4c]
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            s[r + 4 * ((c + r) % 4)] = t[r + 4 * c];
        }
    }
}

static void kpa_inv_sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = kpa_isbox[s[i]];
}

static void kpa_inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[4 * c + 0], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
        s[4 * c + 0] = kpa_mul(a0, 0x0e) ^ kpa_mul(a1, 0x0b) ^ kpa_mul(a2, 0x0d) ^ kpa_mul(a3, 0x09);
        s[4 * c + 1] = kpa_mul(a0, 0x09) ^ kpa_mul(a1, 0x0e) ^ kpa_mul(a2, 0x0b) ^ kpa_mul(a3, 0x0d);
        s[4 * c + 2] = kpa_mul(a0, 0x0d) ^ kpa_mul(a1, 0x09) ^ kpa_mul(a2, 0x0e) ^ kpa_mul(a3, 0x0b);
        s[4 * c + 3] = kpa_mul(a0, 0x0b) ^ kpa_mul(a1, 0x0d) ^ kpa_mul(a2, 0x09) ^ kpa_mul(a3, 0x0e);
    }
}

static void kpa_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    kpa_init();
    uint8_t rk[176];
    kpa_expand(key, rk);
    uint8_t s[16];
    memcpy(s, in, 16);

    kpa_add_round_key(s, rk + 160);
    for (int round = 9; round >= 1; round--) {
        kpa_inv_shift_rows(s);
        kpa_inv_sub_bytes(s);
        kpa_add_round_key(s, rk + 16 * round);
        kpa_inv_mix_columns(s);
    }
    kpa_inv_shift_rows(s);
    kpa_inv_sub_bytes(s);
    kpa_add_round_key(s, rk);

    memcpy(out, s, 16);
}

// ECB 解密 len 字节（len 必须是 16 的倍数）
static void kpa_decrypt_ecb(const uint8_t key[16], const uint8_t *in, uint8_t *out, int len) {
    for (int off = 0; off + 16 <= len; off += 16) {
        kpa_decrypt_block(key, in + off, out + off);
    }
}

#endif

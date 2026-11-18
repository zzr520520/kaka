// ==========================================
// 自带 RSA-2048 / PKCS#1 v1.5 (SHA-256) 签名与验签
// 不依赖 Security 框架导入私钥，纯整数运算，跨平台可验证
// ==========================================
#ifndef KP_RSA_H
#define KP_RSA_H
#include <stdint.h>
#include <string.h>

#define KPR_MAXW 68          // 2048bit / 32 + 余量
#define KPR_BYTES 256

// ---------- 大数基础 ----------
static int kpr_cmp(const uint32_t *a, const uint32_t *b, int len) {
    for (int i = len - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static void kpr_sub(uint32_t *a, const uint32_t *b, int len) {
    uint64_t br = 0;
    for (int i = 0; i < len; i++) {
        uint64_t d = (uint64_t)a[i] - (uint64_t)b[i] - br;
        a[i] = (uint32_t)d;
        br = (d >> 32) & 1;
    }
}

static void kpr_dbl_mod(uint32_t *x, const uint32_t *n, int len) {
    uint32_t carry = 0;
    for (int i = 0; i < len; i++) {
        uint32_t v = (x[i] << 1) | carry;
        carry = x[i] >> 31;
        x[i] = v;
    }
    if (carry || kpr_cmp(x, n, len) >= 0) kpr_sub(x, n, len);
}

// ---------- 蒙哥马利 ----------
typedef struct {
    uint32_t n[KPR_MAXW];
    uint32_t rr[KPR_MAXW];   // R^2 mod n
    uint32_t n0inv;          // -n^-1 mod 2^32
    int len;
} kpr_ctx;

static void kpr_mont_init(kpr_ctx *c, const uint32_t *n, int len) {
    memset(c, 0, sizeof(*c));
    c->len = len;
    memcpy(c->n, n, len * sizeof(uint32_t));

    uint32_t inv = 1;
    for (int i = 0; i < 5; i++) inv *= 2 - n[0] * inv;
    c->n0inv = (uint32_t)(0u - inv);

    // rr = 2^(64*len) mod n，用反复倍增得到
    uint32_t x[KPR_MAXW] = {0};
    x[0] = 1;
    for (int i = 0; i < 64 * len; i++) kpr_dbl_mod(x, n, len);
    memcpy(c->rr, x, len * sizeof(uint32_t));
}

static void kpr_mont_mul(const kpr_ctx *c, uint32_t *out,
                         const uint32_t *a, const uint32_t *b) {
    int len = c->len;
    uint32_t t[KPR_MAXW + 2];
    memset(t, 0, sizeof(t));

    for (int i = 0; i < len; i++) {
        uint64_t cy = 0;
        for (int j = 0; j < len; j++) {
            uint64_t s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + cy;
            t[j] = (uint32_t)s;
            cy = s >> 32;
        }
        uint64_t s2 = (uint64_t)t[len] + cy;
        t[len] = (uint32_t)s2;
        t[len + 1] = (uint32_t)(s2 >> 32);

        uint32_t u = (uint32_t)(t[0] * c->n0inv);
        uint64_t s3 = (uint64_t)t[0] + (uint64_t)u * c->n[0];
        cy = s3 >> 32;
        for (int j = 1; j < len; j++) {
            uint64_t s4 = (uint64_t)t[j] + (uint64_t)u * c->n[j] + cy;
            t[j - 1] = (uint32_t)s4;
            cy = s4 >> 32;
        }
        uint64_t s5 = (uint64_t)t[len] + cy;
        t[len - 1] = (uint32_t)s5;
        t[len] = t[len + 1] + (uint32_t)(s5 >> 32);
    }

    int need = (t[len] != 0) ? 1 : (kpr_cmp(t, c->n, len) >= 0);
    if (need) kpr_sub(t, c->n, len);
    memcpy(out, t, len * sizeof(uint32_t));
}

// out = base^exp mod n（base/exp 为普通小端 limb）
static void kpr_mont_exp(const kpr_ctx *c, uint32_t *out,
                         const uint32_t *base, const uint32_t *exp, int expw) {
    int len = c->len;
    uint32_t one[KPR_MAXW] = {0}, bm[KPR_MAXW] = {0}, acc[KPR_MAXW] = {0};
    one[0] = 1;

    kpr_mont_mul(c, bm,  base, c->rr);   // base * R mod n
    kpr_mont_mul(c, acc, one,  c->rr);   // R mod n

    int started = 0;
    for (int i = expw - 1; i >= 0; i--) {
        for (int bit = 31; bit >= 0; bit--) {
            uint32_t v = (exp[i] >> bit) & 1u;
            if (!started) {
                if (!v) continue;
                started = 1;
                memcpy(acc, bm, len * sizeof(uint32_t));
                continue;
            }
            kpr_mont_mul(c, acc, acc, acc);
            if (v) kpr_mont_mul(c, acc, acc, bm);
        }
    }
    kpr_mont_mul(c, out, acc, one);      // 退出蒙哥马利域
}

// ---------- DER 解析（只取需要的 INTEGER） ----------
static int kpr_der_int(const uint8_t *p, const uint8_t *end,
                       const uint8_t **next, uint32_t *out, int *outw) {
    if (p + 2 > end || p[0] != 0x02) return -1;
    int len = p[1];
    p += 2;
    if (len & 0x80) {
        int nb = len & 0x7f;
        if (nb < 1 || nb > 3 || p + nb > end) return -1;
        len = 0;
        for (int i = 0; i < nb; i++) len = (len << 8) | p[i];
        p += nb;
    }
    if (p + len > end) return -1;

    const uint8_t *b = p;
    int n = len;
    while (n > 0 && b[0] == 0x00) { b++; n--; }   // 去掉符号位补零

    int words = (n + 3) / 4;
    if (words > KPR_MAXW) return -1;
    memset(out, 0, KPR_MAXW * sizeof(uint32_t));
    for (int i = 0; i < n; i++) {
        int byteIdx = n - 1 - i;                  // 小端
        out[i / 4] |= (uint32_t)b[byteIdx] << (8 * (i % 4));
    }
    *outw = words > 0 ? words : 1;
    if (next) *next = p + len;
    return 0;
}

static int kpr_skip_tlv(const uint8_t *p, const uint8_t *end, const uint8_t **next) {
    if (p + 2 > end) return -1;
    int len = p[1];
    const uint8_t *q = p + 2;
    if (len & 0x80) {
        int nb = len & 0x7f;
        if (nb < 1 || nb > 3 || q + nb > end) return -1;
        len = 0;
        for (int i = 0; i < nb; i++) len = (len << 8) | q[i];
        q += nb;
    }
    if (q + len > end) return -1;
    *next = q + len;
    return 0;
}

// 解析 RSAPrivateKey: SEQ{ ver, n, e, d, ... }
static int kpr_parse_priv(const uint8_t *der, int derlen,
                          uint32_t *n, uint32_t *e, uint32_t *d,
                          int *nw, int *dw) {
    const uint8_t *p = der, *end = der + derlen;
    if (p + 2 > end || p[0] != 0x30) return -1;
    int seqlen = p[1];
    p += 2;
    if (seqlen & 0x80) {
        int nb = seqlen & 0x7f;
        if (nb < 1 || nb > 3 || p + nb > end) return -1;
        seqlen = 0;
        for (int i = 0; i < nb; i++) seqlen = (seqlen << 8) | p[i];
        p += nb;
    }
    if (p + seqlen > end) return -1;
    end = p + seqlen;

    uint32_t tmp[KPR_MAXW];
    int tw, ew;
    if (kpr_der_int(p, end, &p, tmp, &tw)) return -1;   // version
    if (kpr_der_int(p, end, &p, n, nw))   return -1;   // modulus
    if (kpr_der_int(p, end, &p, e, &ew))  return -1;   // public exponent
    if (kpr_der_int(p, end, &p, d, dw))   return -1;   // private exponent
    return 0;
}

// 解析 RSAPublicKey: SEQ{ n, e }
static int kpr_parse_pub(const uint8_t *der, int derlen,
                         uint32_t *n, uint32_t *e, int *nw, int *ew) {
    const uint8_t *p = der, *end = der + derlen;
    if (p + 2 > end || p[0] != 0x30) return -1;
    int seqlen = p[1];
    p += 2;
    if (seqlen & 0x80) {
        int nb = seqlen & 0x7f;
        if (nb < 1 || nb > 3 || p + nb > end) return -1;
        seqlen = 0;
        for (int i = 0; i < nb; i++) seqlen = (seqlen << 8) | p[i];
        p += nb;
    }
    end = p + seqlen;
    if (kpr_der_int(p, end, &p, n, nw)) return -1;
    if (kpr_der_int(p, end, &p, e, ew)) return -1;
    return 0;
}

static void kpr_to_bytes(const uint32_t *a, int len, uint8_t *out) {
    for (int i = 0; i < len * 4; i++) {
        int byteIdx = len * 4 - 1 - i;
        out[byteIdx] = (uint8_t)(a[i / 4] >> (8 * (i % 4)));
    }
}

// EMSA-PKCS1-v1_5: 00 01 FF..FF 00 || DigestInfo(SHA-256) || H
static const uint8_t kpr_sha256_prefix[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static int kpr_emsa(const uint8_t *digest32, uint8_t *out, int k) {
    int tlen = 19 + 32;
    if (k < tlen + 11) return -1;
    out[0] = 0x00;
    out[1] = 0x01;
    int ps = k - tlen - 3;
    memset(out + 2, 0xff, ps);
    out[2 + ps] = 0x00;
    memcpy(out + 3 + ps, kpr_sha256_prefix, 19);
    memcpy(out + 3 + ps + 19, digest32, 32);
    return 0;
}

// 签名：输入私钥 DER 与 32 字节摘要，输出 256 字节签名
static int kpr_sign_sha256(const uint8_t *priv_der, int derlen,
                           const uint8_t *digest32, uint8_t *out_sig) {
    uint32_t n[KPR_MAXW], e[KPR_MAXW], d[KPR_MAXW];
    int nw, ew, dw;
    if (kpr_parse_priv(priv_der, derlen, n, e, d, &nw, &dw)) return -1;
    (void)ew;

    int k = nw * 4;
    if (k != KPR_BYTES) return -2;   // 只支持 2048 位

    uint8_t em[KPR_BYTES];
    if (kpr_emsa(digest32, em, k)) return -3;

    uint32_t m[KPR_MAXW] = {0}, sig[KPR_MAXW] = {0};
    for (int i = 0; i < KPR_BYTES; i++) {
        int byteIdx = KPR_BYTES - 1 - i;
        m[i / 4] |= (uint32_t)em[byteIdx] << (8 * (i % 4));
    }

    kpr_ctx c;
    kpr_mont_init(&c, n, nw);
    kpr_mont_exp(&c, sig, m, d, dw);
    kpr_to_bytes(sig, nw, out_sig);
    return 0;
}

// 验签：输入公钥 DER、32 字节摘要、256 字节签名
static int kpr_verify_sha256(const uint8_t *pub_der, int derlen,
                             const uint8_t *digest32, const uint8_t *sig) {
    uint32_t n[KPR_MAXW], e[KPR_MAXW];
    int nw, ew;
    if (kpr_parse_pub(pub_der, derlen, n, e, &nw, &ew)) return -1;
    if (nw * 4 != KPR_BYTES) return -2;

    uint32_t s[KPR_MAXW] = {0}, out[KPR_MAXW] = {0};
    for (int i = 0; i < KPR_BYTES; i++) {
        int byteIdx = KPR_BYTES - 1 - i;
        s[i / 4] |= (uint32_t)sig[byteIdx] << (8 * (i % 4));
    }

    kpr_ctx c;
    kpr_mont_init(&c, n, nw);
    kpr_mont_exp(&c, out, s, e, ew);

    uint8_t got[KPR_BYTES], want[KPR_BYTES];
    kpr_to_bytes(out, nw, got);
    if (kpr_emsa(digest32, want, KPR_BYTES)) return -3;
    return memcmp(got, want, KPR_BYTES) == 0 ? 0 : -4;
}

#endif

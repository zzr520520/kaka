// kp_aes.h —— AES-128-ECB 解密（CommonCrypto 实现）
// 供 KakaVoicePro.m 里的 kpa_decrypt_ecb(key, in, out, len) 调用。
#ifndef KP_AES_H
#define KP_AES_H

#include <stdint.h>
#include <stddef.h>
#include <CommonCrypto/CommonCryptor.h>

// ECB 单块无 IV：key 为 16 字节（AES-128），len 必须是 16 的整倍数。
static inline int kpa_decrypt_ecb(const uint8_t *key16,
                                  const uint8_t *in,
                                  uint8_t *out,
                                  size_t len) {
    if (!key16 || !in || !out || len == 0 || (len % 16) != 0) return -1;
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt,
                                 kCCAlgorithmAES128,
                                 0,            // kCCOptionECBMode == 0
                                 key16,
                                 kCCKeySizeAES128,
                                 NULL,         // ECB 无 IV
                                 in, len,
                                 out, len,
                                 &moved);
    if (st != kCCSuccess) return -1;
    return moved == len ? 0 : -1;
}

#endif

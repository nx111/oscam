#ifndef _TWOFISH_H_
#define _TWOFISH_H_

#include "stdint.h"
#define u8 unsigned char
#define u16 unsigned short int
#define u32 unsigned int

#define CRYPTO_TFM_REQ_MASK             0x000fff00
#define CRYPTO_TFM_RES_MASK             0xfff00000

#define CRYPTO_TFM_REQ_WEAK_KEY         0x00000100
#define CRYPTO_TFM_REQ_MAY_SLEEP        0x00000200
#define CRYPTO_TFM_REQ_MAY_BACKLOG      0x00000400
#define CRYPTO_TFM_RES_WEAK_KEY         0x00100000
#define CRYPTO_TFM_RES_BAD_KEY_LEN      0x00200000
#define CRYPTO_TFM_RES_BAD_KEY_SCHED    0x00400000
#define CRYPTO_TFM_RES_BAD_BLOCK_LEN    0x00800000
#define CRYPTO_TFM_RES_BAD_FLAGS        0x01000000

#define TWOFISH_MAX_KEY_LENGHT          32
#define TWOFISH_MODE_ENCRYPT            0
#define TWOFISH_MODE_DECRYPT            1

struct twofish_ctx {  
    uint32_t sBox[4*256];
    uint32_t subKeys[40];
    uint32_t sBoxKey[4];
    uint8_t  key[TWOFISH_MAX_KEY_LENGHT];
    uint8_t  key_length;
}; 

int twofish_setkey(struct twofish_ctx* ctx, uint8_t * key, int length);
int twofish_encrypt(struct twofish_ctx* ctx, uint8_t *in, int len, uint8_t *out, int maxlen);
int twofish_decrypt(struct twofish_ctx* ctx, uint8_t *in, int len, uint8_t *out, int maxlen);

// bDecrypt & 0x7F == 0, encrypt
// bDecrypt & 0x7F == 1, decrypt
int twofish(uint8_t * data, int len, uint8_t *out, int maxlen, uint8_t * key, int keylen, int bDecrypt);

#endif

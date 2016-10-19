/*
 * An implementation of the TwoFish algorithm
 * Copyright (c) 2015 Supraja Meedinti
 *
 * This file is ported from FFmpeg.
 *
 */

#ifndef TWOFISH_H
#define TWOFISH_H

#include <stdint.h>
#include <string.h>
#include <errno.h>

#   define RL32(x)                                   \
    (((uint32_t)((const uint8_t*)(x))[3] << 24) |    \
               (((const uint8_t*)(x))[2] << 16) |    \
               (((const uint8_t*)(x))[1] <<  8) |    \
                ((const uint8_t*)(x))[0])

#   define WL32(p, darg) do {                \
        unsigned d = (darg);                 \
        ((uint8_t*)(p))[0] = (d);            \
        ((uint8_t*)(p))[1] = (d)>>8;         \
        ((uint8_t*)(p))[2] = (d)>>16;        \
        ((uint8_t*)(p))[3] = (d)>>24;        \
    } while(0)


typedef struct TWOFISH {
    uint32_t K[40];
    uint32_t S[4];
    int ksize;
    uint32_t MDS1[256];
    uint32_t MDS2[256];
    uint32_t MDS3[256];
    uint32_t MDS4[256];
} TWOFISH;

/**
  * Allocate an TWOFISH context
  * To free the struct: free(ptr)
  */
//struct TWOFISH *twofish_alloc(void);

/**
  * Initialize an TWOFISH context.
  *
  * @param ctx an TWOFISH context
  * @param key a key of size ranging from 1 to 32 bytes used for encryption/decryption
  * @param key_bits number of keybits: 128, 192, 256 If less than the required, padded with zeroes to nearest valid value; return value is 0 if key_bits is 128/192/256, -1 if less than 0, 1 otherwise
 */
int twofish_init(struct TWOFISH *ctx, const uint8_t *key, int key_bits);

/**
  * Encrypt or decrypt a buffer using a previously initialized context
  *
  * @param ctx an TWOFISH context
  * @param dst destination array, can be equal to src
  * @param src source array, can be equal to dst
  * @param count number of 16 byte blocks
  * @paran iv initialization vector for CBC mode, NULL for ECB mode
  * @param decrypt 0 for encryption, 1 for decryption
 */
void twofish_crypt(struct TWOFISH *ctx, uint8_t *dst, const uint8_t *src, int count, uint8_t* iv, int decrypt);

/**
 * @}
 */
#endif /* TWOFISH_H */

// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

#include <stdint.h>
#include <stdlib.h>

/** A hasher class for SHA-256. */
class CSHA256 {
public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();

    CSHA256 &Write(const unsigned char *data, size_t len);

    void Finalize(unsigned char hash[OUTPUT_SIZE]);

    void FinalizeNoPadding(unsigned char hash[OUTPUT_SIZE]) {
        FinalizeNoPadding(hash, true);
    };

    CSHA256 &Reset();

private:
    uint32_t s[8];
    unsigned char buf[64];
    size_t bytes;

    void FinalizeNoPadding(unsigned char hash[OUTPUT_SIZE], bool enforce_compression);
};

uint32_t static inline ReadBE32(const unsigned char *ptr) {
    uint32_t sum = 0;
    for (int i = 0; i < 4; i++) {
        sum += ptr[i] * (1 << (8 * (3 - i)));
    }
    return sum;
}

void static inline WriteBE32(unsigned char *ptr, uint32_t x) {
    for (int i = 0; i < 4; i++) {
        ptr[i] = (unsigned char) ((x >> (8 * (3 - i))) & 0xff);
    }
    return;
}

void static inline WriteBE64(unsigned char *ptr, uint64_t x) {
    for (int i = 0; i < 8; i++) {
        ptr[i] = (unsigned char) ((x >> (8 * (7 - i))) & 0xff);
    }
    return;
}

#endif // BITCOIN_CRYPTO_SHA256_H

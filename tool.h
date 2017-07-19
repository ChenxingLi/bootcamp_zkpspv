//
// Created by lylcx-mac on 2017/7/17.
//

#ifndef BOOTCAMP_ZKPSPV_TOOL_H
#define BOOTCAMP_ZKPSPV_TOOL_H

#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <cstring>
#include <assert.h>

#ifdef DEBUG
#   define ASSERT(condition, message) \
    do { \
        if (! (condition)) { \
            std::cerr << "Assertion `" #condition "` failed in " << __FILE__ \
                      << " line " << __LINE__ << ": " << message << std::endl; \
            std::terminate(); \
        } \
    } while (false)
#else
#   define ASSERT(condition, message) do { } while (false)
#endif

const signed char p_util_hexdigit[256] =
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
         -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,};

signed char HexDigit(char c) {
    return p_util_hexdigit[(unsigned char) c];
}

template<unsigned int BITS>
class base_blob {
protected:
    enum {
        WIDTH = BITS / 8
    };
    alignas(uint32_t) uint8_t data[WIDTH];
public:
    base_blob() {
        memset(data, 0, sizeof(data));
    }

    base_blob(const std::vector<unsigned char> &vch) {
        memcpy(data, &vch[0], sizeof(data));
    }

    bool IsNull() const {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    void SetNull() {
        memset(data, 0, sizeof(data));
    }

    friend inline bool operator==(const base_blob &a, const base_blob &b) {
        return memcmp(a.data, b.data, sizeof(a.data)) == 0;
    }

    friend inline bool operator!=(const base_blob &a, const base_blob &b) {
        return memcmp(a.data, b.data, sizeof(a.data)) != 0;
    }

    friend inline bool operator<(const base_blob &a, const base_blob &b) {
        return memcmp(a.data, b.data, sizeof(a.data)) < 0;
    }

    std::string GetHex() const {
        char psz[sizeof(data) * 2 + 1];
        for (unsigned int i = 0; i < sizeof(data); i++)
            sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
        return std::string(psz, psz + sizeof(data) * 2);
    }

    std::string GetHexInv() const {
        char psz[sizeof(data) * 2 + 1];
        for (unsigned int i = 0; i < sizeof(data); i++)
            sprintf(psz + i * 2, "%02x", data[i]);
        return std::string(psz, psz + sizeof(data) * 2);
    }

    void SetHex(const char *psz) {

        memset(data, 0, sizeof(data));

        // skip leading spaces
        while (isspace(*psz))
            psz++;

        // skip 0x
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;

        // hex string to uint
        const char *pbegin = psz;
        while (HexDigit(*psz) != -1)
            psz++;
        psz--;
        unsigned char *p1 = (unsigned char *) data;
        unsigned char *pend = p1 + WIDTH;
        while (psz >= pbegin && p1 < pend) {
            *p1 = HexDigit(*psz--);
            if (psz >= pbegin) {
                *p1 |= ((unsigned char) HexDigit(*psz--) << 4);
                p1++;
            }
        }
    }

    void SetHexInv(const char *psz) {

        memset(data, 0, sizeof(data));

        // skip leading spaces
        while (isspace(*psz))
            psz++;

        // skip 0x
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;

        // hex string to uint
        const char *pbegin = psz;
        while (HexDigit(*psz) != -1)
            psz++;
        psz--;
        unsigned char *pstart = (unsigned char *) data;
        unsigned char *pend = pstart + WIDTH;
        unsigned char *p1 = pend - 1;
        while (psz >= pbegin && p1 >= pstart) {
            *p1 = HexDigit(*psz--);
            if (psz >= pbegin) {
                *p1 |= ((unsigned char) HexDigit(*psz--) << 4);
                p1--;
            }
        }

    }

    void SetHex(const std::string &str) {
        SetHex(str.c_str());
    }

    void SetHexInv(const std::string &str) {
        SetHexInv(str.c_str());
    }

    std::string ToString() const {
        return (GetHex());
    }

    unsigned char *begin() {
        return &data[0];
    }

    unsigned char *end() {
        return &data[WIDTH];
    }

    const unsigned char *begin() const {
        return &data[0];
    }

    const unsigned char *end() const {
        return &data[WIDTH];
    }

    unsigned int size() const {
        return sizeof(data);
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const {
        return sizeof(data);
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const {
        s.write((char *) data, sizeof(data));
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) {
        s.read((char *) data, sizeof(data));
    }
};

class uint256 : public base_blob<256> {
public:
    uint256() {}

    uint256(const base_blob<256> &b) : base_blob<256>(b) {}

    uint256(const std::string &str, bool LE = true) {
        if (LE) {
            SetHexInv(str);
        } else {
            SetHex(str);
        }
    }

    explicit uint256(const std::vector<unsigned char> &vch) : base_blob<256>(vch) {}
};

typedef uint256 BlockHash;

class BlockHeader : public base_blob<640> {
public:
    BlockHeader() {}

    BlockHeader(const std::string &str, bool LE = true) {
        if (LE) {
            SetHexInv(str);
        } else {
            SetHex(str);
        }

    }

    uint256 getHash() {
        uint256 msg = getFirstHash();
        CSHA256 sha256;
        uint256 ans;
        sha256.Write(msg.begin(), 32);
        sha256.Finalize(ans.begin());
        return ans;
    }

    uint256 getFirstHash() {
        CSHA256 sha256;
        uint256 ans;
        sha256.Write(this->begin(), 80);
        sha256.Finalize(ans.begin());
        return ans;
    }

    uint32_t getTimeStamp() {
        uint32_t ans;
        memcpy(&ans, begin() + 68, 4);
        return ans;
    }

    uint256 getPrevHash() {
        uint256 ans;
        memcpy(ans.begin(), begin() + 4, 32);
        return ans;
    }

    BlockHeader(const base_blob<640> &b) : base_blob<640>(b) {}

    explicit BlockHeader(const std::vector<unsigned char> &vch) : base_blob<640>(vch) {}
};

class TimeStamp : public std::vector<uint32_t> {
public:
    TimeStamp() : std::vector<uint32_t>(11, 0) {}

    TimeStamp(std::vector<uint32_t> &vch) : std::vector<uint32_t>(vch) { assert(vch.size() == 11); }

    void update(uint32_t s) {
        this->insert(begin(), s);
        this->erase(end() - 1);
    }
};

long long div_ceil(long long x, long long y) {
    return (x + y - 1) / y;
}


#endif //BOOTCAMP_ZKPSPV_TOOL_H

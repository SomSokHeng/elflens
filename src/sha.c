#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha.h"

static uint32_t ror32(uint32_t x, int r)
{
    return (x >> r) | (x << (32 - r));
}

static uint32_t rol32(uint32_t x, int r)
{
    return (x << r) | (x >> (32 - r));
}

static void be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static void le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static void hex(const unsigned char *d, size_t n, char *out)
{
    static const char *t = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = t[d[i] >> 4];
        out[i * 2 + 1] = t[d[i] & 15];
    }
    out[n * 2] = 0;
}

static void sha256(const unsigned char *b, size_t n, unsigned char *out)
{
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t tot = n;
    size_t i = 0;
    for (; i + 64 <= n; i += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)b[i + j * 4] << 24) | ((uint32_t)b[i + j * 4 + 1] << 16) |
                   ((uint32_t)b[i + j * 4 + 2] << 8) | (uint32_t)b[i + j * 4 + 3];
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = ror32(w[j - 15], 7) ^ ror32(w[j - 15], 18) ^ (w[j - 15] >> 3);
            uint32_t s1 = ror32(w[j - 2], 17) ^ ror32(w[j - 2], 19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + K[j] + w[j];
            uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
            uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
            uint32_t t2 = S0 + mj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = bb;
            bb = a;
            a = t1 + t2;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    unsigned char tail[128];
    size_t r = n - i;
    memcpy(tail, b + i, r);
    tail[r++] = 0x80;
    size_t pad = (r <= 56) ? (56 - r) : (120 - r);
    memset(tail + r, 0, pad);
    r += pad;
    uint64_t bits = (uint64_t)tot * 8;
    for (int j = 0; j < 8; j++)
        tail[r + j] = (unsigned char)(bits >> (56 - j * 8));
    r += 8;
    for (size_t k = 0; k < r; k += 64) {
        uint32_t w[64];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)tail[k + j * 4] << 24) | ((uint32_t)tail[k + j * 4 + 1] << 16) |
                   ((uint32_t)tail[k + j * 4 + 2] << 8) | (uint32_t)tail[k + j * 4 + 3];
        for (int j = 16; j < 64; j++) {
            uint32_t s0 = ror32(w[j - 15], 7) ^ ror32(w[j - 15], 18) ^ (w[j - 15] >> 3);
            uint32_t s1 = ror32(w[j - 2], 17) ^ ror32(w[j - 2], 19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int j = 0; j < 64; j++) {
            uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + K[j] + w[j];
            uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
            uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int j = 0; j < 8; j++)
        be32(out + j * 4, h[j]);
}

static void sha1(const unsigned char *b, size_t n, unsigned char *out)
{
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t tot = n, i = 0;
    for (; i + 64 <= n; i += 64) {
        uint32_t w[80];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)b[i + j * 4] << 24) | ((uint32_t)b[i + j * 4 + 1] << 16) |
                   ((uint32_t)b[i + j * 4 + 2] << 8) | (uint32_t)b[i + j * 4 + 3];
        for (int j = 16; j < 80; j++)
            w[j] = rol32(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t f, k;
            if (j < 20) { f = (bb & c) | ((~bb) & d); k = 0x5A827999; }
            else if (j < 40) { f = bb ^ c ^ d; k = 0x6ED9EBA1; }
            else if (j < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = bb ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t t = rol32(a, 5) + f + e + k + w[j];
            e = d; d = c; c = rol32(bb, 30); bb = a; a = t;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
    }
    unsigned char tail[128];
    size_t r = n - i;
    memcpy(tail, b + i, r);
    tail[r++] = 0x80;
    size_t pad = (r <= 56) ? (56 - r) : (120 - r);
    memset(tail + r, 0, pad);
    r += pad;
    uint64_t bits = (uint64_t)tot * 8;
    be32(tail + r, (uint32_t)(bits >> 32));
    be32(tail + r + 4, (uint32_t)bits);
    r += 8;
    for (size_t k = 0; k < r; k += 64) {
        uint32_t w[80];
        for (int j = 0; j < 16; j++)
            w[j] = ((uint32_t)tail[k + j * 4] << 24) | ((uint32_t)tail[k + j * 4 + 1] << 16) |
                   ((uint32_t)tail[k + j * 4 + 2] << 8) | (uint32_t)tail[k + j * 4 + 3];
        for (int j = 16; j < 80; j++)
            w[j] = rol32(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t f, k;
            if (j < 20) { f = (bb & c) | ((~bb) & d); k = 0x5A827999; }
            else if (j < 40) { f = bb ^ c ^ d; k = 0x6ED9EBA1; }
            else if (j < 60) { f = (bb & c) | (bb & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = bb ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t t = rol32(a, 5) + f + e + k + w[j];
            e = d; d = c; c = rol32(bb, 30); bb = a; a = t;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
    }
    for (int j = 0; j < 5; j++)
        be32(out + j * 4, h[j]);
}

static void md5(const unsigned char *b, size_t n, unsigned char *out)
{
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
    static const int S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    uint32_t h[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    size_t tot = n, i = 0;
    for (; i + 64 <= n; i += 64) {
        uint32_t m[16];
        for (int j = 0; j < 16; j++)
            m[j] = (uint32_t)b[i + j * 4] | ((uint32_t)b[i + j * 4 + 1] << 8) |
                   ((uint32_t)b[i + j * 4 + 2] << 16) | ((uint32_t)b[i + j * 4 + 3] << 24);
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3];
        for (int j = 0; j < 64; j++) {
            uint32_t f;
            int g;
            if (j < 16) { f = (bb & c) | (~bb & d); g = j; }
            else if (j < 32) { f = (d & bb) | (~d & c); g = (5 * j + 1) % 16; }
            else if (j < 48) { f = bb ^ c ^ d; g = (3 * j + 5) % 16; }
            else { f = c ^ (bb | ~d); g = (7 * j) % 16; }
            uint32_t tmp = d;
            d = c;
            c = bb;
            bb = bb + rol32(a + f + K[j] + m[g], S[j]);
            a = tmp;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
    }
    unsigned char tail[128];
    size_t r = n - i;
    memcpy(tail, b + i, r);
    tail[r++] = 0x80;
    size_t pad = (r <= 56) ? (56 - r) : (120 - r);
    memset(tail + r, 0, pad);
    r += pad;
    uint64_t bits = (uint64_t)tot * 8;
    le32(tail + r, (uint32_t)bits);
    le32(tail + r + 4, (uint32_t)(bits >> 32));
    r += 8;
    for (size_t k = 0; k < r; k += 64) {
        uint32_t m[16];
        for (int j = 0; j < 16; j++)
            m[j] = (uint32_t)tail[k + j * 4] | ((uint32_t)tail[k + j * 4 + 1] << 8) |
                   ((uint32_t)tail[k + j * 4 + 2] << 16) | ((uint32_t)tail[k + j * 4 + 3] << 24);
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3];
        for (int j = 0; j < 64; j++) {
            uint32_t f;
            int g;
            if (j < 16) { f = (bb & c) | (~bb & d); g = j; }
            else if (j < 32) { f = (d & bb) | (~d & c); g = (5 * j + 1) % 16; }
            else if (j < 48) { f = bb ^ c ^ d; g = (3 * j + 5) % 16; }
            else { f = c ^ (bb | ~d); g = (7 * j) % 16; }
            uint32_t tmp = d;
            d = c;
            c = bb;
            bb = bb + rol32(a + f + K[j] + m[g], S[j]);
            a = tmp;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
    }
    for (int j = 0; j < 4; j++)
        le32(out + j * 4, h[j]);
}

void vso_hash(const unsigned char *b, size_t n, char *o256, char *o1, char *o5)
{
    if (o256) {
        unsigned char o[32];
        sha256(b, n, o);
        hex(o, 32, o256);
    }
    if (o1) {
        unsigned char o[20];
        sha1(b, n, o);
        hex(o, 20, o1);
    }
    if (o5) {
        unsigned char o[16];
        md5(b, n, o);
        hex(o, 16, o5);
    }
}

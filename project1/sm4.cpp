﻿#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <random>
#include <iomanip>

using namespace std;

static const uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// 系统参数 FK 和 CK（常量轮密钥）
const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

//循环移位函数
uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

//合成变换T
uint32_t T(uint32_t A) {
    //拆分1字为4字节
    uint8_t a[4] = {
        static_cast<uint8_t>(A >> 24),
        static_cast<uint8_t>(A >> 16),
        static_cast<uint8_t>(A >> 8),
        static_cast<uint8_t>(A)
    };
    //过S盒
    for (int i = 0; i < 4; ++i)
        a[i] = SM4_SBOX[a[i]];
    uint32_t B = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
    //线性变换
    return B ^ rotl(B, 2) ^ rotl(B, 10) ^ rotl(B, 18) ^ rotl(B, 24);
}

//密钥扩展的合成变换
uint32_t T_prime(uint32_t A) {
    uint8_t a[4] = {
        static_cast<uint8_t>(A >> 24),
        static_cast<uint8_t>(A >> 16),
        static_cast<uint8_t>(A >> 8),
        static_cast<uint8_t>(A)
    };
    for (int i = 0; i < 4; ++i)
        a[i] = SM4_SBOX[a[i]];
    uint32_t B = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
    return B ^ rotl(B, 13) ^ rotl(B, 23);
}

// 密钥扩展
void key_schedule(const uint32_t key[4], uint32_t rk[32]) {
    uint32_t K[36];
    for (int i = 0; i < 4; ++i)
        K[i] = key[i] ^ FK[i];
    for (int i = 0; i < 32; ++i)
        K[i + 4] = K[i] ^ T_prime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
    memcpy(rk, &K[4], 32 * sizeof(uint32_t));
}

// 通用加/解密（enc=true 为加密）
void sm4_crypt(uint32_t block[4], const uint32_t rk[32], bool enc = true) {
    uint32_t X[36];
    memcpy(X, block, 4 * sizeof(uint32_t));
    for (int i = 0; i < 32; ++i) {
        int r = enc ? i : 31 - i;
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[r]);
    }
    for (int i = 0; i < 4; ++i)
        block[i] = X[35 - i];
}

// 随机生成明文、密钥
void random_block(uint32_t block[4]) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint32_t> dis(0, UINT32_MAX);
    for (int i = 0; i < 4; ++i)
        block[i] = dis(gen);
}

//输出
void print_block(const string& label, const uint32_t block[4]) {
    cout << label << ": ";
    for (int i = 0; i < 4; ++i)
        cout << hex << setw(8) << setfill('0') << block[i] << " ";
    cout << dec << endl;
}

//加解密正确性检测
bool test_sm4_once() {
    uint32_t plaintext[4], key[4], rk[32], ciphertext[4], decrypted[4];

    random_block(plaintext);
    random_block(key);

    key_schedule(key, rk);

    memcpy(ciphertext, plaintext, sizeof(ciphertext));
    sm4_crypt(ciphertext, rk, true);

    memcpy(decrypted, ciphertext, sizeof(decrypted));
    sm4_crypt(decrypted, rk, false);

    print_block("Plaintext ", plaintext);
    print_block("Key       ", key);
    print_block("Ciphertext", ciphertext);
    print_block("Decrypted ", decrypted);

    return memcmp(plaintext, decrypted, sizeof(plaintext)) == 0;
}

//效率测试
void test_performance() {
    const int N = 1000000;
    uint32_t data[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    uint32_t key[4] = { 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff };
    uint32_t rk[32];
    key_schedule(key, rk);

    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; ++i) {
        uint32_t tmp[4];
        memcpy(tmp, data, sizeof(tmp));
        sm4_crypt(tmp, rk, true);
    }
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;

    cout << "\n[Performance Test]\n";
    cout << "SM4 encrypt " << N << " blocks in " << diff.count() << " seconds.\n";
    cout << "Average time per block: " << (diff.count() * 1e6 / N) << " us\n";
}

int main() {
    cout << "[SM4 Correctness Test]\n";
    bool ok = test_sm4_once();
    cout << (ok ? "Encryption & decryption match.\n" : " Decryption failed.\n");

    test_performance();
    return 0;
}

#include <iostream>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <random>

using namespace std;

// SM4算法S盒（非线性变换表）
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

// 系统参数FK（密钥扩展初始参数）
const uint32_t SM4_FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// 系统参数CK（轮常量）
const uint32_t SM4_CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

// T变换查找表（预计算S盒与线性变换的组合结果）
uint32_t TBox0[256], TBox1[256], TBox2[256], TBox3[256];

inline uint32_t rotateLeft(uint32_t value, int shiftBits) {
    return (value << shiftBits) | (value >> (32 - shiftBits));
}

uint32_t linearTransformL(uint32_t value) {
    return value ^ rotateLeft(value, 2) ^ rotateLeft(value, 10) ^ rotateLeft(value, 18) ^ rotateLeft(value, 24);
}

void initTBox() {
    for (int i = 0; i < 256; ++i) {
        uint8_t sBoxVal = SM4_SBOX[i];
        uint32_t transformed = linearTransformL(static_cast<uint32_t>(sBoxVal) << 24);
        TBox0[i] = transformed;
        TBox1[i] = rotateLeft(transformed, 8);
        TBox2[i] = rotateLeft(transformed, 16);
        TBox3[i] = rotateLeft(transformed, 24);
    }
}

inline uint32_t tTransformLookup(uint32_t value) {
    return TBox0[(value >> 24) & 0xFF]    // 高8位查表
        ^ TBox1[(value >> 16) & 0xFF]  // 次高8位查表
        ^ TBox2[(value >> 8) & 0xFF]   // 次低8位查表
        ^ TBox3[value & 0xFF];         // 低8位查表
}

uint32_t tPrimeTransform(uint32_t value) {
    uint8_t bytes[4] = {
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value)
    };
    // S盒变换
    for (int i = 0; i < 4; ++i) {
        bytes[i] = SM4_SBOX[bytes[i]];
    }
    // 重组并线性变换
    uint32_t merged = (static_cast<uint32_t>(bytes[0]) << 24)
        | (static_cast<uint32_t>(bytes[1]) << 16)
        | (static_cast<uint32_t>(bytes[2]) << 8)
        | bytes[3];
    return merged ^ rotateLeft(merged, 13) ^ rotateLeft(merged, 23);
}

void generateRoundKeys(const uint32_t key[4], uint32_t roundKeys[32]) {
    uint32_t intermediateKeys[36];
    // 初始密钥与FK异或
    for (int i = 0; i < 4; ++i) {
        intermediateKeys[i] = key[i] ^ SM4_FK[i];
    }
    // 扩展生成32轮轮密钥
    for (int i = 0; i < 32; ++i) {
        intermediateKeys[i + 4] = intermediateKeys[i]
            ^ tPrimeTransform(intermediateKeys[i + 1]
                ^ intermediateKeys[i + 2]
                ^ intermediateKeys[i + 3]
                ^ SM4_CK[i]);
    }
    // 提取轮密钥
    memcpy(roundKeys, intermediateKeys + 4, 32 * sizeof(uint32_t));
}

void sm4Cipher(uint32_t block[4], const uint32_t roundKeys[32], bool isEncrypt = true) {
    uint32_t state[36];  // 加密过程中的状态数组
    memcpy(state, block, 4 * sizeof(uint32_t));

    // 32轮迭代
    for (int round = 0; round < 32; ++round) {
        int roundIdx = isEncrypt ? round : 31 - round;  // 解密使用逆序轮密钥
        state[round + 4] = state[round] ^ tTransformLookup(
            state[round + 1] ^ state[round + 2] ^ state[round + 3] ^ roundKeys[roundIdx]
        );
    }

    // 输出变换（逆序取最后4个状态）
    for (int i = 0; i < 4; ++i) {
        block[i] = state[35 - i];
    }
}

void printBlock(const string& label, const uint32_t block[4]) {
    cout << label << ": ";
    for (int i = 0; i < 4; ++i) {
        cout << hex << setw(8) << setfill('0') << block[i] << " ";
    }
    cout << dec << endl;
}

void testSingleCase() {
    uint32_t plaintext[4], key[4], ciphertext[4], decrypted[4], roundKeys[32];

    // 随机生成明文和密钥
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    for (int i = 0; i < 4; ++i) {
        plaintext[i] = dist(gen);
        key[i] = dist(gen);
    }

    // 生成轮密钥
    generateRoundKeys(key, roundKeys);

    // 加密
    memcpy(ciphertext, plaintext, sizeof(ciphertext));
    sm4Cipher(ciphertext, roundKeys, true);

    // 解密
    memcpy(decrypted, ciphertext, sizeof(decrypted));
    sm4Cipher(decrypted, roundKeys, false);

    // 输出结果
    printBlock("plaintext ", plaintext);
    printBlock("key       ", key);
    printBlock("ciphertext", ciphertext);
    printBlock("decrypted ", decrypted);
    cout << (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0 ? "match\n" : "mismatch\n");
}

void testPerformance() {
    const int totalBlocks = 1000000;  // 总加密块数
    uint32_t dataBlock[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    uint32_t roundKeys[32];
    uint32_t key[4] = { 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff };

    // 生成轮密钥
    generateRoundKeys(key, roundKeys);

    // 计时开始
    auto startTime = chrono::high_resolution_clock::now();
    for (int i = 0; i < totalBlocks; ++i) {
        uint32_t tempBlock[4];
        memcpy(tempBlock, dataBlock, sizeof(tempBlock));
        sm4Cipher(tempBlock, roundKeys, true);
    }
    auto endTime = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = endTime - startTime;

    // 输出性能数据
    cout << "\nperformance test\n";
    cout << "encrypted " << totalBlocks << " blocks in " << elapsed.count() << " seconds.\n";
    cout << "average time : " << (elapsed.count() * 1e6 / totalBlocks) << " us\n";
}

int main() {
    initTBox();         // 初始化T变换查找表
    testSingleCase();   // 单次加解密测试
    testPerformance();  // 性能测试
    return 0;
}
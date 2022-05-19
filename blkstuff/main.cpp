#include <iostream>
#include <cstdint>
#include <cstring>

#include <random>
#include <filesystem>

#include <lz4.h>

#include "util.h"
#include "magic_constants.h"

using std::cout, std::endl, std::hex, std::dec;

void key_descramble2(uint8_t* key);

// notes are from the genshin impact 1.5 dev build leak UnityEngine.dll (sha256 38399169552791bbfb7b3792dd3e91d3788067e29ffc2437f595060b051d2dd3)

void key_scramble1(uint8_t* key) {
    // UnityPlayer:$1615F0
    for (unsigned i = 0; i < 0x10; i++)
        key[i] = key_scramble_table1[((i & 3) << 8) | key[i]];
}

void create_encrypt_vector(uint8_t* output, uint64_t output_size, uint64_t seed) {
    auto mt_rand = std::mt19937_64(seed);
    for (uint64_t i = 0; i < output_size >> 3; i++)
        ((uint64_t*)output)[i] = mt_rand();
}

uint8_t key_scramble_table1_rev(int subtable, uint8_t value) {
    int key_table_offset = (subtable & 3) << 8;
    
    int pp = 0;
    for (pp = 0; pp < 256; pp++) { // TODO: not a most efficient but works
      if (*(key_scramble_table1 + key_table_offset + pp) == value)
          break;
    }
    
    assert(pp < 256);

    return pp;
}

void key_descramble1(uint8_t* key) {
    for (unsigned i = 0; i < 0x10; i++) {
        key[i] = key_scramble_table1_rev(i & 3, key[i]);
    }
}

void calc_decrypt_key(uint8_t* key, uint64_t seed, uint8_t* encrypted_data, uint64_t encrypted_size) {
    auto* key_qword = (uint64_t*)key;

    uint64_t val = 0xFFFFFFFFFFFFFFFF;

    for (int i = 0; i < encrypted_size >> 3; i++) {
        val = ((uint64_t*)encrypted_data)[i] ^ val;
    }

    for (int i = 0; i < 8; i++)
        key[i] = rand() & 0xFF;

    key_qword[1] = 0x567BA22BABB08098 ^ val ^ key_qword[0] ^ seed;

    uint8_t hard_key[] = { 0xE3, 0xFC, 0x2D, 0x26, 0x9C, 0xC5, 0xA2, 0xEC, 0xD3, 0xF8, 0xC6, 0xD3, 0x77, 0xC2, 0x49, 0xB9 };
    for (int i = 0; i < 16; i++)
        key[i] ^= hard_key[i];

    key_descramble2(key);
    key_descramble1(key);
}

void create_decrypt_vector(uint8_t* key, uint8_t* encrypted_data, uint64_t encrypted_size, uint8_t* output, uint64_t output_size) {
    if (output_size != 4096) {
        cout << "create_decrypt_vector does not support an output_size other than 4096" << endl;
        exit(1);
    }

    // TODO: reimplement this properly instead of copy and pasting from decomp
    uint64_t val = 0xFFFFFFFFFFFFFFFF;

    for (int i = 0; i < encrypted_size >> 3; i++) {
        val = ((uint64_t*)encrypted_data)[i] ^ val;
    }

    auto* key_qword = (uint64_t*)key;
    // another magic constant, this time from blk_stuff2
    uint64_t seed = key_qword[1] ^ 0x567BA22BABB08098 ^ val ^ key_qword[0];
    //cout << "seed: 0x" << hex << seed << endl;

    auto mt_rand = std::mt19937_64(seed);
    for (uint64_t i = 0; i < output_size >> 3; i++)
        ((uint64_t*)output)[i] = mt_rand();
}

#if 1
void aes_expand_round_keys(uint8_t* round_keys, const uint8_t* seed)
{
    int N = 4;

    static const uint8_t lookup_rcon[] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};

    static const uint8_t lookup_sbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

    static const uint8_t lookup_sbox_inv[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

    auto rot_word = [](uint32_t word) {
        return (word << 8) | ((word >> 24) & 0x000000FF);
        //return (word >> 8) | ((word << 24) & 0xFF000000);
    };

    static const uint8_t* ls = lookup_sbox;

    auto sub_word = [](uint32_t word) {
        return 
          ls[ word        & 0xFF]       |
          ls[(word >>  8) & 0xFF] <<  8 |
          ls[(word >> 16) & 0xFF] << 16 |
          ls[(word >> 24) & 0xFF] << 24 ;
    };

    for (int i = 0; i < 16; i++)
        round_keys[i] = seed[i];

    uint32_t* round_key_words = (uint32_t*)round_keys;

    for (int i = N; i < N*11; i++)
    {
        if (i % N == 0)
        {
            round_key_words[i] = round_key_words[i-N] ^ sub_word(rot_word(round_key_words[i-1])) ^ (lookup_rcon[i/N]);
        } else {
            round_key_words[i] = round_key_words[i-N] ^ round_key_words[i-1];
        }
    }

    #if 0
    for (int round = 0; round <= 10; round++)
    {
        hexdump("Derived round key: ", round_keys + round*16, 16);
    }
    #endif
}
#endif

void kinda_expand_round_keys(uint8_t* round_keys)
{
    // There're eleven rounds...
    for (int round = 0; round <= 10; round++)
    {
        // ... and each key has 16 bytes = 128 bits ...
        for (int i = 0; i < 16; i++)
            // ... and each byte is a sum modulo 2 of 16 bytes of data
            for (int j = 0; j < 16; j++)
            {
                uint64_t idx = (round << 8) + (i*16) + j;
                round_keys[round * 16 + i] ^= blk_stuff1_p1[idx] ^ stack_stuff[idx];
            }
    }

    #if 0
    for (int round = 0; round <= 10; round++)
    {
        hexdump("Round key: ", round_keys + round*16, 16);
    }
    #endif
}

// These functions are not exported, so hackaround it
extern "C" void oqs_mhy128_enc_c(const uint8_t *plaintext, const void *_schedule, uint8_t *ciphertext);
extern "C" void oqs_mhy128_dec_c(const uint8_t *chiphertext, const void *_schedule, uint8_t *plaintext);

void key_scramble2(uint8_t* key) {
    uint8_t round_keys[11*16] = {0};

    kinda_expand_round_keys(round_keys);

    uint8_t chip[16];

    oqs_mhy128_enc_c(key, round_keys, chip);

    memcpy(key, chip, 16);
}

void key_descramble2(uint8_t* key) {
    uint8_t round_keys[11*16] = {0};

    kinda_expand_round_keys(round_keys);

    uint8_t chip[16];

    oqs_mhy128_dec_c(key, round_keys, chip);

    memcpy(key, chip, 16);
}

void mhy0_header_scramble2(uint8_t* input)
{
    // UnityPlayer:$152300
    uint8_t tmp[16];

    uint8_t mhy0_index_scramble[] = {
        0x0B,0x02,0x08,0x0C,0x01,0x05,0x00,0x0F,0x06,0x07,0x09,0x03,0x0D,0x04,0x0E,0x0A,
        0x04,0x05,0x07,0x0A,0x02,0x0F,0x0B,0x08,0x0E,0x0D,0x09,0x06,0x0C,0x03,0x00,0x01,
        0x08,0x00,0x0C,0x06,0x04,0x0B,0x07,0x09,0x05,0x03,0x0F,0x01,0x0D,0x0A,0x02,0x0E,
    };

    uint8_t smol_key[] = {
        0x48, 0x14, 0x36, 0xED, 0x8E, 0x44, 0x5B, 0xB6
    };

    uint8_t v25[] = {
        0xA7, 0x99, 0x66, 0x50, 0xB9, 0x2D, 0xF0, 0x78
    };

    for (int k = 0; k < 3; k++)
    {
        for (int j = 0; j < 16; ++j)
        {
            int i = mhy0_index_scramble[(2 - k)*16 + j];

            int idx = j % 8;

            tmp[j] = smol_key[idx] ^ key_scramble_table1[((j & 3) << 8) | gf256_mul(v25[idx], input[i])];
        }
        memcpy(input, tmp, 16);
    }
}

void mhy0_header_descramble2(uint8_t* input)
{
    uint8_t tmp[16];

    uint8_t smol_key[] = {
        0x48, 0x14, 0x36, 0xED, 0x8E, 0x44, 0x5B, 0xB6
    };

    uint8_t v25[] = {
        0xA7, 0x99, 0x66, 0x50, 0xB9, 0x2D, 0xF0, 0x78
    };

    uint8_t mhy0_index_scramble[] = {
        0x0B,0x02,0x08,0x0C,0x01,0x05,0x00,0x0F,0x06,0x07,0x09,0x03,0x0D,0x04,0x0E,0x0A,
        0x04,0x05,0x07,0x0A,0x02,0x0F,0x0B,0x08,0x0E,0x0D,0x09,0x06,0x0C,0x03,0x00,0x01,
        0x08,0x00,0x0C,0x06,0x04,0x0B,0x07,0x09,0x05,0x03,0x0F,0x01,0x0D,0x0A,0x02,0x0E,
    };

    for (int k = 0; k < 3; k++)
    {
        for (int j = 0; j < 16; j++)
        {
            //int i = mhy0_index_scramble[(2 - k)*16 + j];
            int i = mhy0_index_scramble[k*16 + j];

            int idx = j % 8;
            uint8_t q = smol_key[idx] ^ input[j];
            int key_table_offset = (j & 3) << 8;

            uint8_t pp = key_scramble_table1_rev(j&3, q);

            tmp[i] = gf256_div(pp, v25[idx]);
        }
        memcpy(input, tmp, 16);
    }
}

void mhy0_header_scramble(uint8_t* input, uint64_t limit, uint8_t* input2, uint64_t chunk_size) {
    if (!((limit == 0x39 && chunk_size == 0x1C) || (limit == 0x21 && chunk_size == 8))) {
        cout << "unsupported parameters for mhy0_header_scramble" << endl;
        exit(1);
    }

    // UnityPlayer:$151090
    int rounded_size = (chunk_size + 15) & 0xFFFFFFF0;

    for (int i = 0; i < rounded_size; i += 16)
        mhy0_header_scramble2(&input[i + 4]);

    for (int j = 0; j < 4; j++)
        input[j] ^= input2[j];

    uint64_t total_rounded_size = (uint64_t)rounded_size + 4;

    bool finished = false;
    while (total_rounded_size < limit && !finished)
    {
        for (int k = 0; k < chunk_size; ++k)
        {
            input[k + total_rounded_size] ^= input2[k];
            if (k + total_rounded_size >= limit - 1)
            {
                finished = true;
                break;
            }
        }
        total_rounded_size += chunk_size;
    }
}

void mhy0_header_descramble(uint8_t* input, uint64_t limit, uint8_t* input2, uint64_t chunk_size) {
    if (!((limit == 0x39 && chunk_size == 0x1C) || (limit == 0x21 && chunk_size == 8))) {
        cout << "unsupported parameters for mhy0_header_scramble" << endl;
        exit(1);
    }

    int rounded_size = (chunk_size + 15) & 0xFFFFFFF0;
    uint64_t total_rounded_size = (uint64_t)rounded_size + 4;

    bool finished = false;
    while (total_rounded_size < limit && !finished)
    {
        for (int k = 0; k < chunk_size; ++k)
        {
            input[k + total_rounded_size] ^= input2[k];
            if (k + total_rounded_size >= limit - 1)
            {
                finished = true;
                break;
            }
        }
        total_rounded_size += chunk_size;
    }

    for (int j = 3; j >= 0; j--)
        input[j] ^= input2[j];

    for (int i = 0; i < rounded_size; i += 16) // This can be left as is without reversing the direction
        mhy0_header_descramble2(&input[i + 4]);
}

void mhy0_repack(const char* out_format, int block_index, uint8_t* input, size_t input_size, uint8_t*& output_buf, size_t& output_size) {
    // loosely based on UnityPlayer:$1C64C0
    // TODO: bounds checks
    if (*(uint32_t*)input != 0x3079686D) { // mhy0
        cout << "decrypted data didn't start with mhy0, so decryption probably failed" << endl;
        exit(1);
    }

    uint32_t size = *(uint32_t*)(input + 4);
    cout << "first size 0x" << std::hex << size << endl;

    if (size > input_size) {
        // TODO: this is probably caused by the awful mhy0 searching approach i do instead of properly calculating offsets
        cout << "oh shit! attempted to get 0x" << hex << size << " bytes out of a 0x" << hex << input_size << " input! skipping mhy0 " << dec << block_index << endl;
        return;
    }

    uint8_t* tmp_output_buf = new uint8_t[input_size*2]; // To be 146% sure

    auto* data = new uint8_t[size];
    memcpy(data, input + 8, size);

    //hexdump("initial data", data, size);

    mhy0_header_scramble(data, 0x39, data + 4, 0x1C);

    //hexdump("data after scramble", data, size);

    //dump_to_file("mhy0_header_descrambled.bin", data, size);

    // TODO: there is a different path for calculating this, so this might mess up on some inputs
    //uint32_t decomp_size = MAKE_UINT32(data[0x20 + 1], data[0x20 + 6], data[0x20 + 3], data[0x20 + 2]);
    uint32_t decomp_size = MAKE_UINT32(data, 0x20 + 1, 0x20 + 6, 0x20 + 3, 0x20 + 2);
    cout << "decompressed size: 0x" << hex << decomp_size << endl;
    uint8_t* decomp_output = new uint8_t[decomp_size];
    auto lz4_res = LZ4_decompress_safe((const char*)(data + 0x27), (char*)decomp_output, size - 0x27, decomp_size);
    if (lz4_res < 0) {
        cout << "decompression failed: " << lz4_res << endl;
        exit(1);
    }
    delete[] data;
    //dump_to_file("mhy0_header_decompressed.bin", decomp_output, decomp_size);

    //cout << "next data cmp size: 0x" << hex << MAKE_UINT32(decomp_output, 0x11F + 2, 0x11F + 4, 0x11F, 0x11F + 5) << endl;
    //cout << "next data decmp size: 0x" << hex << MAKE_UINT32(decomp_output, 0x112 + 1, 0x112 + 6, 0x112 + 3, 0x112 + 2) << endl;
    //cout << "unknown 1: 0x" << hex << MAKE_UINT32(decomp_output, 0x10C + 2, 0x10C + 4, 0x10C, 0x10C + 5) << endl;
    auto cab_count = MAKE_UINT32(decomp_output, 2, 4, 0, 5);
    cout << "cab count: 0x" << hex << cab_count << endl;
    //auto entry_count = MAKE_UINT32(decomp_output, 0x119 + 2, 0x119 + 4, 0x119, 0x119 + 5);
    auto entry_count = MAKE_UINT32(decomp_output, cab_count * 0x113 + 6 + 2, cab_count * 0x113 + 6 + 4, cab_count * 0x113 + 6, cab_count * 0x113 + 6 + 5);
    cout << "entry count: 0x" << hex << entry_count << endl;
    //dump_to_file("bruh.bin", decomp_output, decomp_size);
    //hexdump("asdf", decomp_output, decomp_size);
    //exit(1);
    //if (entry_count > 0x10000) {
        //hexdump("wtf???? something probably went wrong!", decomp_output, decomp_size);
        //cout << "0x" << hex << MAKE_UINT32(decomp_output, 2, 4, 0, 5) << endl;
        //exit(1);
    //}

    uint8_t* entry_ptr = input + 0x8 + size;
    uint8_t* w_entry_ptr = tmp_output_buf;
    char filename[0x100] = {};
    //cout << out_format << endl;
    snprintf(filename, sizeof(filename), out_format, block_index);
    auto* output = fopen(filename, "wb");
    if (!output) {
        cout << "failed to open " << filename << endl;
        exit(1);
    }
    for (int i = 0; i < entry_count; i++) {
        auto offset = i * 13 + cab_count * 0x113 + 6;
        //cout << "processing entry " << i << " offset " << offset << " ptr " << 0x8 + size << endl;
        auto entry_cmp_size = MAKE_UINT32(decomp_output, offset + 6 + 2, offset + 6 + 4, offset + 6, offset + 6 + 5);
        auto entry_decmp_size = MAKE_UINT32(decomp_output, offset + 0xC + 1, offset + 0xC + 6, offset + 0xC + 3, offset + 0xC + 2);
        cout << hex << entry_cmp_size << endl;
        cout << hex << entry_decmp_size << endl;
        //hexdump("initial data", entry_ptr, entry_cmp_size);
        mhy0_header_scramble(entry_ptr, 0x21, entry_ptr + 4, 8);
        //hexdump("data after scramble", entry_ptr, entry_cmp_size);

        auto* entry_decmp = new uint8_t[entry_decmp_size];
        auto lz4_res = LZ4_decompress_safe((const char*)(entry_ptr + 0xC), (char*)entry_decmp, entry_cmp_size - 0xC, entry_decmp_size);
        if (lz4_res < 0) {
            cout << "decompression failed: " << lz4_res << endl;
            exit(1);
        }
        //dump_to_file(filename, entry_decmp, entry_decmp_size);
        fwrite(entry_decmp, entry_decmp_size, 1, output);

        dump_to_file("PROCESS.bin", entry_decmp, entry_decmp_size);

        cout << "Process PROCESS.bin file and press Enter when finished. Try not to change size!" << endl;

        getchar();

        uint8_t* new_entry_data = nullptr;
        size_t new_entry_size = 0;

        read_from_file("PROCESS.bin", new_entry_data, new_entry_size);
  
        if (new_entry_size != entry_decmp_size) {
          cout << "WARN: new file size is different: " << new_entry_size << " != " << entry_decmp_size << endl;
        }

        memcpy(w_entry_ptr, entry_ptr, 0xC);
        auto lz4_c_res = LZ4_compress_default((const char*)new_entry_data, (char*)(w_entry_ptr + 0xC), new_entry_size, (entry_cmp_size - 0xC)*2); // To be 146% sure
        if (lz4_c_res == 0) {
            cout << "compression failed: " << lz4_c_res << endl;
            exit(1);
        }
        mhy0_header_descramble(w_entry_ptr, 0x21, w_entry_ptr + 4, 8);
        lz4_c_res += 0xC;

        delete[] new_entry_data;

        cout << "new comp size " << lz4_c_res << endl;
        cout << "new decomp size " << new_entry_size << endl;

        PUT_UINT32(decomp_output, offset + 6 + 2, offset + 6 + 4, offset + 6, offset + 6 + 5, lz4_c_res);
        PUT_UINT32(decomp_output, offset + 0xC + 1, offset + 0xC + 6, offset + 0xC + 3, offset + 0xC + 2, new_entry_size);

        delete[] entry_decmp;
        entry_ptr += entry_cmp_size;
        w_entry_ptr += lz4_c_res;

        entry_cmp_size = MAKE_UINT32(decomp_output, offset + 6 + 2, offset + 6 + 4, offset + 6, offset + 6 + 5);
        entry_decmp_size = MAKE_UINT32(decomp_output, offset + 0xC + 1, offset + 0xC + 6, offset + 0xC + 3, offset + 0xC + 2);
        cout << "Recorded" << endl;
        cout << hex << entry_cmp_size << endl;
        cout << hex << entry_decmp_size << endl;
    }
    fclose(output);

    uint8_t* new_header = new uint8_t[0x27 + 8 + decomp_size*2]; // To be 146% sure
    uint8_t* new_data = new_header + 8;

    memcpy(new_data, data, size);

    auto lz4_c_res = LZ4_compress_default((const char*)decomp_output, (char*)(new_data + 0x27), decomp_size, decomp_size*2); // To be 146% sure
    if (lz4_c_res == 0) {
        cout << "compression failed: " << lz4_c_res << endl;
        exit(1);
    }

    delete[] decomp_output;

    size = lz4_c_res + 0x27;

    cout << "new size " << size << endl;

    *(uint32_t*)new_header = 0x3079686D; // "mhy0"
    *(uint32_t*)(new_header+4) = size; // New compressed size

    mhy0_header_descramble(new_data, 0x39, new_data + 4, 0x1C);

    size_t pure_output_size = w_entry_ptr - tmp_output_buf;

    output_size = pure_output_size + size + 8;

    output_buf = new uint8_t[output_size];
    memcpy(output_buf, new_header, size+8);
    memcpy(output_buf+size+8, tmp_output_buf, pure_output_size);

    delete[] new_header;
    delete[] tmp_output_buf;

    //dump_to_file("reconstructed.bin", output_buf, output_size);
}

void mhy0_extract(const char* out_format, int block_index, uint8_t* input, size_t input_size) {
    // loosely based on UnityPlayer:$1C64C0
    // TODO: bounds checks
    if (*(uint32_t*)input != 0x3079686D) { // mhy0
        cout << "decrypted data didn't start with mhy0, so decryption probably failed" << endl;
        exit(1);
    }

    uint32_t size = *(uint32_t*)(input + 4);
    //cout << "first size 0x" << std::hex << size << endl;

    if (size > input_size) {
        // TODO: this is probably caused by the awful mhy0 searching approach i do instead of properly calculating offsets
        cout << "oh shit! attempted to get 0x" << hex << size << " bytes out of a 0x" << hex << input_size << " input! skipping mhy0 " << dec << block_index << endl;
        return;
    }

    auto* data = new uint8_t[size];
    memcpy(data, input + 8, size);

    //hexdump("initial data", data, size);

    mhy0_header_scramble(data, 0x39, data + 4, 0x1C);

    //hexdump("data after scramble", data, size);

    //dump_to_file("mhy0_header_descrambled.bin", data, size);

    // TODO: there is a different path for calculating this, so this might mess up on some inputs
    //uint32_t decomp_size = MAKE_UINT32(data[0x20 + 1], data[0x20 + 6], data[0x20 + 3], data[0x20 + 2]);
    uint32_t decomp_size = MAKE_UINT32(data, 0x20 + 1, 0x20 + 6, 0x20 + 3, 0x20 + 2);
    //cout << "decompressed size: 0x" << hex << decomp_size << endl;
    uint8_t* decomp_output = new uint8_t[decomp_size];
    auto lz4_res = LZ4_decompress_safe((const char*)(data + 0x27), (char*)decomp_output, size - 0x27, decomp_size);
    if (lz4_res < 0) {
        cout << "decompression failed: " << lz4_res << endl;
        exit(1);
    }
    delete[] data;
    //dump_to_file("mhy0_header_decompressed.bin", decomp_output, decomp_size);

    //cout << "next data cmp size: 0x" << hex << MAKE_UINT32(decomp_output, 0x11F + 2, 0x11F + 4, 0x11F, 0x11F + 5) << endl;
    //cout << "next data decmp size: 0x" << hex << MAKE_UINT32(decomp_output, 0x112 + 1, 0x112 + 6, 0x112 + 3, 0x112 + 2) << endl;
    //cout << "unknown 1: 0x" << hex << MAKE_UINT32(decomp_output, 0x10C + 2, 0x10C + 4, 0x10C, 0x10C + 5) << endl;
    auto cab_count = MAKE_UINT32(decomp_output, 2, 4, 0, 5);
    //cout << "cab count: 0x" << hex << cab_count << endl;
    //auto entry_count = MAKE_UINT32(decomp_output, 0x119 + 2, 0x119 + 4, 0x119, 0x119 + 5);
    auto entry_count = MAKE_UINT32(decomp_output, cab_count * 0x113 + 6 + 2, cab_count * 0x113 + 6 + 4, cab_count * 0x113 + 6, cab_count * 0x113 + 6 + 5);
    //cout << "entry count: 0x" << hex << entry_count << endl;
    //dump_to_file("bruh.bin", decomp_output, decomp_size);
    //hexdump("asdf", decomp_output, decomp_size);
    //exit(1);
    //if (entry_count > 0x10000) {
        //hexdump("wtf???? something probably went wrong!", decomp_output, decomp_size);
        //cout << "0x" << hex << MAKE_UINT32(decomp_output, 2, 4, 0, 5) << endl;
        //exit(1);
    //}

    uint8_t* entry_ptr = input + 0x8 + size;
    char filename[0x100] = {};
    //cout << out_format << endl;
    snprintf(filename, sizeof(filename), out_format, block_index);
    auto* output = fopen(filename, "wb");
    if (!output) {
        cout << "failed to open " << filename << endl;
        exit(1);
    }
    for (int i = 0; i < entry_count; i++) {
        auto offset = i * 13 + cab_count * 0x113 + 6;
        //cout << "processing entry " << i << " offset " << offset << " ptr " << 0x8 + size << endl;
        auto entry_cmp_size = MAKE_UINT32(decomp_output, offset + 6 + 2, offset + 6 + 4, offset + 6, offset + 6 + 5);
        auto entry_decmp_size = MAKE_UINT32(decomp_output, offset + 0xC + 1, offset + 0xC + 6, offset + 0xC + 3, offset + 0xC + 2);
        //cout << hex << entry_cmp_size << endl;
        //hexdump("initial data", entry_ptr, entry_cmp_size);
        mhy0_header_scramble(entry_ptr, 0x21, entry_ptr + 4, 8);
        //hexdump("data after scramble", entry_ptr, entry_cmp_size);

        auto* entry_decmp = new uint8_t[entry_decmp_size];
        auto lz4_res = LZ4_decompress_safe((const char*)(entry_ptr + 0xC), (char*)entry_decmp, entry_cmp_size - 0xC, entry_decmp_size);
        if (lz4_res < 0) {
            cout << "decompression failed: " << lz4_res << endl;
            exit(1);
        }
        //dump_to_file(filename, entry_decmp, entry_decmp_size);
        fwrite(entry_decmp, entry_decmp_size, 1, output);
        delete[] entry_decmp;
        entry_ptr += entry_cmp_size;
    }
    fclose(output);

    delete[] decomp_output;
}

int extract_blk(char* in_filename, const char* out_format, bool perform_repack = false) {
    auto* blk_file = fopen(in_filename, "rb");

    if (!blk_file) {
        cout << "failed to open blk" << endl;
        return 1;
    }

    blk_header hdr, hdr_copy;
    bool fail = false;

    if (fread(&hdr, sizeof(blk_header), 1, blk_file) < 1) {
        cout << "Failed to read BLK header!" << endl;
        fail = true;
    }

    if (!fail && hdr.magic != 0x6B6C62) { // blk\x00
        cout << "bad file magic" << endl;
        fail = true;
    }

    if (!fail && hdr.version != 0x10) {
        cout << "version is not 0x10" << endl;
        fail = true;
    }

    if (fail) {
        fclose(blk_file);
        return 1;
    }

    if (perform_repack)
        memcpy(&hdr_copy, &hdr, sizeof(blk_header));

    //hexdump("encrypted blk key:", key, sizeof(key));
    key_scramble1(hdr.key1);
    key_scramble2(hdr.key1);
    // this should also go into magic_constants.h, but it's small
    // this value goes through a lot of computation to get generated, but is always the same
    uint8_t hard_key[] = { 0xE3, 0xFC, 0x2D, 0x26, 0x9C, 0xC5, 0xA2, 0xEC, 0xD3, 0xF8, 0xC6, 0xD3, 0x77, 0xC2, 0x49, 0xB9 };
    for (int i = 0; i < 16; i++)
        hdr.key1[i] ^= hard_key[i];
    //hexdump("decrypted blk key:", key, sizeof(key));

    fseek(blk_file, 0, SEEK_END);
    size_t size = ftell(blk_file) - sizeof(blk_header);
    fseek(blk_file, sizeof(blk_header), SEEK_SET); // skip header 

    auto* data = new uint8_t[size];
    fread(data, size, 1, blk_file);
    fclose(blk_file);

    uint8_t xorpad[4096] = {};
    create_decrypt_vector(hdr.key1, data, std::min((uint64_t)hdr.block_size, sizeof(xorpad)), xorpad, sizeof(xorpad));
    for (int i = 0; i < size; i++)
        data[i] ^= xorpad[i & 0xFFF];
    //dump_to_file("decrypted.bin", data, size);
    //dump_to_file("xorpad.bin", xorpad, sizeof(xorpad));

    //fwrite(data, size, 1, output);

    uint8_t* output_buf = nullptr;
    size_t output_size = 0;

    uint8_t* full_buff = nullptr;
    size_t full_size = 0;

    std::vector<size_t> mhy0_locs;
    size_t last_loc = 0;
    for (int i = 0; ; i++) {
        auto res = memmem(data + last_loc, size - last_loc, (void*)"mhy0", 4);
        if (res) {
            auto loc = (uint8_t*)res - data;
            mhy0_locs.push_back(loc);
            //cout << "found mhy0 at 0x" << hex << loc << endl;
            if (perform_repack) {
                mhy0_repack(out_format, i, data + loc, size, output_buf, output_size);
                full_buff = (uint8_t*)realloc(full_buff, full_size + output_size);
                memcpy(full_buff+full_size, output_buf, output_size);
                full_size += output_size;
                delete[] output_buf;
            } else {
                mhy0_extract(out_format, i, data + loc, size);
            }
            last_loc = loc + 4;
        } else {
            break;
        }
    }

    delete[] data;

    if (perform_repack) {
        for (int i = 0; i < 4096; i++)
          xorpad[i] = 0;
    
        uint64_t seed = 0xDEADBEEF; // TODO: maybe choose a random one?

        create_encrypt_vector(xorpad, sizeof(xorpad), seed);
    
        for (int i = 0; i < output_size; i++)
          full_buff[i] ^= xorpad[i & 0xFFF];
    
        calc_decrypt_key(hdr_copy.key1, seed, full_buff, std::min((uint64_t)hdr.block_size, sizeof(xorpad))); // TODO: what if data size is small?
    
        FILE* repack = fopen("repack.blk", "wb");
        fwrite(&hdr_copy, sizeof(blk_header), 1, repack);
        fwrite(full_buff, full_size, 1, repack);
        fclose(repack);
    
        free(full_buff);
    }

    return 0;
}

int main(int argc, char** argv) {
    #if 0
    uint8_t round_keys[11*16] = {0};
    uint8_t seed[] = {0x54, 0x2f, 0xed, 0x67, 0x5d, 0xdd, 0x11, 0x2e, 0xb7, 0x40, 0x13, 0xe3, 0x29, 0xab, 0x6d, 0x28};
    uint8_t seed2[] = {0x1e, 0x14, 0x40, 0x12, 0xed, 0x7b, 0x85, 0x47, 0x8d, 0xd2, 0xcd, 0xf8, 0x4d, 0x71, 0xbc, 0x62};

    aes_expand_round_keys(round_keys, seed);
    puts("--------------------");
    memset(round_keys, 0, 11*16);
    kinda_expand_round_keys(round_keys);
    puts("--------------------");
    memset(round_keys, 0, 11*16);
    aes_expand_round_keys(round_keys, seed2);
    exit(0);
    #endif

    if (argc < 2) {
        cout << "you need an input file" << endl;
        return 1;
    }
    if (!strcmp(argv[1], "batch")) {
        if (argc < 4) {
            cout << "you need input and output folders for batch mode" << endl;
            return 1;
        }

        auto base_path = std::filesystem::path(argv[2]);
        std::vector<std::filesystem::path> blk_paths;
        cout << "scanning for blks" << endl;
        try {
            for (auto& p : std::filesystem::recursive_directory_iterator(base_path)) {
                if (p.path().extension() == ".blk")
                    //cout << p.path().lexically_relative(base_path) << endl;
                    blk_paths.push_back(p.path().lexically_relative(base_path));
            }
        } catch (const std::exception& e) {
            cout << "failed to search for blk files with error: " << e.what() << endl;
            return 1;
        }
        cout << "found " << blk_paths.size() << " blks to extract" << endl;

        auto output_base = std::filesystem::path(argv[3]);
        //for (auto& p : blk_paths) {
        #pragma omp parallel for
        for (int i = 0; i < blk_paths.size(); i++) {
            auto p = blk_paths[i];
            cout << "processing " << p << "... ";

            auto input_path = base_path / p;
            auto output_path = (output_base / p).replace_extension(".%d.bin");
            auto output_dir = std::filesystem::path(output_path).remove_filename();
            //cout << output_path << endl;
            std::filesystem::create_directories(output_dir);
            int ret = extract_blk((char*)input_path.generic_string().c_str(), output_path.generic_string().c_str());

            if (!ret)
              cout << "ok" << endl;
        }
    } else if (!strcmp(argv[1], "repack")) {
        if (argc < 3) {
            cout << "you need to provide input BLK name" << endl;
            return 1;
        }
        extract_blk(argv[2], "output%d.bin", true);
    } else {
        extract_blk(argv[1], "output%d.bin");
    }
}

# FindCrypt
A Python implementation of IDA FindCrypt/FindCrypt2 plugin (see http://www.hexblog.com/?p=28).

## How to use
Execute findcrypt.py on your IDA. Tested on IDA 7.0+ for macOS.

## Supported constants
* (XX)TEA: (XX)TEA_delta
* AES: Rijndael_sbox, Rijndael_inv_sbox, Rijndael_Te0, Rijndael_Te1, Rijndael_Te2, Rijndael_Te3, Rijndael_Te4, Rijndael_Td0, Rijndael_Td1, Rijndael_Td2, Rijndael_Td3, Rijndael_Td4
* Adler-32: Adler32_BASE
* Blowfish: Blowfish_P_array, Blowfish_S_boxes
* CRC32: CRC32_m_tab_le, CRC32_m_tab_be, ms_pst_crc32_table_0, ms_pst_crc32_table_1, ms_pst_crc32_table_2, ms_pst_crc32_table_3, ms_pst_crc32_table_4, ms_pst_crc32_table_5, ms_pst_crc32_table_6, lzma_crc32_table_0, lzma_crc32_table_1, lzma_crc32_table_2, lzma_crc32_table_3, lzma_crc32_table_4, lzma_crc32_table_5, lzma_crc32_table_6, lzma_crc32_table_7
* CRC64: CRC64_ECMA
* Camellia: Camellia_sigma, Camellia_SBOX1, Camellia_SBOX2, Camellia_SBOX3, Camellia_SBOX4
* DES: DES_ip, DES_fp, DES_ei, DES_sbox1, DES_sbox2, DES_sbox3, DES_sbox4, DES_sbox5, DES_sbox6, DES_sbox7, DES_sbox8, DES_p32i, DES_pc1, DES_pc2
* FNV-1-32: FNV-1-32_prime, FNV-1-32_offset_basis
* FNV-1-64: FNV-1-64_prime, FNV-1-64_offset_basis
* MD5: MD5_T, MD5_initstate
* RC5_RC6: RC5_RC6_PQ
* SHA1: SHA1_H, SHA1_K
* SHA224: SHA224_H
* SHA224/SHA256: SHA224_SHA256_K
* SHA256: SHA256_H
* SHA512: SHA512_H, SHA512_K
* SM3: SM3_IV
* SM4: SM4_SBox, SM4_CK, SM4_FK
* Salsa20_ChaCha: Salsa20_ChaCha_sigma, Salsa20_ChaCha_tau
* VEST: rns_w, rns_f, p5, vest_sbox, vest_f, vest_4_structure, provest_4, vest_8_structure, provest_8, vest_16_structure, provest_16, vest_32_structure, provest_32
* aPLib: aPLib_magic
* xxHash32: xxHash32_PRIME32
* xxHash64: xxHash64_PRIME64
* zlib: zinflate_lengthStarts, zinflate_lengthExtraBits, zinflate_distanceStarts, zinflate_distanceExtraBits, zdeflate_lengthCodes

## Todo
1. Add more constants - I always welcome your pull request :)
2. Performance improvement

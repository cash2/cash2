// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include <cstdint>
#include "Logging/LoggerGroup.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "Serialization/BinarySerializationTools.h"
#include "Common/Base58.cpp"

using namespace Tools;
using namespace CryptoNote;

namespace
{

void test_uint_8be_to_64(uint64_t expected, const std::string& data)
{
  uint64_t val = Base58::uint_8be_to_64(reinterpret_cast<const uint8_t*>(data.data()), data.size());
  ASSERT_EQ(val, expected);
}

void test_uint_64_to_8be(uint64_t num, const std::string& expected_str)
{
  std::string data(expected_str.size(), '\x0');
  Base58::uint_64_to_8be(num, data.size(), reinterpret_cast<uint8_t*>(&data[0]));
  ASSERT_EQ(data, expected_str);
}

void test_encode_block(const std::string& block, const std::string& expected)
{
  ASSERT_TRUE(1 <= block.size() && block.size() <= Base58::full_block_size);
  std::string enc(Base58::encoded_block_sizes[block.size()], Base58::alphabet[0]);
  Base58::encode_block(block.data(), block.size(), &enc[0]);
  ASSERT_EQ(enc, expected);

  std::string dec(block.size(), '\0');
  ASSERT_TRUE(Base58::decode_block(enc.data(), enc.size(), &dec[0]));
  ASSERT_EQ(block, dec);
}

void test_decode_block_pos(const std::string& enc, const std::string& expected)
{
  std::string data(Base58::decoded_block_sizes::instance(enc.size()), '\0');
  ASSERT_TRUE(Base58::decode_block(enc.data(), enc.size(), &data[0]));
  ASSERT_EQ(data, expected);
}

void test_decode_block_neg(const std::string& enc)
{
  std::string data(Base58::full_block_size, '\0');
  ASSERT_FALSE(Base58::decode_block(enc.data(), enc.size(), &data[0]));
}

void test_encode(const std::string& data, const std::string& expected)
{
  std::string enc = Base58::encode(data);
  ASSERT_EQ(enc, expected);

  std::string dec;
  ASSERT_TRUE(Base58::decode(enc, dec));
  ASSERT_EQ(dec, data);
}

void test_decode_pos(const std::string& enc, const std::string& expected)
{
  std::string dec;
  ASSERT_TRUE(Base58::decode(enc, dec));
  ASSERT_EQ(dec, expected);
}

void test_decode_neg(const std::string& enc)
{
  std::string dec;
  ASSERT_FALSE(Base58::decode(enc, dec));
}

void test_encode_decode_addr(uint64_t tag, const std::string& data, const std::string& expected)
{
  std::string addr = Base58::encode_addr(tag, data);
  ASSERT_EQ(addr, expected);

  uint64_t dec_tag;
  std::string dec_data;
  ASSERT_TRUE(Base58::decode_addr(addr, dec_tag, dec_data));
  ASSERT_EQ(tag, dec_tag);
  ASSERT_EQ(data, dec_data);
}

}

TEST(base58_uint_8be_to_64, 0x0000000000000001)
{
  test_uint_8be_to_64(0x0000000000000001, "\x1");
}

TEST(base58_uint_8be_to_64, 0x0000000000000102)
{
  test_uint_8be_to_64(0x0000000000000102, "\x1\x2");
}

TEST(base58_uint_8be_to_64, 0x0000000000010203)
{
  test_uint_8be_to_64(0x0000000000010203, "\x1\x2\x3");
}

TEST(base58_uint_8be_to_64, 0x0000000001020304)
{
  test_uint_8be_to_64(0x0000000001020304, "\x1\x2\x3\x4");
}

TEST(base58_uint_8be_to_64, 0x0000000102030405)
{
  test_uint_8be_to_64(0x0000000102030405, "\x1\x2\x3\x4\x5");
}

TEST(base58_uint_8be_to_64, 0x0000010203040506)
{
  test_uint_8be_to_64(0x0000010203040506, "\x1\x2\x3\x4\x5\x6");
}

TEST(base58_uint_8be_to_64, 0x0001020304050607)
{
  test_uint_8be_to_64(0x0001020304050607, "\x1\x2\x3\x4\x5\x6\x7");
}

TEST(base58_uint_8be_to_64, 0x0102030405060708)
{
  test_uint_8be_to_64(0x0102030405060708, "\x1\x2\x3\x4\x5\x6\x7\x8");
}

TEST(TEST_uint_64_to_8be, 0x0000000000000001)
{
  test_uint_64_to_8be(0x0000000000000001, "\x1");
}

TEST(TEST_uint_64_to_8be, 0x0000000000000102)
{
  test_uint_64_to_8be(0x0000000000000102, "\x1\x2");
}

TEST(TEST_uint_64_to_8be, 0x0000000000010203)
{
  test_uint_64_to_8be(0x0000000000010203, "\x1\x2\x3");
}

TEST(TEST_uint_64_to_8be, 0x0000000001020304)
{
  test_uint_64_to_8be(0x0000000001020304, "\x1\x2\x3\x4");
}

TEST(TEST_uint_64_to_8be, 0x0000000102030405)
{
  test_uint_64_to_8be(0x0000000102030405, "\x1\x2\x3\x4\x5");
}

TEST(TEST_uint_64_to_8be, 0x0000010203040506)
{
  test_uint_64_to_8be(0x0000010203040506, "\x1\x2\x3\x4\x5\x6");
}

TEST(TEST_uint_64_to_8be, 0x0001020304050607)
{
  test_uint_64_to_8be(0x0001020304050607, "\x1\x2\x3\x4\x5\x6\x7");
}

TEST(TEST_uint_64_to_8be, 0x0102030405060708)
{
  test_uint_64_to_8be(0x0102030405060708, "\x1\x2\x3\x4\x5\x6\x7\x8");
}

TEST(reverse_alphabet, is_correct)
{
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance(0));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance(std::numeric_limits<char>::min()));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance(std::numeric_limits<char>::max()));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance('1' - 1));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance('z' + 1));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance('0'));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance('I'));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance('O'));
  ASSERT_EQ(-1, Base58::reverse_alphabet::instance('l'));
  ASSERT_EQ(0,  Base58::reverse_alphabet::instance('1'));
  ASSERT_EQ(8,  Base58::reverse_alphabet::instance('9'));
  ASSERT_EQ(Base58::alphabet_size - 1, Base58::reverse_alphabet::instance('z'));
}


// encode block



#define MAKE_STR(arr) std::string(arr, sizeof(arr) - 1)

#include <iostream>

TEST(base58_encode_block, 11)
{

  const std::string block = std::string("\x00", sizeof("\x00") - 1);
  test_encode_block(block, "11");
}

TEST(base58_encode_block, 1z)
{
  const std::string block = std::string("\x39", sizeof("\x39") - 1);
  test_encode_block(block, "1z");
}

TEST(base58_encode_block, 5Q)
{
  const std::string block = std::string("\xFF", sizeof("\xFF") - 1);
  test_encode_block(block, "5Q");
}

TEST(base58_encode_block, 111)
{
  const std::string block = std::string("\x00\x00", sizeof("\x00\x00") - 1);
  test_encode_block(block, "111");
}

TEST(base58_encode_block, 11z)
{
  const std::string block = std::string("\x00\x39", sizeof("\x00\x39") - 1);
  test_encode_block(block, "11z");
}

TEST(base58_encode_block, 15R)
{
  const std::string block = std::string("\x01\x00", sizeof("\x01\x00") - 1);
  test_encode_block(block, "15R");
}

TEST(base58_encode_block, LUv)
{
  const std::string block = std::string("\xFF\xFF", sizeof("\xFF\xFF") - 1);
  test_encode_block(block, "LUv");
}

TEST(base58_encode_block, 11111)
{
  const std::string block = std::string("\x00\x00\x00", sizeof("\x00\x00\x00") - 1);
  test_encode_block(block, "11111");
}

TEST(base58_encode_block, 1111z)
{
  const std::string block = std::string("\x00\x00\x39", sizeof("\x00\x00\x39") - 1);
  test_encode_block(block, "1111z");
}

TEST(base58_encode_block, 11LUw)
{
  const std::string block = std::string("\x01\x00\x00", sizeof("\x01\x00\x00") - 1);
  test_encode_block(block, "11LUw");
}

TEST(base58_encode_block, 2UzHL)
{
  const std::string block = std::string("\xFF\xFF\xFF", sizeof("\xFF\xFF\xFF") - 1);
  test_encode_block(block, "2UzHL");
}

TEST(base58_encode_block, 11111z)
{
  const std::string block = std::string("\x00\x00\x00\x39", sizeof("\x00\x00\x00\x39") - 1);
  test_encode_block(block, "11111z");
}

TEST(base58_encode_block, 7YXq9G)
{
  const std::string block = std::string("\xFF\xFF\xFF\xFF", sizeof("\xFF\xFF\xFF\xFF") - 1);
  test_encode_block(block, "7YXq9G");
}

TEST(base58_encode_block, 111111z)
{
  const std::string block = std::string("\x00\x00\x00\x00\x39", sizeof("\x00\x00\x00\x00\x39") - 1);
  test_encode_block(block, "111111z");
}

TEST(base58_encode_block, VtB5VXc)
{
  const std::string block = std::string("\xFF\xFF\xFF\xFF\xFF", sizeof("\xFF\xFF\xFF\xFF\xFF") - 1);
  test_encode_block(block, "VtB5VXc");
}

TEST(base58_encode_block, 11111111z)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x39", sizeof("\x00\x00\x00\x00\x00\x39") - 1);
  test_encode_block(block, "11111111z");
}

TEST(base58_encode_block, 3CUsUpv9t)
{
  const std::string block = std::string("\xFF\xFF\xFF\xFF\xFF\xFF", sizeof("\xFF\xFF\xFF\xFF\xFF\xFF") - 1);
  test_encode_block(block, "3CUsUpv9t");
}

TEST(base58_encode_block, 111111111z)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x39", sizeof("\x00\x00\x00\x00\x00\x00\x39") - 1);
  test_encode_block(block, "111111111z");
}

TEST(base58_encode_block, Ahg1opVcGW)
{
  const std::string block = std::string("\xFF\xFF\xFF\xFF\xFF\xFF\xFF", sizeof("\xFF\xFF\xFF\xFF\xFF\xFF\xFF") - 1);
  test_encode_block(block, "Ahg1opVcGW");
}

TEST(base58_encode_block, 1111111111z)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x39", sizeof("\x00\x00\x00\x00\x00\x00\x00\x39") - 1);
  test_encode_block(block, "1111111111z");
}

TEST(base58_encode_block, jpXCZedGfVQ)
{
  const std::string block = std::string("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", sizeof("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF") - 1);
  test_encode_block(block, "jpXCZedGfVQ");
}

TEST(base58_encode_block, 11111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode_block(block, "11111111111");
}

TEST(base58_encode_block, 11111111112)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x01", sizeof("\x00\x00\x00\x00\x00\x00\x00\x01") - 1);
  test_encode_block(block, "11111111112");
}

TEST(base58_encode_block, 11111111119)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x08", sizeof("\x00\x00\x00\x00\x00\x00\x00\x08") - 1);
  test_encode_block(block, "11111111119");
}

TEST(base58_encode_block, 1111111111A)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x09", sizeof("\x00\x00\x00\x00\x00\x00\x00\x09") - 1);
  test_encode_block(block, "1111111111A");
}

TEST(base58_encode_block, 11111111121)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x3A", sizeof("\x00\x00\x00\x00\x00\x00\x00\x3A") - 1);
  test_encode_block(block, "11111111121");
}

TEST(base58_encode_block, 1Ahg1opVcGW)
{
  const std::string block = std::string("\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF", sizeof("\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF") - 1);
  test_encode_block(block, "1Ahg1opVcGW");
}

TEST(base58_encode_block, 22222222222)
{
  const std::string block = std::string("\x06\x15\x60\x13\x76\x28\x79\xF7", sizeof("\x06\x15\x60\x13\x76\x28\x79\xF7") - 1);
  test_encode_block(block, "22222222222");
}

TEST(base58_encode_block, 1z111111111)
{
  const std::string block = std::string("\x05\xE0\x22\xBA\x37\x4B\x2A\x00", sizeof("\x05\xE0\x22\xBA\x37\x4B\x2A\x00") - 1);
  test_encode_block(block, "1z111111111");
}


// Decode block

// 1-byte block


TEST(base58_decode_block, 1)
{
  test_decode_block_neg("1");
}

TEST(base58_decode_block, z)
{
  test_decode_block_neg("z");
}


// 2-bytes block


TEST(base58_decode_block, 11)
{
  const std::string block = std::string("\x00", sizeof("\x00") - 1);
  test_encode_block(block, "11");
}

TEST(base58_decode_block, 5Q)
{
  test_decode_block_pos("5Q", "\xFF");
}

TEST(base58_decode_block, 5R)
{
  test_decode_block_neg("5R");
}

TEST(base58_decode_block, zz)
{
  test_decode_block_neg("zz");
}


// 3-bytes block


TEST(base58_decode_block, 111)
{
  const std::string block = std::string("\x00\x00", sizeof("\x00\x00") - 1);
  test_encode_block(block, "111");
}

TEST(base58_decode_block, LUv)
{
  test_decode_block_pos("LUv", "\xFF\xFF");
}

TEST(base58_decode_block, LUw)
{
  test_decode_block_neg("LUw");
}

TEST(base58_decode_block, zzz)
{
  test_decode_block_neg("zzz");
}


// 4-bytes block


TEST(base58_decode_block, 1111)
{
  const std::string block = std::string("1111", sizeof("1111") - 1);
  test_decode_block_neg(block);
}

TEST(base58_decode_block, zzzz)
{
  test_decode_block_neg("zzzz");
}


// 5-bytes block


TEST(base58_decode_block, 11111)
{
  const std::string block = std::string("\x00\x00\x00", sizeof("\x00\x00\x00") - 1);
  test_decode_block_pos("11111", block);
}

TEST(base58_decode_block, 2UzHL)
{
  test_decode_block_pos("2UzHL", "\xFF\xFF\xFF");
}

TEST(base58_decode_block, 2UzHM)
{
  test_decode_block_neg("2UzHM");
}

TEST(base58_decode_block, zzzzz)
{
  test_decode_block_neg("zzzzz");
}


// 6-bytes block


TEST(base58_decode_block, 111111)
{
  const std::string block = std::string("\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00") - 1);
  test_decode_block_pos("111111", block);
}

TEST(base58_decode_block, 7YXq9G)
{
  test_decode_block_pos("7YXq9G", "\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_block, 7YXq9H)
{
  test_decode_block_neg("7YXq9H");
}

TEST(base58_decode_block, zzzzzz)
{
  test_decode_block_neg("zzzzzz");
}


// 7-bytes block


TEST(base58_decode_block, 1111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00") - 1);
  test_decode_block_pos("1111111", block);
}

TEST(base58_decode_block, VtB5VXc)
{
  test_decode_block_pos("VtB5VXc", "\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_block, VtB5VXd)
{
  test_decode_block_neg("VtB5VXd");
}

TEST(base58_decode_block, zzzzzzz)
{
  test_decode_block_neg("zzzzzzz");
}


// 8-bytes block


TEST(base58_decode_block, 11111111)
{
  const std::string block = std::string("11111111", sizeof("11111111") - 1);
  test_decode_block_neg(block);
}

TEST(base58_decode_block, zzzzzzzz)
{
  test_decode_block_neg("zzzzzzzz");
}


// 9-bytes block


TEST(base58_decode_block, 111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00") - 1);
  test_decode_block_pos("111111111", block);
}

TEST(base58_decode_block, 3CUsUpv9t)
{
  test_decode_block_pos("3CUsUpv9t", "\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_block, 3CUsUpv9u)
{
  test_decode_block_neg("3CUsUpv9u");
}

TEST(base58_decode_block, zzzzzzzzz)
{
  test_decode_block_neg("zzzzzzzzz");
}


// 10-bytes block


TEST(base58_decode_block, 1111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_decode_block_pos("1111111111", block);
}

TEST(base58_decode_block, Ahg1opVcGW)
{
  test_decode_block_pos("Ahg1opVcGW", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_block, Ahg1opVcGX)
{
  test_decode_block_neg("Ahg1opVcGX");
}

TEST(base58_decode_block, zzzzzzzzzz)
{
  test_decode_block_neg("zzzzzzzzzz");
}


// 11-bytes block


TEST(base58_decode_block, 11111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_decode_block_pos("11111111111", block);
}

TEST(base58_decode_block, jpXCZedGfVQ)
{
  test_decode_block_pos("jpXCZedGfVQ", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_block, jpXCZedGfVR)
{
  test_decode_block_neg("jpXCZedGfVR");
}

TEST(base58_decode_block, zzzzzzzzzzz)
{
  test_decode_block_neg("zzzzzzzzzzz");
}


// Invalid symbols


TEST(base58_decode_block, 01111111111)
{
  test_decode_block_neg("01111111111");
}

TEST(base58_decode_block, 11111111110)
{
  test_decode_block_neg("11111111110");
}

TEST(base58_decode_block, 11111011111)
{
  test_decode_block_neg("11111011111");
}

TEST(base58_decode_block, I1111111111)
{
  test_decode_block_neg("I1111111111");
}

TEST(base58_decode_block, O1111111111)
{
  test_decode_block_neg("O1111111111");
}

TEST(base58_decode_block, l1111111111)
{
  test_decode_block_neg("l1111111111");
}

TEST(base58_decode_block, _1111111111)
{
  test_decode_block_neg("_1111111111");
}

TEST(base58_encode, handles_11)
{
  const std::string block = std::string("\x00", sizeof("\x00") - 1);
  test_encode(block, "11");
}

TEST(base58_encode, handles_111)
{
  const std::string block = std::string("\x00\x00", sizeof("\x00\x00") - 1);
  test_encode(block, "111");
}

TEST(base58_encode, handles_11111)
{
  const std::string block = std::string("\x00\x00\x00", sizeof("\x00\x00\x00") - 1);
  test_encode(block, "11111");
}

TEST(base58_encode, handles_111111)
{
  const std::string block = std::string("\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00") - 1);
  test_encode(block, "111111");
}

TEST(base58_encode, handles_1111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "1111111");
}

TEST(base58_encode, handles_111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "111111111");
}

TEST(base58_encode, handles_1111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "1111111111");
}

TEST(base58_encode, handles_11111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "11111111111");
}

TEST(base58_encode, handles_1111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "1111111111111");
}

TEST(base58_encode, handles_11111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "11111111111111");
}

TEST(base58_encode, handles_1111111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "1111111111111111");
}

TEST(base58_encode, handles_11111111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "11111111111111111");
}

TEST(base58_encode, handles_111111111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "111111111111111111");
}

TEST(base58_encode, handles_11111111111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "11111111111111111111");
}

TEST(base58_encode, handles_111111111111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "111111111111111111111");
}

TEST(base58_encode, handles_1111111111111111111111)
{
  const std::string block = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  test_encode(block, "1111111111111111111111");
}

TEST(base58_encode, handles_22222222222VtB5VXc)
{

  const std::string block = std::string("\x06\x15\x60\x13\x76\x28\x79\xF7\xFF\xFF\xFF\xFF\xFF", sizeof("\x06\x15\x60\x13\x76\x28\x79\xF7\xFF\xFF\xFF\xFF\xFF") - 1);
  test_encode(block, "22222222222VtB5VXc");
}

TEST(base58_decode_pos, handles_pos)
{
  test_decode_pos("", "");
}

TEST(base58_decode_pos, handles_pos_5Q)
{
  test_decode_pos("5Q", "\xFF");
}

TEST(base58_decode_pos, handles_pos_LUv)
{
  test_decode_pos("LUv", "\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_2UzHL)
{
  test_decode_pos("2UzHL", "\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_7YXq9G)
{
  test_decode_pos("7YXq9G", "\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_VtB5VXc)
{
  test_decode_pos("VtB5VXc", "\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_3CUsUpv9t)
{
  test_decode_pos("3CUsUpv9t", "\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_Ahg1opVcGW)
{
  test_decode_pos("Ahg1opVcGW", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQ)
{
  test_decode_pos("jpXCZedGfVQ", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQ5Q)
{
  test_decode_pos("jpXCZedGfVQ5Q", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQLUv)
{
  test_decode_pos("jpXCZedGfVQLUv", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQ2UzHL)
{
  test_decode_pos("jpXCZedGfVQ2UzHL", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQ7YXq9G)
{
  test_decode_pos("jpXCZedGfVQ7YXq9G", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQVtB5VXc)
{
  test_decode_pos("jpXCZedGfVQVtB5VXc", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQ3CUsUpv9t)
{
  test_decode_pos("jpXCZedGfVQ3CUsUpv9t", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQAhg1opVcGW)
{
  test_decode_pos("jpXCZedGfVQAhg1opVcGW", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}

TEST(base58_decode_pos, handles_pos_jpXCZedGfVQjpXCZedGfVQ)
{
  test_decode_pos("jpXCZedGfVQjpXCZedGfVQ", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
}


// Invalid length


TEST(base58_decode_neg, handles_neg_1)
{
  test_decode_neg("1");
}

TEST(base58_decode_neg, handles_neg_z)
{
  test_decode_neg("z");
}

TEST(base58_decode_neg, handles_neg_1111)
{
  test_decode_neg("1111");
}

TEST(base58_decode_neg, handles_neg_zzzz)
{
  test_decode_neg("zzzz");
}

TEST(base58_decode_neg, handles_neg_11111111)
{
  test_decode_neg("11111111");
}

TEST(base58_decode_neg, handles_neg_zzzzzzzz)
{
  test_decode_neg("zzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789AB1)
{
  test_decode_neg("123456789AB1");
}

TEST(base58_decode_neg, handles_neg_123456789ABz)
{
  test_decode_neg("123456789ABz");
}

TEST(base58_decode_neg, handles_neg_123456789AB1111)
{
  test_decode_neg("123456789AB1111");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzz)
{
  test_decode_neg("123456789ABzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789AB11111111)
{
  test_decode_neg("123456789AB11111111");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzzzzzz)
{
  test_decode_neg("123456789ABzzzzzzzz");
}


// Overflow


TEST(base58_decode_neg, handles_neg_5R)
{
  test_decode_neg("5R");
}

TEST(base58_decode_neg, handles_neg_zz)
{
  test_decode_neg("zz");
}

TEST(base58_decode_neg, handles_neg_LUw)
{
  test_decode_neg("LUw");
}

TEST(base58_decode_neg, handles_neg_zzz)
{
  test_decode_neg("zzz");
}

TEST(base58_decode_neg, handles_neg_2UzHM)
{
  test_decode_neg("2UzHM");
}

TEST(base58_decode_neg, handles_neg_zzzzz)
{
  test_decode_neg("zzzzz");
}

TEST(base58_decode_neg, handles_neg_7YXq9H)
{
  test_decode_neg("7YXq9H");
}

TEST(base58_decode_neg, handles_neg_zzzzzz)
{
  test_decode_neg("zzzzzz");
}

TEST(base58_decode_neg, handles_neg_VtB5VXd)
{
  test_decode_neg("VtB5VXd");
}

TEST(base58_decode_neg, handles_neg_zzzzzzz)
{
  test_decode_neg("zzzzzzz");
}

TEST(base58_decode_neg, handles_neg_3CUsUpv9u)
{
  test_decode_neg("3CUsUpv9u");
}

TEST(base58_decode_neg, handles_neg_zzzzzzzzz)
{
  test_decode_neg("zzzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_Ahg1opVcGX)
{
  test_decode_neg("Ahg1opVcGX");
}

TEST(base58_decode_neg, handles_neg_zzzzzzzzzz)
{
  test_decode_neg("zzzzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_jpXCZedGfVR)
{
  test_decode_neg("jpXCZedGfVR");
}

TEST(base58_decode_neg, handles_neg_zzzzzzzzzzz)
{
  test_decode_neg("zzzzzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789AB5R)
{
  test_decode_neg("123456789AB5R");
}

TEST(base58_decode_neg, handles_neg_123456789ABzz)
{
  test_decode_neg("123456789ABzz");
}

TEST(base58_decode_neg, handles_neg_123456789ABLUw)
{
  test_decode_neg("123456789ABLUw");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzz)
{
  test_decode_neg("123456789ABzzz");
}

TEST(base58_decode_neg, handles_neg_123456789AB2UzHM)
{
  test_decode_neg("123456789AB2UzHM");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzzz)
{
  test_decode_neg("123456789ABzzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789AB7YXq9H)
{
  test_decode_neg("123456789AB7YXq9H");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzzzz)
{
  test_decode_neg("123456789ABzzzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789ABVtB5VXd)
{
  test_decode_neg("123456789ABVtB5VXd");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzzzzz)
{
  test_decode_neg("123456789ABzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789AB3CUsUpv9u)
{
  test_decode_neg("123456789AB3CUsUpv9u");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzzzzzzz)
{
  test_decode_neg("123456789ABzzzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789ABAhg1opVcGX)
{
  test_decode_neg("123456789ABAhg1opVcGX");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzzzzzzzz)
{
  test_decode_neg("123456789ABzzzzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_123456789ABjpXCZedGfVR)
{
  test_decode_neg("123456789ABjpXCZedGfVR");
}

TEST(base58_decode_neg, handles_neg_123456789ABzzzzzzzzzzz)
{
  test_decode_neg("123456789ABzzzzzzzzzzz");
}

TEST(base58_decode_neg, handles_neg_zzzzzzzzzzz11)
{
  test_decode_neg("zzzzzzzzzzz11");
}


// Invalid symbols


TEST(base58_decode_neg, handles_neg_10)
{
  test_decode_neg("10");
}

TEST(base58_decode_neg, handles_neg_11I)
{
  test_decode_neg("11I");
}

TEST(base58_decode_neg, handles_neg_11O11)
{
  test_decode_neg("11O11");
}

TEST(base58_decode_neg, handles_neg_11l111)
{
  test_decode_neg("11l111");
}

TEST(base58_decode_neg, handles_neg_11_11111111)
{
  test_decode_neg("11_11111111");
}

TEST(base58_decode_neg, handles_neg_1101111111111)
{
  test_decode_neg("1101111111111");
}

TEST(base58_decode_neg, handles_neg_11I11111111111111)
{
  test_decode_neg("11I11111111111111");
}

TEST(base58_decode_neg, handles_neg_11O1111111111111111111)
{
  test_decode_neg("11O1111111111111111111");
}

TEST(base58_decode_neg, handles_neg_1111111111110)
{
  test_decode_neg("1111111111110");
}

TEST(base58_decode_neg, handles_neg_111111111111l1111)
{
  test_decode_neg("111111111111l1111");
}

TEST(base58_decode_neg, handles_neg_111111111111_111111111)
{
  test_decode_neg("111111111111_111111111");
}

TEST(base58_encode_decode_addr, handles_21D35quxec71111111111111111111111111111111111111111111111111111111111111111111111111111117DCT1u)
{
  uint64_t tag = 6;
  std::string data = std::string("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  std::string address = "21D35quxec71111111111111111111111111111111111111111111111111111111111111111111111111111117DCT1u";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_2Aui6ejTFscjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVrFHqfP)
{
  uint64_t tag = 6;
  std::string data = std::string("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                                  sizeof("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF") - 1);
  std::string address = "2Aui6ejTFscjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVrFHqfP";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_1119XrkPuSmLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKVsvKKYw)
{
  uint64_t tag = 0;
  std::string data = std::string("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                                  sizeof("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF") - 1);
  std::string address = "1119XrkPuSmLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKjepg5hZAxffLzdHXgVgrZKVsvKKYw";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_111111111111111111111111111111111111111111111111111111111111111111111111111111111111111116QGnML)
{
  uint64_t tag = 0;
  std::string data = std::string( "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  std::string address = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111116QGnML";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83qvSEivPLYo1111111111111111111111111111111111111111111111111111111111111111111111111111112rSWj3)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = std::string( "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  sizeof("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") - 1);
  std::string address = "PuT7GAdgbA83qvSEivPLYo1111111111111111111111111111111111111111111111111111111111111111111111111111112rSWj3";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA841d7FXjswpJjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVms5VhB)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = std::string("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                                  sizeof("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF") - 1);
  std::string address = "PuT7GAdgbA841d7FXjswpJjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQjpXCZedGfVQVms5VhB";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA819VyyBLbs)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x11";
  std::string address = "PuT7GAdgbA819VyyBLbs";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA81efAiK31Hz)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x22\x22";
  std::string address = "PuT7GAdgbA81efAiK31Hz";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83sryEtDjvG4)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x33\x33\x33";
  std::string address = "PuT7GAdgbA83sryEtDjvG4";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83tWUuc6CSBJ3U)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x44\x44\x44\x44";
  std::string address = "PuT7GAdgbA83tWUuc6CSBJ3U";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83u9zaKrtFFs4fQ)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x55\x55\x55\x55\x55";
  std::string address = "PuT7GAdgbA83u9zaKrtFFs4fQ";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83uoWF3eanFs17rX7)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x66\x66\x66\x66\x66\x66";
  std::string address = "PuT7GAdgbA83uoWF3eanFs17rX7";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83vT1umSHMYJ3YST32)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x77\x77\x77\x77\x77\x77\x77";
  std::string address = "PuT7GAdgbA83vT1umSHMYJ3YST32";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83w6XaVDyvpoGTBJFBL)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x88\x88\x88\x88\x88\x88\x88\x88";
  std::string address = "PuT7GAdgbA83w6XaVDyvpoGTBJFBL";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_PuT7GAdgbA83wk3FD1gW7J2KVL4JYwB)
{
  uint64_t tag = 0x1122334455667788;
  std::string data = "\x99\x99\x99\x99\x99\x99\x99\x99\x99";
  std::string address = "PuT7GAdgbA83wk3FD1gW7J2KVL4JYwB";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_115ahhP)
{
  uint64_t tag = 0;
  std::string data = "";
  std::string address = "115ahhP";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_FQAC7o6)
{
  uint64_t tag = 0x7F;
  std::string data = "";
  std::string address = "FQAC7o6";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_26k6k8Zze)
{
  uint64_t tag = 0x80;
  std::string data = "";
  std::string address = "26k6k8Zze";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_3BzB5DBYF)
{
  uint64_t tag = 0xFF;
  std::string data = "";
  std::string address = "3BzB5DBYF";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_11efCaY6UjG65YFsC)
{
  uint64_t tag = 0;
  std::string data = "\x11\x22\x33\x44\x55\x66\x77";
  std::string address = "11efCaY6UjG65YFsC";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_encode_decode_addr, handles_21rhHRT48LN19e63n)
{
  uint64_t tag = 6;
  std::string data = "\x11\x22\x33\x44\x55\x66\x77";
  std::string address = "21rhHRT48LN19e63n";
  test_encode_decode_addr(tag, data, address);
}

TEST(base58_decode_addr_neg, decode_fails_due_overflow)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("zuT7GAdgbA819VwdWVDP", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_invalid_char_0)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("0uT7GAdgbA819VwdWVDP", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_invalid_char_I)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("0uT7GAdgbA819VwdWVDP", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_invalid_char_O)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("0uT7GAdgbA819VwdWVDP", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_invalid_char_l)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("luT7GAdgbA819VwdWVDP", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_invalid_lenght)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("PuT7GAdgbA819VwdWVD", tag, data));
}

TEST(base58_decode_addr_neg, handles_invalid_checksum)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("11efCaY6UjG7JrxuC", tag, data));
}

TEST(base58_decode_addr_neg, handles_non_correct_tag)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("jerj2e4mESo", tag, data)); // "jerj2e4mESo" == "\xFF\x00\xFF\xFF\x5A\xD9\xF1\x1C"
}

TEST(base58_decode_addr_neg, decode_fails_due_invalid_block_len_0)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("1", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_invalid_block_len_1)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("1111", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_address_too_short_0)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("11", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_address_too_short_1)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("111", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_address_too_short_2)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("11111", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_address_too_short_3)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("111111", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_address_too_short_4)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("999999", tag, data));
}

TEST(base58_decode_addr_neg, decode_fails_due_address_too_short_5)
{
  uint64_t tag;
  std::string data;
  ASSERT_FALSE(Base58::decode_addr("ZZZZZZ", tag, data));
}

namespace
{
  std::string test_serialized_keys = std::string("\xf7\x24\xbc\x5c\x6c\xfb\xb9\xd9\x76\x02\xc3\x00\x42\x3a\x2f\x28\x64\x18\x74\x51\x3a\x03\x57\x78\xa0\xc1\x77\x8d\x83\x32\x01\xe9\x22\x09\x39\x68\x9e\xdf\x1a\xbd\x5b\xc1\xd0\x31\xf7\x3e\xcd\x6c\x99\x3a\xdd\x66\xd6\x80\x88\x70\x45\x6a\xfe\xb8\xe7\xee\xb6\x8d",
                                      sizeof("\xf7\x24\xbc\x5c\x6c\xfb\xb9\xd9\x76\x02\xc3\x00\x42\x3a\x2f\x28\x64\x18\x74\x51\x3a\x03\x57\x78\xa0\xc1\x77\x8d\x83\x32\x01\xe9\x22\x09\x39\x68\x9e\xdf\x1a\xbd\x5b\xc1\xd0\x31\xf7\x3e\xcd\x6c\x99\x3a\xdd\x66\xd6\x80\x88\x70\x45\x6a\xfe\xb8\xe7\xee\xb6\x8d") - 1);
  std::string test_keys_addr_str = "2AaF4qEmER6dNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJzLdaKAYSLVh6e6jKnAuzj3bw1oGyAg811";
  const uint64_t TEST_PUBLIC_ADDRESS_BASE58_PREFIX = 6;
}

TEST(getAccountAddressAsStr, works_correctly)
{
  CryptoNote::AccountPublicAddress addr;

  ASSERT_NO_THROW(CryptoNote::loadFromBinary(addr, Common::asBinaryArray(test_serialized_keys)));
  std::string addr_str = CryptoNote::getAccountAddressAsStr(TEST_PUBLIC_ADDRESS_BASE58_PREFIX, addr);
  ASSERT_EQ(addr_str, test_keys_addr_str);
}

TEST(parseAccountAddressString, handles_valid_address)
{
  uint64_t prefix;
  CryptoNote::AccountPublicAddress addr;
  ASSERT_TRUE(CryptoNote::parseAccountAddressString(prefix, addr, test_keys_addr_str));
  ASSERT_EQ(TEST_PUBLIC_ADDRESS_BASE58_PREFIX, prefix);

  BinaryArray blob;
  ASSERT_NO_THROW(blob = CryptoNote::storeToBinary(addr));
  ASSERT_EQ(Common::asString(blob), test_serialized_keys);
}

TEST(parseAccountAddressString, fails_on_invalid_address_format)
{
  std::string addr_str = test_keys_addr_str;
  addr_str[0] = '0';

  uint64_t prefix;
  CryptoNote::AccountPublicAddress addr;
  ASSERT_FALSE(CryptoNote::parseAccountAddressString(prefix, addr, addr_str));
}

TEST(parseAccountAddressString, fails_on_invalid_address_prefix)
{
  std::string addr_str = Base58::encode_addr(0, test_serialized_keys);

  Logging::LoggerGroup logger;
  CryptoNote::Currency currency = CryptoNote::CurrencyBuilder(logger).currency();

  CryptoNote::AccountPublicAddress addr;
  
  ASSERT_FALSE(currency.parseAccountAddressString(addr_str, addr));
}

TEST(parseAccountAddressString, fails_on_invalid_address_content)
{
  std::string addr_str = Base58::encode_addr(TEST_PUBLIC_ADDRESS_BASE58_PREFIX, test_serialized_keys.substr(1));

  uint64_t prefix;
  CryptoNote::AccountPublicAddress addr;
  ASSERT_FALSE(CryptoNote::parseAccountAddressString(prefix, addr, addr_str));
}

TEST(parseAccountAddressString, fails_on_invalid_address_spend_key)
{
  std::string serialized_keys_copy = test_serialized_keys;
  serialized_keys_copy[0] = '\0';
  std::string addr_str = Base58::encode_addr(TEST_PUBLIC_ADDRESS_BASE58_PREFIX, serialized_keys_copy);

  uint64_t prefix;
  CryptoNote::AccountPublicAddress addr;
  ASSERT_FALSE(CryptoNote::parseAccountAddressString(prefix, addr, addr_str));
}

TEST(parseAccountAddressString, fails_on_invalid_address_view_key)
{
  std::string serialized_keys_copy = test_serialized_keys;
  serialized_keys_copy.back() = '\x01';
  std::string addr_str = Base58::encode_addr(TEST_PUBLIC_ADDRESS_BASE58_PREFIX, serialized_keys_copy);

  uint64_t prefix;
  CryptoNote::AccountPublicAddress addr;
  ASSERT_FALSE(CryptoNote::parseAccountAddressString(prefix, addr, addr_str));
}

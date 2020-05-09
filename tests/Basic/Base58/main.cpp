// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Common/Base58.h"
#include <iostream>

using namespace Tools;
using namespace Base58;

// encode()
TEST(Base58, 1)
{
  std::string data = "Hello";
  std::string encoded = encode(data);

  // values obtained from compiler
  ASSERT_EQ(7, encoded.size());
  ASSERT_EQ("9Ajdvzr", encoded);
}

// decode()
TEST(Base58, 2)
{
  std::string data = "Hello";
  std::string encoded = encode(data);

  // values obtained from compiler
  ASSERT_EQ(7, encoded.size());
  ASSERT_EQ("9Ajdvzr", encoded);

  std::string decoded;
  ASSERT_TRUE(decode(encoded, decoded));

  ASSERT_EQ("Hello", decoded);
}

// encode_addr()
TEST(Base58, 3)
{
  // I do not know what tag is used for
  uint64_t tag = 1;
  std::string data = "Hello";
  std::string encodedAddress = encode_addr(tag, data);

  ASSERT_EQ("1DSo7pPy9D7Hcb", encodedAddress);
}

// decode_addr()
TEST(Base58, 4)
{
  // I do not know what tag is used for
  uint64_t tag = 1;
  std::string str = "Hello";
  std::string encodedAddress = encode_addr(tag, str);

  ASSERT_EQ("1DSo7pPy9D7Hcb", encodedAddress);

  std::string decodedAddress;
  ASSERT_TRUE(decode_addr(encodedAddress, tag, decodedAddress));

  ASSERT_EQ("Hello", decodedAddress);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/Ipv4Address.h"

using namespace System;

// constructor
TEST(Ipv4Address, 1)
{
  uint32_t value = 0;
  Ipv4Address ipv4Address(value);
}

// constructor
TEST(Ipv4Address, 2)
{
  const std::string dottedDecimal = "123.123.123.123";
  Ipv4Address ipv4Address(dottedDecimal);
}

// operator!=()
TEST(Ipv4Address, 3)
{
  uint32_t value1 = 1;
  Ipv4Address ipv4Address1(value1);

  uint32_t value2 = 2;
  Ipv4Address ipv4Address2(value2);

  ASSERT_TRUE(ipv4Address1 != ipv4Address2);
}

// operator==()
TEST(Ipv4Address, 4)
{
  uint32_t value1 = 1;
  Ipv4Address ipv4Address1(value1);

  uint32_t value2 = 1;
  Ipv4Address ipv4Address2(value2);

  ASSERT_TRUE(ipv4Address1 == ipv4Address2);
}

// getValue()
TEST(Ipv4Address, 5)
{
  uint32_t value = 0;
  Ipv4Address ipv4Address(value);
  uint32_t valueRet = ipv4Address.getValue();
  ASSERT_EQ(value, valueRet);
}

// isLoopback()
// checks if first part of ip address is 127
TEST(Ipv4Address, 6)
{
  std::string str = "127.0.0.0";
  Ipv4Address ipv4Address(str);
  ASSERT_TRUE(ipv4Address.isLoopback());
}

// isPrivate()
TEST(Ipv4Address, 7)
{
  std::string str = "10.0.0.0";
  Ipv4Address ipv4Address(str);
  ASSERT_TRUE(ipv4Address.isPrivate());
}

// toDottedDecimal()
TEST(Ipv4Address, 8)
{
  uint32_t value = 0;
  Ipv4Address ipv4Address(value);
  std::string strRet = ipv4Address.toDottedDecimal();
  ASSERT_EQ("0.0.0.0", strRet);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
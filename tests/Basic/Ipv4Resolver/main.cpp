// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/Ipv4Resolver.h"
#include "System/Dispatcher.h"
#include "System/Ipv4Address.h"

using namespace System;

// constructor
TEST(Ipv4Resolver, 1)
{
  Ipv4Resolver();
}

// constructor
TEST(Ipv4Resolver, 2)
{
  Dispatcher dispatcher;
  Ipv4Resolver ipv4Resolver(dispatcher);
}

// constructor
TEST(Ipv4Resolver, 3)
{
  Ipv4Resolver ipv4Resolver1;
  Ipv4Resolver ipv4Resolver2(std::move(ipv4Resolver1));
}

// operator=()
TEST(Ipv4Resolver, 4)
{
  Ipv4Resolver ipv4Resolver1;
  Ipv4Resolver ipv4Resolver2 = std::move(ipv4Resolver1);
}

// resolve()
TEST(Ipv4Resolver, 5)
{
  Dispatcher dispatcher;
  Ipv4Resolver ipv4Resolver(dispatcher);
  std::string host = "0.0.0.0";
  Ipv4Address address = ipv4Resolver.resolve(host);
  ASSERT_EQ(Ipv4Address("0.0.0.0"), address);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
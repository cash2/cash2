// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/TcpStream.h"
#include "System/TcpConnection.h"

using namespace System;

// constructor
TEST(TcpStream, 1)
{
  TcpConnection connection;
  TcpStreambuf buf(connection);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
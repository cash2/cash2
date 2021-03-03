// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/OperationTimeout.h"

using namespace System;

// constructor
TEST(OperationTimeout, 1)
{
  Dispatcher dispatcher;
  int i = 0;
  std::chrono::nanoseconds timeout = std::chrono::nanoseconds{1000};
  OperationTimeout<int>(dispatcher, i, timeout);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
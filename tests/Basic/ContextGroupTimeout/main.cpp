// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/ContextGroupTimeout.h"
#include "System/ContextGroup.h"
#include "System/Dispatcher.h"

using namespace System;

// constructor
TEST(ContextGroupTimeout, 1)
{
  Dispatcher dispatcher;
  ContextGroup contextGroup(dispatcher);
  std::chrono::nanoseconds time = std::chrono::nanoseconds{1000};
  ContextGroupTimeout(dispatcher, contextGroup, time);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
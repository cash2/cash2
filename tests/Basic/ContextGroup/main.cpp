// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/ContextGroup.h"
#include "System/Dispatcher.h"

using namespace System;

// constructor
TEST(ContextGroup, 1)
{
  Dispatcher dispatcher;
  ContextGroup contextGroup(dispatcher);
}

// constructor
TEST(ContextGroup, 2)
{
  Dispatcher dispatcher;
  ContextGroup contextGroup1(dispatcher);
  ContextGroup contextGroup2(std::move(contextGroup1));
}

// constructor
TEST(ContextGroup, 3)
{
  Dispatcher dispatcher;
  ContextGroup contextGroup1(dispatcher);
  ContextGroup contextGroup2 = std::move(contextGroup1);
}

// interrupt()
TEST(ContextGroup, 4)
{
  Dispatcher dispatcher;
  ContextGroup contextGroup(dispatcher);
  ASSERT_NO_THROW(contextGroup.interrupt());
}

// spawn()
TEST(ContextGroup, 5)
{
  Dispatcher dispatcher;
  ContextGroup contextGroup(dispatcher);
  ASSERT_NO_THROW(contextGroup.spawn([&] { return true; }));
}

// wait()
TEST(ContextGroup, 6)
{
  Dispatcher dispatcher;
  ContextGroup contextGroup(dispatcher);
  ASSERT_NO_THROW(contextGroup.wait());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
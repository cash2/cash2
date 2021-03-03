// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/Context.h"
#include "System/Dispatcher.h"
#include <iostream>

using namespace System;

/*

My Notes

class Context
public
  Context()
  get()
  interrupt()
  wait()

*/

// constructor
TEST(Context, 1)
{
  Dispatcher dispatcher;
  Context<std::string>(dispatcher, [&]() { return "Hello World"; });
}

// get()
TEST(Context, 2)
{
  Dispatcher dispatcher;
  Context<std::string> context(dispatcher, [&]() { return "Hello World"; });
  std::string str = context.get();
  ASSERT_EQ("Hello World", str);
}

// interrupt()
TEST(Context, 3)
{
  Dispatcher dispatcher;
  Context<std::string> context(dispatcher, [&]() { return "Hello World"; });
  ASSERT_NO_THROW(context.interrupt());
}

// wait()
TEST(Context, 4)
{
  Dispatcher dispatcher;
  Context<std::string> context(dispatcher, [&]() { return "Hello World"; });
  ASSERT_NO_THROW(context.wait());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
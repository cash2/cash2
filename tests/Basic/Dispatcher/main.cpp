// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/Dispatcher.h"
#include "System/Context.h"

/*

My Notes

*Dispatcher()
*clear()
*dispatch()
*getCurrentContext()
*interrupt()
*interrupted()
*pushContext()
*remoteSpawn()
*yield()
*getEpoll()
*getReusableContext()
pushReusableContext()
*getTimer()
*pushTimer()

*/

using namespace System;

// constructor
TEST(Dispatcher, 1)
{
  Dispatcher dispatcher;
}

// clear()
TEST(Dispatcher, 2)
{
  Dispatcher dispatcher;
  ASSERT_NO_THROW(dispatcher.clear());
}

// dispatch()
TEST(Dispatcher, 3)
{
  Dispatcher dispatcher;
  dispatcher.pushContext(dispatcher.getCurrentContext()); // needed so that test will end
  dispatcher.dispatch();
}

// getCurrentContext()
TEST(Dispatcher, 4)
{
  Dispatcher dispatcher;
  NativeContext* n = dispatcher.getCurrentContext();
}

// interrupt()
TEST(Dispatcher, 5)
{
  Dispatcher dispatcher;
  ASSERT_NO_THROW(dispatcher.interrupt());
}

// interrupt()
TEST(Dispatcher, 6)
{
  Dispatcher dispatcher;
  NativeContext context;
  ASSERT_NO_THROW(dispatcher.interrupt(&context));
}

// interrupted()
TEST(Dispatcher, 7)
{
  Dispatcher dispatcher;
  ASSERT_NO_THROW(dispatcher.interrupt());
  ASSERT_TRUE(dispatcher.interrupted());
}

// pushContext()
TEST(Dispatcher, 8)
{
  Dispatcher dispatcher;
  NativeContext* context = dispatcher.getCurrentContext();
  dispatcher.pushContext(context);
  dispatcher.dispatch(); // needed so that assertion does not fail
}

// remoteSpawn()
TEST(Dispatcher, 9)
{
  Dispatcher dispatcher;
  ASSERT_NO_THROW(dispatcher.remoteSpawn([&](){ return true; }));
}

// yield()
TEST(Dispatcher, 10)
{
  Dispatcher dispatcher;
  ASSERT_NO_THROW(dispatcher.yield());
}

// getEpoll()
TEST(Dispatcher, 11)
{
  Dispatcher dispatcher;
  ASSERT_EQ(3, dispatcher.getEpoll());
}

// getReusableContext()
TEST(Dispatcher, 12)
{
  Dispatcher dispatcher;
  dispatcher.getReusableContext();
}

// getTimer()
TEST(Dispatcher, 13)
{
  Dispatcher dispatcher;
  ASSERT_EQ(5, dispatcher.getTimer());
}

// pushTimer()
TEST(Dispatcher, 14)
{
  Dispatcher dispatcher;
  ASSERT_NO_THROW(dispatcher.pushTimer(1));
  ASSERT_EQ(1, dispatcher.getTimer());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
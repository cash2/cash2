// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/EventLock.h"
#include "System/Dispatcher.h"
#include "System/Event.h"
#include "System/Context.h"

using namespace System;

// constructor
TEST(EventLock, 1)
{
  Dispatcher dispatcher;
  Event event(dispatcher);
  bool done = false;
  Context<> context(dispatcher, [&]() {
    EventLock lock(event);
    done = true;
  });

  ASSERT_FALSE(done);
  event.set();
  dispatcher.yield();
  ASSERT_TRUE(done);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
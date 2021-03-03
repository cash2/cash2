// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/Event.h"
#include "System/Dispatcher.h"
#include "System/Context.h"

using namespace System;

// constructor
TEST(Event, 1)
{
  Event();
}

// constructor
TEST(Event, 2)
{
  Dispatcher dispatcher;
  Event event(dispatcher);
}

// constructor
TEST(Event, 3)
{
  Dispatcher dispatcher;
  Event event1(dispatcher);
  Event event2(std::move(event1));
}

// constructor
TEST(Event, 4)
{
  Dispatcher dispatcher;
  Event event1(dispatcher);
  Event event2 = std::move(event1);
}

// set()
TEST(Event, 5)
{
  Dispatcher dispatcher;
  Event event(dispatcher);
  ASSERT_NO_THROW(event.set());
}

// get()
TEST(Event, 6)
{
  Dispatcher dispatcher;
  Event event(dispatcher);
  ASSERT_FALSE(event.get());

  event.set();

  ASSERT_TRUE(event.get());
}

// clear()
TEST(Event, 7)
{
  Dispatcher dispatcher;
  Event event(dispatcher);
  ASSERT_NO_THROW(event.clear());
}

// wait()
TEST(Event, 8)
{
  Dispatcher dispatcher;
  Event event(dispatcher);
  bool interrupted = false;
  Context<> context(dispatcher, [&] {
    try {
      event.wait();
    } catch (InterruptedException&) {
      interrupted = true;
    }
  });

  context.interrupt();
  context.get();
  ASSERT_TRUE(interrupted);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/ObserverManager.h>
#include <gtest/gtest.h>
#include <iostream>

/*

MyNotes

class ObserverManager
public
  add()
  remove()
  clear()
  notify()

*/

using namespace Tools;

class MyInt
{
public:
  MyInt(int i) : m_int(i) {};

  void myFunction()
  {
    std::cout << "Hello World" << std::endl;
  }

private:
  int m_int;
};

// constructor
TEST(ObserverManager, 1)
{
  ObserverManager<int>();
}

// add()
TEST(ObserverManager, 2)
{
  ObserverManager<int> manager;

  int a, b, c, d, e;

  ASSERT_TRUE(manager.add(&a));
  ASSERT_TRUE(manager.add(&b));
  ASSERT_TRUE(manager.add(&c));
  ASSERT_TRUE(manager.add(&d));
  ASSERT_TRUE(manager.add(&e));
}

// remove()
TEST(ObserverManager, 3)
{
  ObserverManager<int> manager;

  int a, b, c, d, e;

  ASSERT_TRUE(manager.add(&a));
  ASSERT_TRUE(manager.add(&b));
  ASSERT_TRUE(manager.add(&c));
  ASSERT_TRUE(manager.add(&d));
  ASSERT_TRUE(manager.add(&e));

  ASSERT_TRUE(manager.remove(&a));
  ASSERT_TRUE(manager.remove(&b));
  ASSERT_TRUE(manager.remove(&c));
  ASSERT_TRUE(manager.remove(&d));
  ASSERT_TRUE(manager.remove(&e));
}

// clear()
TEST(ObserverManager, 4)
{
  ObserverManager<int> manager;

  int a, b, c, d, e;

  ASSERT_TRUE(manager.add(&a));
  ASSERT_TRUE(manager.add(&b));
  ASSERT_TRUE(manager.add(&c));
  ASSERT_TRUE(manager.add(&d));
  ASSERT_TRUE(manager.add(&e));

  manager.clear();
}

// notify()
TEST(ObserverManager, 5)
{
  ObserverManager<MyInt> manager;

  MyInt myInt1(1);
  ASSERT_TRUE(manager.add(&myInt1));

  MyInt myInt2(2);
  ASSERT_TRUE(manager.add(&myInt2));

  MyInt myInt3(3);
  ASSERT_TRUE(manager.add(&myInt3));

  manager.notify(&MyInt::myFunction);
}
























int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
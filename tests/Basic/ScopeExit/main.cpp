// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <Common/ScopeExit.h>
#include <gtest/gtest.h>
#include <iostream>

/*

MyNotes

class ScopeExit
public
  ScopeExit()
  cancel()

*/

using namespace Tools;

// constructor
TEST(ScopeExit, 1)
{
  std::function<void()> handler = [&](){ std::cout << "Hello World" << std::endl; };
  ScopeExit(std::move(handler));
}

// cancel()
TEST(ScopeExit, 2)
{
  std::function<void()> handler = [&](){ std::cout << "Hello World" << std::endl; };
  ScopeExit scopeExit(std::move(handler));

  scopeExit.cancel(); // "Hello World" is not printed
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
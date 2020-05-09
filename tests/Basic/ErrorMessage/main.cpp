// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "System/ErrorMessage.h"

using namespace System;

// lastErrorMessage
TEST(ErrorMessage, 1)
{
  std::string error = lastErrorMessage();
  ASSERT_EQ("result=0, Success", error);
}

// errorMessage
TEST(ErrorMessage, 2)
{
  ASSERT_EQ("result=0, Success", errorMessage(0));
  ASSERT_EQ("result=1, Operation not permitted", errorMessage(1));
  ASSERT_EQ("result=2, No such file or directory", errorMessage(2));
  ASSERT_EQ("result=3, No such process", errorMessage(3));
  ASSERT_EQ("result=4, Interrupted system call", errorMessage(4));
  ASSERT_EQ("result=5, Input/output error", errorMessage(5));
  ASSERT_EQ("result=6, No such device or address", errorMessage(6));
  ASSERT_EQ("result=7, Argument list too long", errorMessage(7));
  ASSERT_EQ("result=8, Exec format error", errorMessage(8));
  ASSERT_EQ("result=9, Bad file descriptor", errorMessage(9));
  ASSERT_EQ("result=10, No child processes", errorMessage(10));
  ASSERT_EQ("result=11, Resource temporarily unavailable", errorMessage(11));
  ASSERT_EQ("result=12, Cannot allocate memory", errorMessage(12));
  ASSERT_EQ("result=13, Permission denied", errorMessage(13));
  ASSERT_EQ("result=14, Bad address", errorMessage(14));
  ASSERT_EQ("result=15, Block device required", errorMessage(15));
  ASSERT_EQ("result=16, Device or resource busy", errorMessage(16));
  ASSERT_EQ("result=17, File exists", errorMessage(17));
  ASSERT_EQ("result=18, Invalid cross-device link", errorMessage(18));
  ASSERT_EQ("result=19, No such device", errorMessage(19));
  ASSERT_EQ("result=20, Not a directory", errorMessage(20));
  ASSERT_EQ("result=100, Network is down", errorMessage(100));
  ASSERT_EQ("result=133, Memory page has hardware error", errorMessage(133));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
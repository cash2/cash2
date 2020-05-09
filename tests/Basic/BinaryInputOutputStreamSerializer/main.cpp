// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gtest/gtest.h"
#include "Serialization/BinaryInputStreamSerializer.h"
#include "Serialization/BinaryOutputStreamSerializer.h"
#include "Common/StdInputStream.h"
#include "Common/StdOutputStream.h"

/*

My Notes

class BinaryOutputStreamSerializer
public
  BinaryOutputStreamSerializer()
  type()
  beginObject()
  endObject()
  beginArray()
  endArray()
  operator()(uint8_t)
  operator()(int16_t)
  operator()(uint16_t)
  operator()(int32_t)
  operator()(uint32_t)
  operator()(int64_t)
  operator()(uint64_t)
  operator()(bool)
  operator()(std::string)
  binary()
  binary()

*/

using namespace Common;
using namespace CryptoNote;

// constructor
TEST(BinaryInputStreamSerializer, 1)
{
  std::stringstream stringStream;
  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer serializer(stdInputStream);
}

// type()
TEST(BinaryInputStreamSerializer, 2)
{
  std::stringstream stringStream;
  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer serializer(stdInputStream);

  ISerializer::SerializerType type = serializer.type();
  ASSERT_EQ(ISerializer::SerializerType::INPUT, type);
}

// operator()(uint8_t)
TEST(BinaryInputStreamSerializer, 3)
{
  std::stringstream stringStream;
  
  uint8_t out = 255; // 1111 1111

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  outputSerializer(out, "randomString");
  
  uint8_t in = 0;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  
  inputSerializer(in, "randomString");

  ASSERT_EQ(255, in);
}

// operator()(int16_t)
TEST(BinaryInputStreamSerializer, 4)
{
  std::stringstream stringStream;
  
  int16_t out = 32767; // 0111 1111 1111 1111

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  outputSerializer(out, "randomString");
  
  int16_t in = 0;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  
  inputSerializer(in, "randomString");

  ASSERT_EQ(32767, in);
}

// operator()(uint16_t)
TEST(BinaryInputStreamSerializer, 5)
{
  std::stringstream stringStream;
  
  uint16_t out = 65535; // 1111 1111 1111 1111

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  outputSerializer(out, "randomString");
  
  uint16_t in = 0;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  
  inputSerializer(in, "randomString");

  ASSERT_EQ(65535, in);
}

// operator()(int32_t)
TEST(BinaryInputStreamSerializer, 6)
{
  std::stringstream stringStream;
  
  int32_t out = 2147483647; // 0111 1111 1111 1111 1111 1111 1111 1111

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  outputSerializer(out, "randomString");
  
  int32_t in = 0;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  
  inputSerializer(in, "randomString");

  ASSERT_EQ(2147483647, in);
}

// operator()(uint32_t)
TEST(BinaryInputStreamSerializer, 7)
{
  std::stringstream stringStream;
  
  uint32_t out = 4294967295; // 1111 1111 1111 1111 1111 1111 1111 1111

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  outputSerializer(out, "randomString");
  
  uint32_t in = 0;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  
  inputSerializer(in, "randomString");

  ASSERT_EQ(4294967295, in);
}

// operator()(int64_t)
TEST(BinaryInputStreamSerializer, 8)
{
  std::stringstream stringStream;
  
  int64_t out = 9223372036854775807; // 0111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  outputSerializer(out, "randomString");
  
  int64_t in = 0;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  
  inputSerializer(in, "randomString");

  ASSERT_EQ(9223372036854775807, in);
}

// operator()(uint64_t)
TEST(BinaryInputStreamSerializer, 9)
{
  std::stringstream stringStream;
  
  uint64_t out = 18446744073709551615U; // 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  outputSerializer(out, "randomString");
  
  uint64_t in = 0;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  
  inputSerializer(in, "randomString");

  ASSERT_EQ(18446744073709551615U, in);
}

// operator()(bool)
TEST(BinaryInputStreamSerializer, 10)
{
  std::stringstream stringStream;
  
  bool out = true;

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  ASSERT_TRUE(outputSerializer(out, "randomString"));
  
  bool in = false;

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  ASSERT_TRUE(inputSerializer(in, "randomString"));

  ASSERT_EQ(true, in);
}

// operator()(string)
TEST(BinaryInputStreamSerializer, 11)
{
  std::stringstream stringStream;
  
  std::string out = "Hello World";

  StdOutputStream stdOutputStream(stringStream);
  BinaryOutputStreamSerializer outputSerializer(stdOutputStream);
  ASSERT_TRUE(outputSerializer(out, "randomString"));
  
  std::string in = "";

  StdInputStream stdInputStream(stringStream);
  BinaryInputStreamSerializer inputSerializer(stdInputStream);
  ASSERT_TRUE(inputSerializer(in, "randomString"));

  ASSERT_EQ("Hello World", in);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Common/PathTools.h"

/*

MyNotes

NativePathToGeneric()
GetPathDirectory()
GetPathFilename()
SplitPath()
CombinePath()
GetExtension()
RemoveExtension()
ReplaceExtenstion()
HasParentPath()

*/

using namespace Common;

// NativePathToGeneric()
TEST(PathTools, 1)
{
  std::string nativePath = "/Hello/World/helloWorld.cpp";
  std::string genericPath = NativePathToGeneric(nativePath);
  ASSERT_EQ("/Hello/World/helloWorld.cpp", genericPath);
}

// GetPathDirectory()
TEST(PathTools, 2)
{
  std::string path = "/Hello/World/helloWorld.cpp";
  std::string directory = GetPathDirectory(path);
  ASSERT_EQ("/Hello/World", directory);
}

// GetPathFilename()
TEST(PathTools, 3)
{
  std::string path = "/Hello/World/helloWorld.cpp";
  std::string filename = GetPathFilename(path);
  ASSERT_EQ("helloWorld.cpp", filename);
}

// SplitPath()
TEST(PathTools, 4)
{
  std::string path = "/Hello/World/helloWorld.cpp";
  std::string directory;
  std::string filename;
  SplitPath(path, directory, filename);

  ASSERT_EQ("/Hello/World", directory);
  ASSERT_EQ("helloWorld.cpp", filename);
}

// CombinePath()
TEST(PathTools, 5)
{
  std::string path1 = "Hello/World";
  std::string path2 = "My/Name/Is";
  std::string combined = CombinePath(path1, path2);
  ASSERT_EQ("Hello/World/My/Name/Is", combined);
}

// GetExtension()
TEST(PathTools, 6)
{
  std::string path = "/Hello/World/helloWorld.cpp";
  std::string extension = GetExtension(path);
  ASSERT_EQ(".cpp", extension);
}

// RemoveExtension()
TEST(PathTools, 7)
{
  std::string path = "/Hello/World/helloWorld.cpp";
  std::string result = RemoveExtension(path);
  ASSERT_EQ("/Hello/World/helloWorld", result);
}

// ReplaceExtenstion()
TEST(PathTools, 8)
{
  const std::string path = "/Hello/World/helloWorld.cpp";
  const std::string extension = ".abc";
  std::string result = ReplaceExtenstion(path, extension);
  ASSERT_EQ("/Hello/World/helloWorld.abc", result);
}

// HasParentPath()
TEST(PathTools, 9)
{
  std::string path = "/Hello/World/helloWorld.cpp";
  ASSERT_TRUE(HasParentPath(path));

  path = "helloWorld.cpp";
  ASSERT_FALSE(HasParentPath(path));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
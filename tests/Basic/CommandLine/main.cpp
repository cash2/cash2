// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Common/CommandLine.h"

/*

My Notes

make_semantic()
make_semantic()
make_semantic()
make_semantic()
add_arg()
add_arg()
parse_command_line()
handle_error_helper()
has_arg()
get_arg()
has_arg()

*/

using namespace command_line;

// make_semantic()
TEST(CommandLine, 1)
{
  arg_descriptor<int, true> arg;
  arg.name = "myName";
  arg.description = "myDescription";

  boost::program_options::typed_value<int, char>* programOptions = make_semantic(arg);
}

// make_semantic()
TEST(CommandLine, 2)
{
  arg_descriptor<int, false> arg;
  arg.name = "myName";
  arg.description = "myDescription";
  arg.default_value = 0;
  arg.not_use_default = false;

  boost::program_options::typed_value<int, char>* programOptions = make_semantic(arg);
}

// make_semantic()
TEST(CommandLine, 3)
{
  arg_descriptor<int, false> arg;
  arg.name = "myName";
  arg.description = "myDescription";
  arg.default_value = 0;
  arg.not_use_default = false;

  int def = 5;
  boost::program_options::typed_value<int, char>* programOptions = make_semantic(arg, def);
}

// make_semantic()
TEST(CommandLine, 4)
{
  arg_descriptor<std::vector<int>, false> arg;
  arg.name = "myName";
  arg.description = "myDescription";

  int def = 5;
  boost::program_options::typed_value<std::vector<int>, char>* programOptions = make_semantic(arg);
}

// add_arg()
TEST(CommandLine, 5)
{
  boost::program_options::options_description description;

  const bool required = true;
  arg_descriptor<int, required> arg;
  arg.name = "myName";
  arg.description = "myDescription";

  add_arg(description, arg);
}

// add_arg()
TEST(CommandLine, 6)
{
  boost::program_options::options_description description;

  arg_descriptor<int, false> arg;
  arg.name = "myName";
  arg.description = "myDescription";
  arg.default_value = 0;
  arg.not_use_default = false;

  int def = 5;

  add_arg(description, arg, def);
}

// parse_command_line()
TEST(CommandLine, 7)
{
  int argc = 1;
  const char* const argv[] = {"Hello"};
  boost::program_options::options_description description;
  bool allow_unregistered = false;

  boost::program_options::basic_parsed_options<char> options = parse_command_line(argc, argv, description, allow_unregistered);
}

// handle_error_helper()
TEST(CommandLine, 8)
{
  boost::program_options::options_description description;

  ASSERT_TRUE(handle_error_helper(description, [&]() {return true;}));
}

// has_arg()
TEST(CommandLine, 9)
{
  boost::program_options::variables_map vm;

  arg_descriptor<int, false> arg;
  arg.name = "myName";
  arg.description = "myDescription";
  arg.default_value = 0;
  arg.not_use_default = false;
  
  ASSERT_FALSE(has_arg(vm, arg));

  vm.insert(std::make_pair("myName", boost::program_options::variable_value("myDescription", false)));

  ASSERT_TRUE(has_arg(vm, arg));
}

// has_arg()
TEST(CommandLine, 10)
{
  boost::program_options::variables_map vm;

  arg_descriptor<bool, false> arg;
  arg.name = "myName";
  arg.description = "myDescription";
  arg.default_value = false;
  arg.not_use_default = false;

  vm.insert(std::make_pair("myName", boost::program_options::variable_value(true, false)));

  bool hasArg = has_arg<bool, false>(vm, arg);
  ASSERT_TRUE(hasArg);
}

// get_arg()
TEST(CommandLine, 11)
{
  boost::program_options::variables_map vm;

  vm.insert(std::make_pair("myName", boost::program_options::variable_value(12345, false)));
  
  arg_descriptor<int, false> arg;
  arg.name = "myName";
  arg.description = "myDescription";
  arg.default_value = 0;
  arg.not_use_default = false;

  int argValue = get_arg(vm, arg);

  ASSERT_EQ(12345, argValue);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

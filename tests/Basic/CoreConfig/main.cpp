// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// SKIP FOR NOW - PAUL

#include "gtest/gtest.h"

#include "CryptoNoteCore/CoreConfig.h"
#include "Common/CommandLine.h"
#include <string>

using namespace CryptoNote;

/*

My Notes

class CoreConfig {

public
  CoreConfig()

  initOptions()
  init()

  std::string configFolder
  bool configFolderDefaulted = true
}

command_line::arg_data_dir.name = 'data-dir'

*/

uint32_t loopCount = 100;

// CoreConfig()
TEST(coreConfig, 1)
{
  CoreConfig coreConfig;

  ASSERT_NE(coreConfig.configFolder, "");

  ASSERT_TRUE(coreConfig.configFolderDefaulted);
}

// init()
TEST(coreConfig, 2)
{
  CoreConfig coreConfig;

  boost::program_options::variables_map options;

  coreConfig.init(options);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
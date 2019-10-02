// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/program_options.hpp>

namespace CryptoNote {

class DaemonConfigurationOptions {
public:

  DaemonConfigurationOptions();

  static void initOptions(boost::program_options::options_description& desc);
  void init(const boost::program_options::variables_map& options);

  std::string configFile;
  std::string dataDirectory;
  bool help;
  std::string logFile;
  uint32_t logLevel;
  bool noConsole;
  bool osVersion;
  bool printGenesisTransaction;
  bool testnet;
};

}
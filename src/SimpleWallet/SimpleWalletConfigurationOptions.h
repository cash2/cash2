// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/program_options.hpp>

namespace CryptoNote {

class SimpleWalletConfigurationOptions {
public:

  SimpleWalletConfigurationOptions();

  void initOptions(boost::program_options::options_description& optionsDescription);
  void init(const boost::program_options::variables_map& options);
  void printHelp(boost::program_options::options_description& optionsDescription);
  void printVersion();

  std::string daemonAddress;
  std::string daemonHost;
  uint16_t daemonPort;
  bool help;
  uint32_t logLevel;
  bool testnet;
  bool version;
};

}
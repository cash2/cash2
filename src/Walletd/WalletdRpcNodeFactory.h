// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "INode.h"

#include <string>

namespace Walletd {

class WalletdRpcNodeFactory {
public:
  static CryptoNote::INode* createNode(const std::string& daemonAddress, uint16_t daemonPort);
  static CryptoNote::INode* createNodeStub();
private:
  WalletdRpcNodeFactory();
  ~WalletdRpcNodeFactory();

  CryptoNote::INode* getNode(const std::string& daemonAddress, uint16_t daemonPort);

  static WalletdRpcNodeFactory factory;
};

} //namespace Walletd

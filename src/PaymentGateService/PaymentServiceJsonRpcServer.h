// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <unordered_map>

#include "Common/JsonValue.h"
#include "JsonRpcServer/JsonRpcServer.h"
#include "PaymentServiceJsonRpcMessages.h"
#include "Serialization/JsonInputValueSerializer.h"
#include "Serialization/JsonOutputStreamSerializer.h"
#include "WalletdRpcCommands.h"

namespace PaymentService {

class PaymentServiceJsonRpcServer : public CryptoNote::JsonRpcServer {

public :

  PaymentServiceJsonRpcServer(System::Dispatcher& sys, System::Event& stopEvent, WalletService& service, Logging::ILogger& loggerGroup, std::string rpcConfigurationPassword);
  PaymentServiceJsonRpcServer(const PaymentServiceJsonRpcServer&) = delete;

private :

  bool getMethod(const Common::JsonValue& request, Common::JsonValue& response, std::string& method);
  virtual void processJsonRpcRequest(const Common::JsonValue& request, Common::JsonValue& response) override;
  bool validateRpcPassword(const Common::JsonValue& request, Common::JsonValue& response);
  
  Logging::LoggerRef logger;
  WalletdRpcCommands m_walletdRpcCommands;

};

} // end namespace PaymentService

// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <system_error>
#include <unordered_map>

#include "Common/JsonValue.h"
#include "HTTP/HttpRequest.h"
#include "HTTP/HttpResponse.h"
#include "Logging/ILogger.h"
#include "Rpc/HttpServer.h"
#include "System/Dispatcher.h"
#include "System/Event.h"
#include "System/TcpConnection.h"
#include "WalletdRpcCommands.h"

namespace PaymentService {

class WalletdRpcServer : CryptoNote::HttpServer {

public :

  WalletdRpcServer(System::Dispatcher& dispatcher, System::Event& stopEvent, WalletService& service, Logging::ILogger& loggerGroup, std::string rpcConfigurationPassword);
  WalletdRpcServer(const WalletdRpcServer&) = delete;

  void start(const std::string& bindAddress, uint16_t bindPort);

private :

  static void fillJsonResponse(const Common::JsonValue& value, Common::JsonValue& response);
  bool getMethod(const Common::JsonValue& request, Common::JsonValue& response, std::string& method);
  std::string getRpcConfigurationPassword();
  static void makeErrorResponse(const std::error_code& ec, Common::JsonValue& response);
  static void makeGenericErrorReponse(Common::JsonValue& response, const char* what, int errorCode = -32001);
  static void makeIncorrectRpcPasswordResponse(Common::JsonValue& response);
  static void makeInvalidRpcPasswordResponse(Common::JsonValue& response);
  static void makeJsonParsingErrorResponse(Common::JsonValue& response);
  static void makeMethodNotFoundResponse(Common::JsonValue& response);
  static void makeMissingRpcPasswordKeyResponse(Common::JsonValue& response);
  void processJsonRpcRequest(const Common::JsonValue& request, Common::JsonValue& response);
  virtual void processRequest(const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response) override;
  bool validateRpcPassword(const Common::JsonValue& request, Common::JsonValue& response);
  
  Logging::LoggerRef m_logger;
  WalletdRpcCommands m_walletdRpcCommands;
  System::Dispatcher& m_dispatcher;
  System::Event& m_stopEvent;
  std::string m_rpcConfigurationPassword;

};

} // end namespace PaymentService

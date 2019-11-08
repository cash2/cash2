// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletdRpcRequestResponseObjects.h"
#include "WalletdRpcServer.h"
#include "Serialization/JsonInputValueSerializer.h"
#include "Serialization/JsonOutputStreamSerializer.h"

namespace Walletd {

// Walletd RPC Commands
//
// create_address
// create_addresses
// create_delayed_transaction
// delete_address
// delete_delayed_transaction
// get_addresses
// get_addresses_count
// get_balance
// get_block_hashes
// get_delayed_transaction_hashes
// get_spend_private_key
// get_spend_private_keys
// get_status
// get_transaction
// get_transaction_hashes
// get_transactions
// get_unconfirmed_transaction_hashes
// get_view_private_key
// reset
// save
// send_delayed_transaction
// send_transaction
// validate_address


// Public functions


WalletdRpcServer::WalletdRpcServer(System::Dispatcher& dispatcher, System::Event& stopEvent, WalletHelper& walletHelper, Logging::ILogger& loggerGroup, std::string rpcConfigurationPassword) :
  HttpServer(dispatcher, loggerGroup), 
  m_dispatcher(dispatcher),
  m_logger(loggerGroup, "WalletdRpcServer"),
  m_stopEvent(stopEvent),
  m_rpcConfigurationPassword(rpcConfigurationPassword),
  m_walletdRpcCommands(walletHelper) {
}

void WalletdRpcServer::start(const std::string& bindAddress, uint16_t bindPort)
{
  HttpServer::start(bindAddress, bindPort);
  m_stopEvent.wait();
  HttpServer::stop();
}


// Private functions


void WalletdRpcServer::fillJsonResponse(const Common::JsonValue& value, Common::JsonValue& response)
{
  response.insert("result", value);
}

bool WalletdRpcServer::getMethod(const Common::JsonValue& request, Common::JsonValue& response, std::string& method)
{
  if (!request.contains("method")) {
    m_logger(Logging::WARNING) << "Field \"method\" is not found in json request : " << request;
    makeGenericErrorReponse(response, "Invalid Request", -3600);
    return false;
  }

  if (!request("method").isString()) {
    m_logger(Logging::WARNING) << "Field \"method\" is not a string type: " << request;
    makeGenericErrorReponse(response, "Invalid Request", -3600);
    return false;
  }

  method = request("method").getString();

  return true;
}

std::string WalletdRpcServer::getRpcConfigurationPassword()
{
  return m_rpcConfigurationPassword;
}

void WalletdRpcServer::makeErrorResponse(const std::error_code& ec, Common::JsonValue& response)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32000); //Application specific error code

  Common::JsonValue message;
  message = ec.message();

  Common::JsonValue data(Common::JsonValue::OBJECT);
  Common::JsonValue appCode;
  appCode = static_cast<int64_t>(ec.value());
  data.insert("application_code", appCode);

  error.insert("code", code);
  error.insert("message", message);
  error.insert("data", data);

  response.insert("error", error);
}

void WalletdRpcServer::makeGenericErrorReponse(Common::JsonValue& response, const char* what, int errorCode)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(errorCode);

  std::string msg;
  if (what) {
    msg = what;
  } else {
    msg = "Unknown application error";
  }

  Common::JsonValue message;
  message = msg;

  error.insert("code", code);
  error.insert("message", message);

  response.insert("error", error);

}

void WalletdRpcServer::makeIncorrectRpcPasswordResponse(Common::JsonValue& response)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32604);

  Common::JsonValue message;
  message = "Incorrect RPC password";

  error.insert("code", code);
  error.insert("message", message);

  response.insert("error", error);
}

void WalletdRpcServer::makeInvalidRpcPasswordResponse(Common::JsonValue& response)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32604);

  Common::JsonValue message;
  message = "Invalid RPC password";

  error.insert("code", code);
  error.insert("message", message);

  response.insert("error", error);
}

void WalletdRpcServer::makeJsonParsingErrorResponse(Common::JsonValue& response)
{
  response = Common::JsonValue(Common::JsonValue::OBJECT);
  response.insert("jsonrpc", "2.0");
  response.insert("id", nullptr);

  Common::JsonValue error(Common::JsonValue::OBJECT);
  Common::JsonValue code;
  code = static_cast<int64_t>(-32700); //ambigous declaration of JsonValue::operator= (between int and JsonValue)

  Common::JsonValue message = "Parse error";

  error.insert("code", code);
  error.insert("message", message);

  response.insert("error", error);
}

void WalletdRpcServer::makeMethodNotFoundResponse(Common::JsonValue& response)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32601); //ambigous declaration of JsonValue::operator= (between int and JsonValue)

  Common::JsonValue message;
  message = "Method not found";

  error.insert("code", code);
  error.insert("message", message);

  response.insert("error", error);
}

void WalletdRpcServer::makeMissingRpcPasswordKeyResponse(Common::JsonValue& response)
{
  Common::JsonValue error(Common::JsonValue::OBJECT);

  Common::JsonValue code;
  code = static_cast<int64_t>(-32604);

  Common::JsonValue message;
  message = "Missing rpc_password key in JSON RPC request";

  error.insert("code", code);
  error.insert("message", message);

  response.insert("error", error);
}

void WalletdRpcServer::processJsonRpcRequest(const Common::JsonValue& request, Common::JsonValue& response)
{
  try
  {
    if (request.contains("id")) {
      response.insert("id", request("id"));
    }
    
    response.insert("jsonrpc", "2.0");

    if (!validateRpcPassword(request, response))
    {
      return;
    }

    // get method
    std::string method;

    if (!getMethod(request, response, method))
    {
      return;
    }

    // get params
    Common::JsonValue params(Common::JsonValue::OBJECT);
    if (request.contains("params")) {
      params = request("params");
    }
    
    if (method == "create_address")
    {
      WALLETD_RPC_COMMAND_CREATE_ADDRESS::Request createAddressRequest;
      WALLETD_RPC_COMMAND_CREATE_ADDRESS::Response createAddressResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(createAddressRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.createAddress(createAddressRequest, createAddressResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(createAddressResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "create_addresses")
    {
      WALLETD_RPC_COMMAND_CREATE_ADDRESSES::Request createAddressesRequest;
      WALLETD_RPC_COMMAND_CREATE_ADDRESSES::Response createAddressesResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(createAddressesRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.createAddresses(createAddressesRequest, createAddressesResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(createAddressesResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "create_delayed_transaction")
    {
      WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Request createDelayedTransactionRequest;
      WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION::Response createDelayedTransactionResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(createDelayedTransactionRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.createDelayedTransaction(createDelayedTransactionRequest, createDelayedTransactionResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(createDelayedTransactionResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "delete_address")
    {
      WALLETD_RPC_COMMAND_DELETE_ADDRESS::Request deleteAddressRequest;
      WALLETD_RPC_COMMAND_DELETE_ADDRESS::Response deleteAddressResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(deleteAddressRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.deleteAddress(deleteAddressRequest, deleteAddressResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(deleteAddressResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "delete_delayed_transaction")
    {
      WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Request deleteDelayedTransactionRequest;
      WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION::Response deleteDelayedTransactionResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(deleteDelayedTransactionRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.deleteDelayedTransaction(deleteDelayedTransactionRequest, deleteDelayedTransactionResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(deleteDelayedTransactionResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_addresses")
    {
      WALLETD_RPC_COMMAND_GET_ADDRESSES::Request getAddressesRequest;
      WALLETD_RPC_COMMAND_GET_ADDRESSES::Response getAddressesResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getAddressesRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getAddresses(getAddressesRequest, getAddressesResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getAddressesResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_addresses_count")
    {
      WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Request getAddressesCountRequest;
      WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT::Response getAddressesCountResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getAddressesCountRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getAddressesCount(getAddressesCountRequest, getAddressesCountResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getAddressesCountResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_balance")
    {
      WALLETD_RPC_COMMAND_GET_BALANCE::Request getBalanceRequest;
      WALLETD_RPC_COMMAND_GET_BALANCE::Response getBalanceResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getBalanceRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getBalance(getBalanceRequest, getBalanceResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getBalanceResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_block_hashes")
    {
      WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Request getBlockHashesRequest;
      WALLETD_RPC_COMMAND_GET_BLOCK_HASHES::Response getBlockHashesResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getBlockHashesRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getBlockHashes(getBlockHashesRequest, getBlockHashesResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getBlockHashesResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_delayed_transaction_hashes")
    {
      WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Request getDelayedTransactionHashesRequest;
      WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES::Response getDelayedTransactionHashesResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getDelayedTransactionHashesRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getDelayedTransactionHashes(getDelayedTransactionHashesRequest, getDelayedTransactionHashesResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getDelayedTransactionHashesResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_spend_private_key")
    {
      WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Request getSpendPrivateKeyRequest;
      WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY::Response getSpendPrivateKeyResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getSpendPrivateKeyRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getSpendPrivateKey(getSpendPrivateKeyRequest, getSpendPrivateKeyResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getSpendPrivateKeyResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_spend_private_keys")
    {
      WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Request getSpendPrivateKeysRequest;
      WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS::Response getSpendPrivateKeysResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getSpendPrivateKeysRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getSpendPrivateKeys(getSpendPrivateKeysRequest, getSpendPrivateKeysResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getSpendPrivateKeysResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_status")
    {
      WALLETD_RPC_COMMAND_GET_STATUS::Request getStatusRequest;
      WALLETD_RPC_COMMAND_GET_STATUS::Response getStatusResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getStatusRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getStatus(getStatusRequest, getStatusResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getStatusResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_transaction")
    {
      WALLETD_RPC_COMMAND_GET_TRANSACTION::Request getTransactionRequest;
      WALLETD_RPC_COMMAND_GET_TRANSACTION::Response getTransactionResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getTransactionRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getTransaction(getTransactionRequest, getTransactionResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getTransactionResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_transaction_hashes")
    {
      WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Request getTransactionHashesRequest;
      WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES::Response getTransactionHashesResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getTransactionHashesRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getTransactionHashes(getTransactionHashesRequest, getTransactionHashesResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getTransactionHashesResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_transactions")
    {
      WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Request getTransactionsRequest;
      WALLETD_RPC_COMMAND_GET_TRANSACTIONS::Response getTransactionsResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getTransactionsRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getTransactions(getTransactionsRequest, getTransactionsResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getTransactionsResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_unconfirmed_transaction_hashes")
    {
      WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Request getUnconfirmedTransactionHashesRequest;
      WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES::Response getUnconfirmedTransactionHashesResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getUnconfirmedTransactionHashesRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getUnconfirmedTransactionHashes(getUnconfirmedTransactionHashesRequest, getUnconfirmedTransactionHashesResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getUnconfirmedTransactionHashesResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "get_view_private_key")
    {
      WALLETD_RPC_COMMAND_GET_VIEW_PRIVATE_KEY::Request getViewKeyRequest;
      WALLETD_RPC_COMMAND_GET_VIEW_PRIVATE_KEY::Response getViewKeyResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(getViewKeyRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.getViewPrivateKey(getViewKeyRequest, getViewKeyResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(getViewKeyResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "reset")
    {
      WALLETD_RPC_COMMAND_RESET::Request resetRequest;
      WALLETD_RPC_COMMAND_RESET::Response resetResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(resetRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.reset(resetRequest, resetResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(resetResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method =="save")
    {
      WALLETD_RPC_COMMAND_SAVE::Request saveRequest;
      WALLETD_RPC_COMMAND_SAVE::Response saveResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(saveRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.save(saveRequest, saveResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(saveResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "send_delayed_transaction")
    {
      WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Request sendDelayedTransactionRequest;
      WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION::Response sendDelayedTransactionResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(sendDelayedTransactionRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.sendDelayedTransaction(sendDelayedTransactionRequest, sendDelayedTransactionResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(sendDelayedTransactionResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "send_transaction")
    {
      WALLETD_RPC_COMMAND_SEND_TRANSACTION::Request sendTransactionRequest;
      WALLETD_RPC_COMMAND_SEND_TRANSACTION::Response sendTransactionResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(sendTransactionRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.sendTransaction(sendTransactionRequest, sendTransactionResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(sendTransactionResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else if (method == "validate_address")
    {
      WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Request validateAddressRequest;
      WALLETD_RPC_COMMAND_VALIDATE_ADDRESS::Response validateAddressResponse;

      try
      {
        CryptoNote::JsonInputValueSerializer inputSerializer(const_cast<Common::JsonValue&>(params));
        serialize(validateAddressRequest, inputSerializer);
      }
      catch (std::exception&)
      {
        makeGenericErrorReponse(response, "Invalid Request", -32600);
        return;
      }

      std::error_code error = m_walletdRpcCommands.validateAddress(validateAddressRequest, validateAddressResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(validateAddressResponse, outputSerializer);
      fillJsonResponse(outputSerializer.getValue(), response);
    }
    else
    {
      m_logger(Logging::WARNING) << "Requested method not found : " << method;
      makeMethodNotFoundResponse(response);
      return;
    }

    m_logger(Logging::DEBUGGING) << method << " request came";

  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error occurred while processing JsonRpc request: " << e.what();
    makeGenericErrorReponse(response, e.what());
  }
}

void WalletdRpcServer::processRequest(const CryptoNote::HttpRequest& request, CryptoNote::HttpResponse& response)
{
  try
  {
    m_logger(Logging::TRACE) << "HTTP request came: \n" << request;

    if (request.getUrl() == "/json_rpc")
    {
      std::istringstream jsonInputStream(request.getBody());
      Common::JsonValue jsonRpcRequest;
      Common::JsonValue jsonRpcResponse(Common::JsonValue::OBJECT);

      try
      {
        jsonInputStream >> jsonRpcRequest;
      }
      catch (std::runtime_error&)
      {
        m_logger(Logging::DEBUGGING) << "Couldn't parse request: \"" << request.getBody() << "\"";
        makeJsonParsingErrorResponse(jsonRpcResponse);
        response.setStatus(CryptoNote::HttpResponse::STATUS_200);
        response.setBody(jsonRpcResponse.toString());
        return;
      }

      processJsonRpcRequest(jsonRpcRequest, jsonRpcResponse);

      std::ostringstream jsonOutputStream;
      jsonOutputStream << jsonRpcResponse;

      response.setStatus(CryptoNote::HttpResponse::STATUS_200);
      response.setBody(jsonOutputStream.str());

    }
    else
    {
      m_logger(Logging::WARNING) << "Requested url \"" << request.getUrl() << "\" is not found";
      response.setStatus(CryptoNote::HttpResponse::STATUS_404);
      return;
    }
  }
  catch (std::exception& e)
  {
    m_logger(Logging::WARNING) << "Error while processing http request: " << e.what();
    response.setStatus(CryptoNote::HttpResponse::STATUS_500);
  }
}

bool WalletdRpcServer::validateRpcPassword(const Common::JsonValue& request, Common::JsonValue& response)
{
  std::string rpcConfigurationPassword = getRpcConfigurationPassword();

  if (rpcConfigurationPassword != "")
  {
    std::string rpcPassword = "";
  
    if (request.contains("rpc_password") && request("rpc_password").isString())
    {
      rpcPassword = request("rpc_password").getString();
    }
    else if (!request.contains("rpc_password"))
    {
      m_logger(Logging::WARNING) << "Missing rpc_password key in JSON RPC request";
      makeMissingRpcPasswordKeyResponse(response);
      return false;
    }
    else
    {
      m_logger(Logging::WARNING) << "RPC password is invalid";
      makeInvalidRpcPasswordResponse(response);
      return false;
    }

    if (rpcPassword != rpcConfigurationPassword)
    {
      if (rpcPassword == "")
      {
        m_logger(Logging::WARNING) << "Your request does not include an RPC password";
      }
      else
      {
        m_logger(Logging::WARNING) << "Incorrect RPC password : " << rpcPassword;
      }

      makeIncorrectRpcPasswordResponse(response);
      return false;
    }
  }

  return true;
}

} // end namespace Walletd
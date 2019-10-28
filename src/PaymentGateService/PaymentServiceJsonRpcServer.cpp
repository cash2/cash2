// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018 The Turtlecoin developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <functional>

#include "PaymentServiceJsonRpcMessages.h"
#include "PaymentServiceJsonRpcServer.h"
#include "Serialization/JsonInputValueSerializer.h"
#include "Serialization/JsonOutputStreamSerializer.h"

namespace PaymentService {

// Walletd RPC Commands
//
// create_address
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
// send_delayed_transaction
// send_transaction
// validate_address


// Public functions


PaymentServiceJsonRpcServer::PaymentServiceJsonRpcServer(System::Dispatcher& sys, System::Event& stopEvent, WalletService& service, Logging::ILogger& loggerGroup, std::string rpcConfigurationPassword) :
  JsonRpcServer(sys, stopEvent, loggerGroup, rpcConfigurationPassword),
  m_walletdRpcCommands(service),
  logger(loggerGroup, "WalletdRpcServer") {
}


// Private functions


bool PaymentServiceJsonRpcServer::getMethod(const Common::JsonValue& request, Common::JsonValue& response, std::string& method)
{
  if (!request.contains("method")) {
    logger(Logging::WARNING) << "Field \"method\" is not found in json request : " << request;
    makeGenericErrorReponse(response, "Invalid Request", -3600);
    return false;
  }

  if (!request("method").isString()) {
    logger(Logging::WARNING) << "Field \"method\" is not a string type: " << request;
    makeGenericErrorReponse(response, "Invalid Request", -3600);
    return false;
  }

  method = request("method").getString();

  return true;
}

void PaymentServiceJsonRpcServer::processJsonRpcRequest(const Common::JsonValue& request, Common::JsonValue& response) {
  try
  {
    prepareJsonResponse(request, response);

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

      std::error_code error = m_walletdRpcCommands.handleCreateAddress(createAddressRequest, createAddressResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(createAddressResponse, outputSerializer);
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

      std::error_code error = m_walletdRpcCommands.handleCreateDelayedTransaction(createDelayedTransactionRequest, createDelayedTransactionResponse);
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

      std::error_code error = m_walletdRpcCommands.handleDeleteAddress(deleteAddressRequest, deleteAddressResponse);
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

      std::error_code error = m_walletdRpcCommands.handleDeleteDelayedTransaction(deleteDelayedTransactionRequest, deleteDelayedTransactionResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetAddresses(getAddressesRequest, getAddressesResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetAddressesCount(getAddressesCountRequest, getAddressesCountResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetBalance(getBalanceRequest, getBalanceResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetBlockHashes(getBlockHashesRequest, getBlockHashesResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetDelayedTransactionHashes(getDelayedTransactionHashesRequest, getDelayedTransactionHashesResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetSpendPrivateKey(getSpendPrivateKeyRequest, getSpendPrivateKeyResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetSpendPrivateKeys(getSpendPrivateKeysRequest, getSpendPrivateKeysResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetStatus(getStatusRequest, getStatusResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetTransaction(getTransactionRequest, getTransactionResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetTransactionHashes(getTransactionHashesRequest, getTransactionHashesResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetTransactions(getTransactionsRequest, getTransactionsResponse);
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

      std::error_code error = m_walletdRpcCommands.handleGetUnconfirmedTransactionHashes(getUnconfirmedTransactionHashesRequest, getUnconfirmedTransactionHashesResponse);
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
      WALLETD_RPC_COMMAND_GET_VIEW_KEY::Request getViewKeyRequest;
      WALLETD_RPC_COMMAND_GET_VIEW_KEY::Response getViewKeyResponse;

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

      std::error_code error = m_walletdRpcCommands.handleGetViewKey(getViewKeyRequest, getViewKeyResponse);
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

      std::error_code error = m_walletdRpcCommands.handleReset(resetRequest, resetResponse);
      if (error)
      {
        makeErrorResponse(error, response);
        return;
      }

      CryptoNote::JsonOutputStreamSerializer outputSerializer;
      serialize(resetResponse, outputSerializer);
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

      std::error_code error = m_walletdRpcCommands.handleSendDelayedTransaction(sendDelayedTransactionRequest, sendDelayedTransactionResponse);
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

      std::error_code error = m_walletdRpcCommands.handleSendTransaction(sendTransactionRequest, sendTransactionResponse);
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

      std::error_code error = m_walletdRpcCommands.handleValidateAddress(validateAddressRequest, validateAddressResponse);
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
      logger(Logging::WARNING) << "Requested method not found : " << method;
      makeMethodNotFoundResponse(response);
      return;
    }

    logger(Logging::DEBUGGING) << method << " request came";

  }
  catch (std::exception& e)
  {
    logger(Logging::WARNING) << "Error occurred while processing JsonRpc request: " << e.what();
    makeGenericErrorReponse(response, e.what());
  }
}

bool PaymentServiceJsonRpcServer::validateRpcPassword(const Common::JsonValue& request, Common::JsonValue& response)
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
      logger(Logging::WARNING) << "Missing rpc_password key in JSON RPC request";
      makeMissingRpcPasswordKeyResponse(response);
      return false;
    }
    else
    {
      logger(Logging::WARNING) << "RPC password is invalid";
      makeInvalidRpcPasswordResponse(response);
      return false;
    }

    if (rpcPassword != rpcConfigurationPassword)
    {
      if (rpcPassword == "")
      {
        logger(Logging::WARNING) << "Your request does not include an RPC password";
      }
      else
      {
        logger(Logging::WARNING) << "Incorrect RPC password : " << rpcPassword;
      }

      makeIncorrectRpcPasswordResponse(response);
      return false;
    }
  }

  return true;
}

} // end namespace PaymentService
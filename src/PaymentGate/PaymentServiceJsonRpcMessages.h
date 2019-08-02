// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <exception>
#include <limits>
#include <vector>

#include "Serialization/ISerializer.h"

namespace PaymentService {

const uint32_t DEFAULT_ANONYMITY_LEVEL = 6;

class RequestSerializationError: public std::exception {
public:
  virtual const char* what() const throw() override { return "Request error"; }
};

struct Reset {
  struct Request {
    std::string view_private_key;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetViewKey {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::string view_private_key;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetStatus {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    uint32_t block_count;
    uint32_t known_block_count;
    std::string last_block_hash;
    uint32_t peer_count;
    uint64_t minimal_fee;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetAddresses {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::vector<std::string> addresses;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetAddressesCount {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    size_t addresses_count;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct CreateAddress {
  struct Request {
    std::string spend_private_key;
    std::string spend_public_key;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct DeleteAddress {
  struct Request {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetSpendPrivateKey {
  struct Request {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::string spend_private_key;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetBalance {
  struct Request {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    uint64_t available_balance;
    uint64_t locked_amount;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetBlockHashes {
  struct Request {
    uint32_t first_block_index;
    uint32_t block_count;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::vector<std::string> block_hashes;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct TransactionHashesInBlockRpcInfo {
  std::string block_hash;
  std::vector<std::string> transaction_hashes;

  void serialize(CryptoNote::ISerializer& serializer);
};

struct GetTransactionHashes {
  struct Request {
    std::vector<std::string> addresses;
    std::string block_hash;
    uint32_t first_block_index = std::numeric_limits<uint32_t>::max();
    uint32_t block_count;
    std::string payment_id;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::vector<TransactionHashesInBlockRpcInfo> items;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct TransferRpcInfo {
  uint8_t type;
  std::string address;
  int64_t amount;

  void serialize(CryptoNote::ISerializer& serializer);
};

struct TransactionRpcInfo {
  uint8_t state;
  std::string transaction_hash;
  uint32_t block_height;
  uint64_t timestamp;
  bool is_base;
  uint64_t unlock_time;
  int64_t amount;
  uint64_t fee;
  std::vector<TransferRpcInfo> transfers;
  std::string extra;
  std::string payment_id;

  void serialize(CryptoNote::ISerializer& serializer);
};

struct GetTransaction {
  struct Request {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    TransactionRpcInfo transaction;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct TransactionsInBlockRpcInfo {
  std::string block_hash;
  std::vector<TransactionRpcInfo> transactions;

  void serialize(CryptoNote::ISerializer& serializer);
};

struct GetTransactions {
  struct Request {
    std::vector<std::string> addresses;
    std::string block_hash;
    uint32_t first_block_index = std::numeric_limits<uint32_t>::max();
    uint32_t block_count;
    std::string payment_id;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::vector<TransactionsInBlockRpcInfo> items;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetUnconfirmedTransactionHashes {
  struct Request {
    std::vector<std::string> addresses;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::vector<std::string> transaction_hashes;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct WalletRpcOrder {
  std::string address;
  uint64_t amount;

  void serialize(CryptoNote::ISerializer& serializer);
};

struct SendTransaction {
  struct Request {
    std::vector<std::string> source_addresses;
    std::vector<WalletRpcOrder> transfers;
    std::string change_address;
    uint64_t fee = 0;
    uint32_t anonymity = DEFAULT_ANONYMITY_LEVEL;
    std::string extra;
    std::string payment_id;
    uint64_t unlock_time = 0;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::string transaction_hash;
    std::string transaction_private_key;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct CreateDelayedTransaction {
  struct Request {
    std::vector<std::string> addresses;
    std::vector<WalletRpcOrder> transfers;
    std::string change_address;
    uint64_t fee = 0;
    uint32_t anonymity = DEFAULT_ANONYMITY_LEVEL;
    std::string extra;
    std::string payment_id;
    uint64_t unlock_time = 0;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct GetDelayedTransactionHashes {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    std::vector<std::string> transaction_hashes;

    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct DeleteDelayedTransaction {
  struct Request {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer);
  };
};

struct SendDelayedTransaction {
  struct Request {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer);
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer);
  };
};

} //namespace PaymentService

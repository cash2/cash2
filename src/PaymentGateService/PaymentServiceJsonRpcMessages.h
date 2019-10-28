// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2019, The Karbo Developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <exception>
#include <limits>
#include <vector>

#include "CryptoNoteConfig.h"
#include "Serialization/ISerializer.h"

namespace PaymentService {

const uint32_t DEFAULT_ANONYMITY_LEVEL = CryptoNote::parameters::MAX_MIXIN;

class RequestSerializationError: public std::exception {
public:
  virtual const char* what() const throw() override { return "Request error"; }
};


// Walletd RPC Data Types


struct TransferRpcInfo {
  uint8_t type;
  std::string address;
  int64_t amount;

  void serialize(CryptoNote::ISerializer& serializer) {
    serializer(type, "type");
    serializer(address, "address");
    serializer(amount, "amount");
  }
};

struct TransactionHashesInBlockRpcInfo {
  std::string block_hash;
  std::vector<std::string> transaction_hashes;

  void serialize(CryptoNote::ISerializer& serializer) {
    serializer(block_hash, "block_hash");
    serializer(transaction_hashes, "transaction_hashes");
  }
};

struct TransactionRpcInfo {
  uint8_t state;
  std::string transaction_hash;
  uint32_t block_index;
  uint64_t timestamp;
  bool is_base;
  uint64_t unlock_time;
  int64_t amount;
  uint64_t fee;
  std::vector<TransferRpcInfo> transfers;
  std::string extra;
  std::string payment_id;

  void serialize(CryptoNote::ISerializer& serializer) {
    serializer(state, "state");
    serializer(transaction_hash, "transaction_hash");
    serializer(block_index, "block_index");
    serializer(timestamp, "timestamp");
    serializer(is_base, "is_base");
    serializer(unlock_time, "unlock_time");
    serializer(amount, "amount");
    serializer(fee, "fee");
    serializer(transfers, "transfers");
    serializer(extra, "extra");
    serializer(payment_id, "payment_id");
  }
};

struct TransactionsInBlockRpcInfo {
  std::string block_hash;
  std::vector<TransactionRpcInfo> transactions;

  void serialize(CryptoNote::ISerializer& serializer) {
    serializer(block_hash, "block_hash");
    serializer(transactions, "transactions");
  }
};

struct WalletRpcOrder {
  std::string address;
  uint64_t amount;

  void serialize(CryptoNote::ISerializer& serializer) {
    bool r = serializer(address, "address");
    r &= serializer(amount, "amount");

    if (!r) {
      throw RequestSerializationError();
    }
  }
};


// Walletd RPC Commands


struct WALLETD_RPC_COMMAND_CREATE_ADDRESS {
  struct Request {
    std::string spend_private_key;
    std::string spend_public_key;

    void serialize(CryptoNote::ISerializer& serializer) {
      bool hasSecretKey = serializer(spend_private_key, "spend_private_key");
      bool hasPublicKey = serializer(spend_public_key, "spend_public_key");

      if (hasSecretKey && hasPublicKey) {
        throw RequestSerializationError();
      }
    }
  };

  struct Response {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(address, "address");
    }
  };
};

struct WALLETD_RPC_COMMAND_CREATE_DELAYED_TRANSACTION {
  struct Request {
    std::vector<std::string> addresses;
    std::vector<WalletRpcOrder> transfers;
    std::string change_address;
    uint64_t fee = 0;
    uint32_t anonymity = DEFAULT_ANONYMITY_LEVEL;
    std::string extra;
    std::string payment_id;
    uint64_t unlock_time = 0;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(addresses, "addresses");

      if (!serializer(transfers, "transfers")) {
        throw RequestSerializationError();
      }

      serializer(change_address, "change_address");

      if (!serializer(fee, "fee")) {
        throw RequestSerializationError();
      }

      if (!serializer(anonymity, "anonymity")) {
        throw RequestSerializationError();
      }

      bool hasExtra = serializer(extra, "extra");
      bool hasPaymentId = serializer(payment_id, "payment_id");

      if (hasExtra && hasPaymentId) {
        throw RequestSerializationError();
      }

      serializer(unlock_time, "unlock_time");
    }
  };

  struct Response {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(transaction_hash, "transaction_hash");
    }
  };
};

struct WALLETD_RPC_COMMAND_DELETE_ADDRESS {
  struct Request {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer) {
      if (!serializer(address, "address")) {
        throw RequestSerializationError();
      }
    }
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };
};

struct WALLETD_RPC_COMMAND_DELETE_DELAYED_TRANSACTION {
  struct Request {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer) {
      if (!serializer(transaction_hash, "transaction_hash")) {
        throw RequestSerializationError();
      }
    }
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };
};

struct WALLETD_RPC_COMMAND_GET_ADDRESSES {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };

  struct Response {
    std::vector<std::string> addresses;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(addresses, "addresses");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_ADDRESSES_COUNT {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };

  struct Response {
    size_t addresses_count;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(addresses_count, "addresses_count");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_BALANCE {
  struct Request {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(address, "address");
    }
  };

  struct Response {
    uint64_t available_balance;
    uint64_t locked_amount;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(available_balance, "available_balance");
      serializer(locked_amount, "locked_amount");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_BLOCK_HASHES {
  struct Request {
    uint32_t start_block_height;
    uint32_t number_of_blocks;

    void serialize(CryptoNote::ISerializer& serializer) {
      bool r = serializer(start_block_height, "start_block_height");
      r &= serializer(number_of_blocks, "number_of_blocks");

      if (!r) {
        throw RequestSerializationError();
      }
    }
  };

  struct Response {
    std::vector<std::string> block_hashes;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(block_hashes, "block_hashes");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_DELAYED_TRANSACTION_HASHES {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };

  struct Response {
    std::vector<std::string> transaction_hashes;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(transaction_hashes, "transaction_hashes");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEY {
  struct Request {
    std::string address;

    void serialize(CryptoNote::ISerializer& serializer) {
      if (!serializer(address, "address")) {
        throw RequestSerializationError();
      }
    }
  };

  struct Response {
    std::string spend_private_key;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(spend_private_key, "spend_private_key");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_SPEND_PRIVATE_KEYS {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };

  struct Response {
    std::vector<std::string> spend_private_keys;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(spend_private_keys, "spend_private_keys");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_STATUS {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };

  struct Response {
    uint32_t block_count;
    uint32_t known_block_count;
    std::string last_block_hash;
    uint32_t peer_count;
    uint64_t minimal_fee;
    std::string cash2_software_version;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(block_count, "block_count");
      serializer(known_block_count, "known_block_count");
      serializer(last_block_hash, "last_block_hash");
      serializer(peer_count, "peer_count");
      serializer(cash2_software_version, "cash2_software_version");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_TRANSACTION {
  struct Request {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer) {
      if (!serializer(transaction_hash, "transaction_hash")) {
        throw RequestSerializationError();
      }
    }
  };

  struct Response {
    TransactionRpcInfo transaction;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(transaction, "transaction");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_TRANSACTION_HASHES {
  struct Request {
    std::vector<std::string> addresses;
    std::string start_block_hash;
    uint32_t start_block_height = std::numeric_limits<uint32_t>::max();
    uint32_t number_of_blocks;
    std::string payment_id;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(addresses, "addresses");

      if (serializer(start_block_hash, "start_block_hash") == serializer(start_block_height, "start_block_height")) {
        throw RequestSerializationError();
      }

      if (!serializer(number_of_blocks, "number_of_blocks")) {
        throw RequestSerializationError();
      }

      serializer(payment_id, "payment_id");
    }
  };

  struct Response {
    std::vector<TransactionHashesInBlockRpcInfo> items;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(items, "items");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_TRANSACTIONS {
  struct Request {
    std::vector<std::string> addresses;
    std::string start_block_hash;
    uint32_t start_block_height = std::numeric_limits<uint32_t>::max();
    uint32_t number_of_blocks;
    std::string payment_id;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(addresses, "addresses");

      if (serializer(start_block_hash, "start_block_hash") == serializer(start_block_height, "start_block_height")) {
        throw RequestSerializationError();
      }

      if (!serializer(number_of_blocks, "number_of_blocks")) {
        throw RequestSerializationError();
      }

      serializer(payment_id, "payment_id");
    }
  };

  struct Response {
    std::vector<TransactionsInBlockRpcInfo> items;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(items, "items");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_UNCONFIRMED_TRANSACTION_HASHES {
  struct Request {
    std::vector<std::string> addresses;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(addresses, "addresses");
    }
  };

  struct Response {
    std::vector<std::string> transaction_hashes;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(transaction_hashes, "transaction_hashes");
    }
  };
};

struct WALLETD_RPC_COMMAND_GET_VIEW_KEY {
  struct Request {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };

  struct Response {
    std::string view_private_key;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(view_private_key, "view_private_key");
    }
  };
};

struct WALLETD_RPC_COMMAND_RESET {
  struct Request {
    std::string view_private_key;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(view_private_key, "view_private_key");
    }
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };
};

struct WALLETD_RPC_COMMAND_SEND_DELAYED_TRANSACTION {
  struct Request {
    std::string transaction_hash;

    void serialize(CryptoNote::ISerializer& serializer) {
      if (!serializer(transaction_hash, "transaction_hash")) {
        throw RequestSerializationError();
      }
    }
  };

  struct Response {
    void serialize(CryptoNote::ISerializer& serializer) {}
  };
};

struct WALLETD_RPC_COMMAND_SEND_TRANSACTION {
  struct Request {
    std::vector<std::string> source_addresses;
    std::vector<WalletRpcOrder> transfers;
    std::string change_address;
    uint64_t fee = 0;
    uint32_t anonymity = DEFAULT_ANONYMITY_LEVEL;
    std::string extra;
    std::string payment_id;
    uint64_t unlock_time = 0;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(source_addresses, "addresses");

      if (!serializer(transfers, "transfers")) {
        throw RequestSerializationError();
      }

      serializer(change_address, "change_address");

      if (!serializer(fee, "fee")) {
        throw RequestSerializationError();
      }

      if (!serializer(anonymity, "anonymity")) {
        throw RequestSerializationError();
      }

      bool hasExtra = serializer(extra, "extra");
      bool hasPaymentId = serializer(payment_id, "payment_id");

      if (hasExtra && hasPaymentId) {
        throw RequestSerializationError();
      }

      serializer(unlock_time, "unlock_time");
    }
  };

  struct Response {
    std::string transaction_hash;
    std::string transaction_private_key;

    void serialize(CryptoNote::ISerializer& serializer) {
      serializer(transaction_hash, "transaction_hash");
      serializer(transaction_private_key, "transaction_private_key");                                                         
    }
  };
};

struct WALLETD_RPC_COMMAND_VALIDATE_ADDRESS {
	struct Request {
		std::string address;

		void serialize(CryptoNote::ISerializer& serializer){
      serializer(address, "address");
    }
	};

	struct Response {
		bool address_valid;

		void serialize(CryptoNote::ISerializer& serializer) {
      serializer(address_valid, "address_valid");
    }
	};
};

} // end namespace PaymentService

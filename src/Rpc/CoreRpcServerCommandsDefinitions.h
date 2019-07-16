// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2017-2018, The Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/Difficulty.h"
#include "crypto/hash.h"

#include "Serialization/SerializationOverloads.h"

namespace CryptoNote {
//-----------------------------------------------
#define CORE_RPC_STATUS_OK "OK"
#define CORE_RPC_STATUS_BUSY "BUSY"

struct EMPTY_STRUCT {
  void serialize(ISerializer &s) {}
};

struct STATUS_STRUCT {
  std::string status;

  void serialize(ISerializer &s) {
    KV_MEMBER(status)
  }
};

struct COMMAND_RPC_GET_HEIGHT {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t height;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(height)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_BLOCKS_FAST {

  struct request {
    std::vector<Crypto::Hash> block_ids; //*first 10 blocks id goes sequential, next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on, and the last one is always genesis block */
    
    void serialize(ISerializer &s) {
      serializeAsBinary(block_ids, "block_ids", s);
    }
  };

  struct response {
    std::vector<block_complete_entry> blocks;
    uint64_t start_height;
    uint64_t current_height;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(blocks)
      KV_MEMBER(start_height)
      KV_MEMBER(current_height)
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_GET_TRANSACTIONS {
  struct request {
    std::vector<std::string> txs_hashes;

    void serialize(ISerializer &s) {
      KV_MEMBER(txs_hashes)
    }
  };

  struct response {
    std::vector<std::string> transactions_as_hex; //transactions blobs as hex
    std::vector<std::string> missed_transactions;  //not found transactions
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(transactions_as_hex)
      KV_MEMBER(missed_transactions)
      KV_MEMBER(status)    
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_GET_POOL_CHANGES {
  struct request {
    Crypto::Hash tail_block_id;
    std::vector<Crypto::Hash> known_txs_ids;

    void serialize(ISerializer &s) {
      KV_MEMBER(tail_block_id)
      serializeAsBinary(known_txs_ids, "known_txs_ids", s);
    }
  };

  struct response {
    bool is_tail_block_actual;
    std::vector<BinaryArray> added_txs;          // Added transactions blobs
    std::vector<Crypto::Hash> deleted_txs_ids; // IDs of not found transactions
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(is_tail_block_actual)
      KV_MEMBER(added_txs)
      serializeAsBinary(deleted_txs_ids, "deleted_txs_ids", s);
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_POOL_CHANGES_LITE {
  struct request {
    Crypto::Hash tail_block_id;
    std::vector<Crypto::Hash> known_txs_ids;

    void serialize(ISerializer &s) {
      KV_MEMBER(tail_block_id)
      serializeAsBinary(known_txs_ids, "known_txs_ids", s);
    }
  };

  struct response {
    bool is_tail_block_actual;
    std::vector<TransactionPrefixInfo> added_txs;          // Added transactions blobs
    std::vector<Crypto::Hash> deleted_txs_ids; // IDs of not found transactions
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(is_tail_block_actual)
      KV_MEMBER(added_txs)
      serializeAsBinary(deleted_txs_ids, "deleted_txs_ids", s);
      KV_MEMBER(status)
    }
  };
};

//-----------------------------------------------
struct COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES {
  
  struct request {
    Crypto::Hash transaction_id;

    void serialize(ISerializer &s) {
      KV_MEMBER(transaction_id)
    }
  };

  struct response {
    std::vector<uint64_t> o_indexes;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(o_indexes)
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request {
  std::vector<uint64_t> amounts;
  uint64_t outs_count;

  void serialize(ISerializer &s) {
    KV_MEMBER(amounts)
    KV_MEMBER(outs_count)
  }
};

#pragma pack(push, 1)
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_out_entry {
  uint64_t global_amount_index;
  Crypto::PublicKey out_key;
};
#pragma pack(pop)

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount {
  uint64_t amount;
  std::vector<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_out_entry> outs;

  void serialize(ISerializer &s) {
    KV_MEMBER(amount)
    serializeAsBinary(outs, "outs", s);
  }
};

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response {
  std::vector<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount> outs;
  std::string status;

  void serialize(ISerializer &s) {
    KV_MEMBER(outs);
    KV_MEMBER(status)
  }
};

struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS {
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request request;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response response;

  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_out_entry out_entry;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount outs_for_amount;
};

//-----------------------------------------------
struct COMMAND_RPC_SEND_RAW_TX {
  struct request {
    std::string tx_as_hex;

    request() {}
    explicit request(const Transaction &);

    void serialize(ISerializer &s) {
      KV_MEMBER(tx_as_hex)
    }
  };

  struct response {
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_START_MINING {
  struct request {
    std::string miner_address;
    uint64_t threads_count;

    void serialize(ISerializer &s) {
      KV_MEMBER(miner_address)
      KV_MEMBER(threads_count)
    }
  };

  struct response {
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
    }
  };
};
//-----------------------------------------------
struct COMMAND_RPC_GET_INFO {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string circulating_supply;
    uint64_t difficulty;
    uint64_t grey_peerlist_size;
    uint64_t height;
    uint64_t incoming_connections_count;
    uint32_t last_known_block_index;
    uint64_t mempool_transactions_count;
    uint64_t orphan_blocks_count;
    uint64_t outgoing_connections_count;
    std::string status;
    uint64_t total_transactions_count;
    uint64_t transaction_fee;
    uint64_t white_peerlist_size;

    void serialize(ISerializer &s) {
      KV_MEMBER(circulating_supply)
      KV_MEMBER(difficulty)
      KV_MEMBER(grey_peerlist_size)
      KV_MEMBER(height)
      KV_MEMBER(incoming_connections_count)
      KV_MEMBER(last_known_block_index)
      KV_MEMBER(mempool_transactions_count)
      KV_MEMBER(orphan_blocks_count)
      KV_MEMBER(outgoing_connections_count)
      KV_MEMBER(status)
      KV_MEMBER(total_transactions_count)
      KV_MEMBER(transaction_fee)
      KV_MEMBER(white_peerlist_size)
    }
  };
};

struct COMMAND_RPC_GET_ORPHAN_BLOCKS_COUNT {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    uint64_t orphan_blocks_count;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(orphan_blocks_count)
    }
  };
};

struct COMMAND_RPC_GET_CIRCULATING_SUPPLY {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    std::string circulating_supply;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(circulating_supply)
    }
  };
};

struct COMMAND_RPC_GET_DIFFICULTY {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    uint64_t difficulty;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(difficulty)
    }
  };
};

struct COMMAND_RPC_GET_GREY_PEERLIST_SIZE {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    uint64_t grey_peerlist_size;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(grey_peerlist_size)
    }
  };
};

struct COMMAND_RPC_GET_INCOMING_CONNECTIONS_COUNT {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    uint64_t incoming_connections_count;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(incoming_connections_count)
    }
  };
};

struct COMMAND_RPC_GET_MEMPOOL_TRANSACTIONS_COUNT {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    uint64_t mempool_transactions_count;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(mempool_transactions_count)
    }
  };
};

struct COMMAND_RPC_GET_TRANSACTION_FEE {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    uint64_t transaction_fee;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(transaction_fee)
    }
  };
};

struct COMMAND_RPC_GET_OUTGOING_CONNECTIONS_COUNT {
  typedef EMPTY_STRUCT request;

  struct response {
    uint64_t outgoing_connections_count;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(outgoing_connections_count)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_TOTAL_TRANSACTIONS_COUNT {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string status;
    uint64_t total_transactions_count;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(total_transactions_count)
    }
  };
};

//-----------------------------------------------
struct COMMAND_RPC_STOP_MINING {
  typedef EMPTY_STRUCT request;
  typedef STATUS_STRUCT response;
};

//-----------------------------------------------
struct COMMAND_RPC_STOP_DAEMON {
  typedef EMPTY_STRUCT request;
  typedef STATUS_STRUCT response;
};

//
struct COMMAND_RPC_GET_BLOCK_COUNT {
  typedef std::vector<std::string> request;

  struct response {
    uint64_t count;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(count)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_BLOCK_HASH {
  typedef std::vector<uint64_t> request;
  typedef std::string response;
};

struct COMMAND_RPC_GET_BLOCK_TEMPLATE {
  struct request {
    uint64_t reserve_size; //max 255 bytes
    std::string wallet_address;

    void serialize(ISerializer &s) {
      KV_MEMBER(reserve_size)
      KV_MEMBER(wallet_address)
    }
  };

  struct response {
    uint64_t difficulty;
    uint32_t height;
    uint64_t reserved_offset;
    std::string block_template_blob;
    std::string status;
    std::string coinbase_transaction;
    std::vector<std::string> transaction_hashes;

    void serialize(ISerializer &s) {
      KV_MEMBER(difficulty)
      KV_MEMBER(height)
      KV_MEMBER(reserved_offset)
      KV_MEMBER(block_template_blob)
      KV_MEMBER(status)
      KV_MEMBER(coinbase_transaction)
      KV_MEMBER(transaction_hashes)
    }
  };
};

struct COMMAND_RPC_GET_CURRENCY_ID {
  typedef EMPTY_STRUCT request;

  struct response {
    std::string currency_id_blob;

    void serialize(ISerializer &s) {
      KV_MEMBER(currency_id_blob)
    }
  };
};

struct COMMAND_RPC_SUBMIT_BLOCK {
  typedef std::vector<std::string> request;
  typedef STATUS_STRUCT response;
};

struct block_header_response {
  uint64_t timestamp;
  std::string prev_hash;
  std::string merkle_root;
  uint64_t nonce;
  bool orphan_status;
  uint64_t height;
  uint64_t depth;
  std::string hash;
  difficulty_type difficulty;
  uint64_t reward;

  void serialize(ISerializer &s) {
    KV_MEMBER(timestamp)
    KV_MEMBER(prev_hash)
    KV_MEMBER(merkle_root)
    KV_MEMBER(nonce)
    KV_MEMBER(orphan_status)
    KV_MEMBER(height)
    KV_MEMBER(depth)
    KV_MEMBER(hash)
    KV_MEMBER(difficulty)
    KV_MEMBER(reward)
  }
};

struct BLOCK_HEADER_RESPONSE {
  std::string status;
  block_header_response block_header;

  void serialize(ISerializer &s) {
    KV_MEMBER(block_header)
    KV_MEMBER(status)
  }
};


struct COMMAND_RPC_GET_LAST_BLOCK_HEADER {
  typedef EMPTY_STRUCT request;
  typedef BLOCK_HEADER_RESPONSE response;
};

struct COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH {
  struct request {
    std::string hash;

    void serialize(ISerializer &s) {
      KV_MEMBER(hash)
    }
  };

  typedef BLOCK_HEADER_RESPONSE response;
};

struct COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT {
  struct request {
    uint64_t height;

    void serialize(ISerializer &s) {
      KV_MEMBER(height)
    }
  };

  typedef BLOCK_HEADER_RESPONSE response;
};

struct COMMAND_RPC_QUERY_BLOCKS {
  struct request {
    std::vector<Crypto::Hash> block_ids; //*first 10 blocks id goes sequential, next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on, and the last one is always genesis block */
    uint64_t timestamp;

    void serialize(ISerializer &s) {
      serializeAsBinary(block_ids, "block_ids", s);
      KV_MEMBER(timestamp)
    }
  };

  struct response {
    std::string status;
    uint64_t start_height;
    uint64_t current_height;
    uint64_t full_offset;
    std::vector<BlockFullInfo> items;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(start_height)
      KV_MEMBER(current_height)
      KV_MEMBER(full_offset)
      KV_MEMBER(items)
    }
  };
};

struct COMMAND_RPC_QUERY_BLOCKS_LITE {
  struct request {
    std::vector<Crypto::Hash> block_ids;
    uint64_t timestamp;

    void serialize(ISerializer &s) {
      serializeAsBinary(block_ids, "block_ids", s);
      KV_MEMBER(timestamp)
    }
  };

  struct response {
    std::string status;
    uint64_t start_height;
    uint64_t current_height;
    uint64_t full_offset;
    std::vector<BlockShortInfo> items;

    void serialize(ISerializer &s) {
      KV_MEMBER(status)
      KV_MEMBER(start_height)
      KV_MEMBER(current_height)
      KV_MEMBER(full_offset)
      KV_MEMBER(items)
    }
  };
};

// Definitions for block explorer

struct block_short_response {
  uint64_t timestamp;
  uint32_t height;
  std::string hash;
  uint64_t size;
  uint64_t transaction_count;
  difficulty_type difficulty;

  void serialize(ISerializer &s) {
    KV_MEMBER(timestamp)
    KV_MEMBER(height)
    KV_MEMBER(hash)
    KV_MEMBER(size)
    KV_MEMBER(transaction_count)
    KV_MEMBER(difficulty)
  }
};

struct transaction_short_response {
  std::string hash;
  uint64_t fee;
  uint64_t amount_out;
  uint64_t size;

  void serialize(ISerializer &s) {
    KV_MEMBER(hash)
    KV_MEMBER(fee)
    KV_MEMBER(amount_out)
    KV_MEMBER(size)
  }
};

struct block_long_response {
  uint64_t timestamp;
  std::string prev_hash;
  std::string merkle_root;
  uint64_t nonce;
  bool is_orphaned;
  uint64_t height;
  uint64_t depth;
  std::string hash;
  difficulty_type difficulty;
  uint64_t total_reward;
  uint64_t size;
  uint64_t transactions_size;
  std::string already_generated_coins;
  uint64_t already_generated_transactions;
  uint64_t base_reward;
  uint64_t total_fees;
  std::vector<transaction_short_response> transactions;

  void serialize(ISerializer &s) {
    KV_MEMBER(timestamp)
    KV_MEMBER(prev_hash)
    KV_MEMBER(merkle_root)
    KV_MEMBER(nonce)
    KV_MEMBER(is_orphaned)
    KV_MEMBER(height)
    KV_MEMBER(depth)
    KV_MEMBER(hash)
    KV_MEMBER(difficulty)
    KV_MEMBER(total_reward)
    KV_MEMBER(size)
    KV_MEMBER(transactions_size)
    KV_MEMBER(already_generated_coins)
    KV_MEMBER(already_generated_transactions)
    KV_MEMBER(base_reward)
    KV_MEMBER(total_fees)
    KV_MEMBER(transactions)
  }
};

struct COMMAND_RPC_GET_BLOCKS_JSON {
  struct request {
    uint64_t height;

    void serialize(ISerializer &s) {
      KV_MEMBER(height)
    }
  };

  struct response {
    std::vector<block_short_response> blocks; //transactions blobs as hex
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(blocks)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_GET_BLOCK {
  struct request {
    std::string hash;

    void serialize(ISerializer &s) {
      KV_MEMBER(hash)
    }
  };

  struct response {
    block_long_response block;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(block)
      KV_MEMBER(status)
    }
  };
};

struct transaction_long_response {
  std::string hash;
  size_t size;
  std::string payment_id;
  uint64_t mixin;
  uint64_t fee;
  uint64_t amount_out;

  void serialize(ISerializer &s) {
    KV_MEMBER(hash)
    KV_MEMBER(size)
    KV_MEMBER(payment_id)
    KV_MEMBER(mixin)
    KV_MEMBER(fee)
    KV_MEMBER(amount_out)
  }
};

struct COMMAND_RPC_GET_TRANSACTION {
  struct request {
    std::string hash;

    void serialize(ISerializer &s) {
      KV_MEMBER(hash)
    }
  };

  struct response {
    Transaction transaction;
    transaction_long_response transaction_details;
    block_short_response block;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(transaction)
      KV_MEMBER(transaction_details)
      KV_MEMBER(block)
      KV_MEMBER(status)
    }
  };
};

struct mempool_transaction_response {
  std::string hash;
  uint64_t fee;
  uint64_t amount;
  uint64_t size;
  uint64_t receive_time;

  void serialize(ISerializer &s) {
    KV_MEMBER(hash)
    KV_MEMBER(fee)
    KV_MEMBER(amount)
    KV_MEMBER(size)
    KV_MEMBER(receive_time)
  }
};

struct COMMAND_RPC_GET_MEMPOOL {
  typedef EMPTY_STRUCT request;

  struct response {
    std::vector<mempool_transaction_response> mempool;
    std::string status;

    void serialize(ISerializer &s) {
      KV_MEMBER(mempool)
      KV_MEMBER(status)
    }
  };
};

struct COMMAND_RPC_CHECK_PAYMENT {
	struct request {
		std::string transaction_id;
		std::string transaction_private_key;
		std::string receiver_address;

		void serialize(ISerializer &s) {
			KV_MEMBER(transaction_id)
			KV_MEMBER(transaction_private_key)
			KV_MEMBER(receiver_address)
		}
	};

	struct response {
		uint64_t amount;
		std::vector<TransactionOutput> outputs;
		std::string status;

		void serialize(ISerializer &s) {
			KV_MEMBER(amount)
			KV_MEMBER(outputs)
			KV_MEMBER(status)
		}
	};
};

} // end namespace CryptoNote

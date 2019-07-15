// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2016-2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#include "CryptoNoteProtocol/CryptoNoteProtocolDefinitions.h"
#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "crypto/hash.h"
#include "Rpc/CoreRpcServerCommandsDefinitions.h"
#include "WalletRpcServerErrorCodes.h"

namespace Tools
{

namespace wallet_rpc
{

using CryptoNote::ISerializer;

#define WALLET_RPC_STATUS_OK      "OK"
#define WALLET_RPC_STATUS_BUSY    "BUSY"

  struct COMMAND_RPC_GET_BALANCE
  {
    typedef CryptoNote::EMPTY_STRUCT request;

    struct response
    {
      uint64_t locked_amount;
      uint64_t available_balance;

      void serialize(ISerializer& s) {
        KV_MEMBER(locked_amount)
        KV_MEMBER(available_balance)
      }
    };
  };

  struct transfer_destination
  {
    uint64_t amount;
    std::string address;

    void serialize(ISerializer& s) {
      KV_MEMBER(amount)
      KV_MEMBER(address)
    }
  };

  struct COMMAND_RPC_TRANSFER
  {
    struct request
    {
      std::list<transfer_destination> destinations;
      uint64_t fee;
      uint64_t mixin;
      uint64_t unlock_time;
      std::string payment_id;

      void serialize(ISerializer& s) {
        KV_MEMBER(destinations)
        KV_MEMBER(fee)
        KV_MEMBER(mixin)
        KV_MEMBER(unlock_time)
        KV_MEMBER(payment_id)
      }
    };

    struct response
    {
      std::string transaction_hash;
      std::string transaction_private_key;                

      void serialize(ISerializer& s) {
        KV_MEMBER(transaction_hash)
        KV_MEMBER(transaction_private_key)             
      }
    };
  };

  struct COMMAND_RPC_STORE
  {
    typedef CryptoNote::EMPTY_STRUCT request;
    typedef CryptoNote::EMPTY_STRUCT response;
  };

  struct payment_details
  {
    std::string transaction_hash;
    uint64_t amount;
    uint64_t block_height;
    uint64_t unlock_time;

    void serialize(ISerializer& s) {
      KV_MEMBER(transaction_hash)
      KV_MEMBER(amount)
      KV_MEMBER(block_height)
      KV_MEMBER(unlock_time)
    }
  };

  struct COMMAND_RPC_GET_PAYMENTS
  {
    struct request
    {
      std::string payment_id;

      void serialize(ISerializer& s) {
        KV_MEMBER(payment_id)
      }
    };

    struct response
    {
      std::list<payment_details> payments;

      void serialize(ISerializer& s) {
        KV_MEMBER(payments)
      }
    };
  };

  struct Transfer {
    uint64_t timestamp;
    bool output;
    std::string transaction_hash;
    uint64_t amount;
    uint64_t fee;
    std::string payment_id;
    std::string address;
    uint64_t block_height;
    uint64_t unlock_time;
    std::string transaction_private_key;                     

    void serialize(ISerializer& s) {
      KV_MEMBER(timestamp)
      KV_MEMBER(output)
      KV_MEMBER(transaction_hash)
      KV_MEMBER(amount)
      KV_MEMBER(fee)
      KV_MEMBER(payment_id)
      KV_MEMBER(address)
      KV_MEMBER(block_height)
      KV_MEMBER(unlock_time)
      KV_MEMBER(transaction_private_key)
    }
  };

  struct COMMAND_RPC_GET_TRANSFERS {
    typedef CryptoNote::EMPTY_STRUCT request;

    struct response {
      std::list<Transfer> transfers;

      void serialize(ISerializer& s) {
        KV_MEMBER(transfers)
      }
    };
  };

  struct COMMAND_RPC_GET_HEIGHT {
    typedef CryptoNote::EMPTY_STRUCT request;

    struct response {
      uint64_t height;

      void serialize(ISerializer& s) {
        KV_MEMBER(height)
      }
    };
  };

	struct COMMAND_RPC_GET_TX_PRIVATE_KEY
	{
		struct request
		{
			std::string transaction_hash;

			void serialize(ISerializer& s)
			{
				KV_MEMBER(transaction_hash)
			}
		};
		struct response
		{
			std::string transaction_private_key;

			void serialize(ISerializer& s)
			{
				KV_MEMBER(transaction_private_key)
			}
		};
	};

  struct COMMAND_RPC_RESET {
    typedef CryptoNote::EMPTY_STRUCT request;
    typedef CryptoNote::EMPTY_STRUCT response;
  };

  struct COMMAND_RPC_GET_ADDRESS
  {
    typedef CryptoNote::EMPTY_STRUCT request;

    struct response
    {
      std::string address;

      void serialize(ISerializer& s) {
        KV_MEMBER(address)
      }
    };
  };

  struct COMMAND_RPC_GET_VIEW_PRIVATE_KEY
  {
    typedef CryptoNote::EMPTY_STRUCT request;

    struct response
    {
      std::string view_private_key;

      void serialize(ISerializer& s) {
        KV_MEMBER(view_private_key)
      }
    };
  };

  struct COMMAND_RPC_GET_SPEND_PRIVATE_KEY
  {
    typedef CryptoNote::EMPTY_STRUCT request;

    struct response
    {
      std::string spend_private_key;

      void serialize(ISerializer& s) {
        KV_MEMBER(spend_private_key)
      }
    };
  };

} // end namespace wallet_rpc

} // end namespace Tools

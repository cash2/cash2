// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PaymentServiceJsonRpcMessages.h"
#include "Serialization/SerializationOverloads.h"

namespace PaymentService {

void Reset::Request::serialize(CryptoNote::ISerializer& serializer) {
  serializer(view_private_key, "view_private_key");
}

void Reset::Response::serialize(CryptoNote::ISerializer& serializer) {
}

void GetViewKey::Request::serialize(CryptoNote::ISerializer& serializer) {
}

void GetViewKey::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(view_private_key, "view_private_key");
}

void GetStatus::Request::serialize(CryptoNote::ISerializer& serializer) {
}

void GetStatus::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(block_count, "block_count");
  serializer(known_block_count, "known_block_count");
  serializer(last_block_hash, "last_block_hash");
  serializer(peer_count, "peer_count");
}

void GetAddresses::Request::serialize(CryptoNote::ISerializer& serializer) {
}

void GetAddresses::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(addresses, "addresses");
}

void GetAddressesCount::Request::serialize(CryptoNote::ISerializer& serializer) {
}

void GetAddressesCount::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(addresses_count, "addresses_count");
}

void CreateAddress::Request::serialize(CryptoNote::ISerializer& serializer) {
  bool hasSecretKey = serializer(spend_private_key, "spend_private_key");
  bool hasPublicKey = serializer(spend_public_key, "spend_public_key");

  if (hasSecretKey && hasPublicKey) {
    //TODO: replace it with error codes
    throw RequestSerializationError();
  }
}

void CreateAddress::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(address, "address");
}

void DeleteAddress::Request::serialize(CryptoNote::ISerializer& serializer) {
  if (!serializer(address, "address")) {
    throw RequestSerializationError();
  }
}

void DeleteAddress::Response::serialize(CryptoNote::ISerializer& serializer) {
}

void GetSpendKeys::Request::serialize(CryptoNote::ISerializer& serializer) {
  if (!serializer(address, "address")) {
    throw RequestSerializationError();
  }
}

void GetSpendKeys::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(spend_private_key, "spend_private_key");
  serializer(spend_public_key, "spend_public_key");
}

void GetBalance::Request::serialize(CryptoNote::ISerializer& serializer) {
  serializer(address, "address");
}

void GetBalance::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(available_balance, "available_balance");
  serializer(locked_amount, "locked_amount");
}

void GetBlockHashes::Request::serialize(CryptoNote::ISerializer& serializer) {
  bool r = serializer(first_block_index, "first_block_index");
  r &= serializer(block_count, "block_count");

  if (!r) {
    throw RequestSerializationError();
  }
}

void GetBlockHashes::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(block_hashes, "block_hashes");
}

void TransactionHashesInBlockRpcInfo::serialize(CryptoNote::ISerializer& serializer) {
  serializer(block_hash, "block_hash");
  serializer(transaction_hashes, "transaction_hashes");
}

void GetTransactionHashes::Request::serialize(CryptoNote::ISerializer& serializer) {
  serializer(addresses, "addresses");

  if (serializer(block_hash, "block_hash") == serializer(first_block_index, "first_block_index")) {
    throw RequestSerializationError();
  }

  if (!serializer(block_count, "block_count")) {
    throw RequestSerializationError();
  }

  serializer(payment_id, "payment_id");
}

void GetTransactionHashes::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(items, "items");
}

void TransferRpcInfo::serialize(CryptoNote::ISerializer& serializer) {
  serializer(type, "type");
  serializer(address, "address");
  serializer(amount, "amount");
}

void TransactionRpcInfo::serialize(CryptoNote::ISerializer& serializer) {
  serializer(state, "state");
  serializer(transaction_hash, "transaction_hash");
  serializer(block_height, "block_height");
  serializer(timestamp, "timestamp");
  serializer(is_base, "is_base");
  serializer(unlock_time, "unlock_time");
  serializer(amount, "amount");
  serializer(fee, "fee");
  serializer(transfers, "transfers");
  serializer(extra, "extra");
  serializer(payment_id, "payment_id");
}

void GetTransaction::Request::serialize(CryptoNote::ISerializer& serializer) {
  if (!serializer(transaction_hash, "transaction_hash")) {
    throw RequestSerializationError();
  }
}

void GetTransaction::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(transaction, "transaction");
}

void TransactionsInBlockRpcInfo::serialize(CryptoNote::ISerializer& serializer) {
  serializer(block_hash, "block_hash");
  serializer(transactions, "transactions");
}

void GetTransactions::Request::serialize(CryptoNote::ISerializer& serializer) {
  serializer(addresses, "addresses");

  if (serializer(block_hash, "block_hash") == serializer(first_block_index, "first_block_index")) {
    throw RequestSerializationError();
  }

  if (!serializer(block_count, "block_count")) {
    throw RequestSerializationError();
  }

  serializer(payment_id, "payment_id");
}

void GetTransactions::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(items, "items");
}

void GetUnconfirmedTransactionHashes::Request::serialize(CryptoNote::ISerializer& serializer) {
  serializer(addresses, "addresses");
}

void GetUnconfirmedTransactionHashes::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(transaction_hashes, "transaction_hashes");
}

void WalletRpcOrder::serialize(CryptoNote::ISerializer& serializer) {
  bool r = serializer(address, "address");
  r &= serializer(amount, "amount");

  if (!r) {
    throw RequestSerializationError();
  }
}

void SendTransaction::Request::serialize(CryptoNote::ISerializer& serializer) {
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

void SendTransaction::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(transaction_hash, "transaction_hash");
  serializer(transaction_private_key, "transaction_private_key");                                                         
}

void CreateDelayedTransaction::Request::serialize(CryptoNote::ISerializer& serializer) {
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

void CreateDelayedTransaction::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(transaction_hash, "transaction_hash");
}

void GetDelayedTransactionHashes::Request::serialize(CryptoNote::ISerializer& serializer) {
}

void GetDelayedTransactionHashes::Response::serialize(CryptoNote::ISerializer& serializer) {
  serializer(transaction_hashes, "transaction_hashes");
}

void DeleteDelayedTransaction::Request::serialize(CryptoNote::ISerializer& serializer) {
  if (!serializer(transaction_hash, "transaction_hash")) {
    throw RequestSerializationError();
  }
}

void DeleteDelayedTransaction::Response::serialize(CryptoNote::ISerializer& serializer) {
}

void SendDelayedTransaction::Request::serialize(CryptoNote::ISerializer& serializer) {
  if (!serializer(transaction_hash, "transaction_hash")) {
    throw RequestSerializationError();
  }
}

void SendDelayedTransaction::Response::serialize(CryptoNote::ISerializer& serializer) {
}

}

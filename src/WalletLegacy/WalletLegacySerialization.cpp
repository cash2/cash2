// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018, Karbo developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletLegacySerialization.h"
#include "WalletLegacy/WalletUnconfirmedTransactions.h"
#include "IWalletLegacy.h"
#include "WalletLegacy/WalletLegacySerializer.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include "Serialization/ISerializer.h"
#include "Serialization/SerializationOverloads.h"

namespace CryptoNote {

void serialize(UnconfirmedTransferDetails& utd, ISerializer& serializer) {
  serializer(utd.tx, "transaction");
  serializer(utd.amount, "amount");
  serializer(utd.outsAmount, "outs_amount");
  uint64_t time = static_cast<uint64_t>(utd.sentTime);
  serializer(time, "sent_time");
  utd.sentTime = static_cast<time_t>(time);
  uint64_t transactionIndex = static_cast<uint64_t>(utd.transactionIndex);
  serializer(transactionIndex, "transaction_index");
  utd.transactionIndex = static_cast<size_t>(transactionIndex);
  if (WALLET_LEGACY_SERIALIZATION_VERSION >= 2)
  {
    serializer(utd.secretKey, "secret_key");
  }                                                         
}

void serialize(WalletLegacyTransaction& txi, ISerializer& serializer) {
  uint64_t trId = static_cast<uint64_t>(txi.firstTransferId);
  serializer(trId, "first_transfer_id");
  txi.firstTransferId = static_cast<size_t>(trId);

  uint64_t trCount = static_cast<uint64_t>(txi.transferCount);
  serializer(trCount, "transfer_count");
  txi.transferCount = static_cast<size_t>(trCount);

  serializer(txi.totalAmount, "total_amount");

  serializer(txi.fee, "fee");
  serializer(txi.hash, "hash");
  serializer(txi.isCoinbase, "is_coinbase");

  serializeBlockHeight(serializer, txi.blockIndex, "block_index");

  serializer(txi.timestamp, "timestamp");
  serializer(txi.unlockTime, "unlock_time");
  serializer(txi.extra, "extra");

  if (WALLET_LEGACY_SERIALIZATION_VERSION >= 2) {
    Crypto::SecretKey secretKey = reinterpret_cast<const Crypto::SecretKey&>(txi.secretKey.get());
    serializer(secretKey, "secret_key");
    txi.secretKey = secretKey;
  }    
                                                       
  //this field has been added later in the structure.
  //in order to not break backward binary compatibility
  // we just set it to zero
  txi.sentTime = 0;
}

void serialize(WalletLegacyTransfer& tr, ISerializer& serializer) {
  serializer(tr.address, "address");
  serializer(tr.amount, "amount");
}

} //namespace CryptoNote

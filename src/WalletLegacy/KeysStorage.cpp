// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "KeysStorage.h"

#include "WalletLegacy/WalletLegacySerialization.h"
#include "Serialization/ISerializer.h"
#include "Serialization/SerializationOverloads.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"

namespace CryptoNote {

void KeysStorage::serialize(ISerializer& serializer, const std::string& name) {
  serializer.beginObject(name);

  serializer(creationTimestamp, "creation_timestamp");

  serializer(spendPublicKey, "spend_public_key");
  serializer(spendSecretKey, "spend_secret_key");

  serializer(viewPublicKey, "view_public_key");
  serializer(viewSecretKey, "view_secret_key");

  serializer.endObject();
}

void KeysStorage::deserialize(ISerializer& deserializer, const std::string& name) {
  deserializer.beginObject(name);

  deserializer(creationTimestamp, "creation_timestamp");

  deserializer(spendPublicKey, "spend_public_key");
  deserializer(spendSecretKey, "spend_secret_key");

  deserializer(viewPublicKey, "view_public_key");
  deserializer(viewSecretKey, "view_secret_key");

  deserializer.endObject();
}

}

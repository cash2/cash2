// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Copyright (c) 2016-2018, The Karbowanec developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <system_error>

namespace CryptoNote {
namespace error {

// custom error conditions enum type:
enum WalletErrorCodes {
  NOT_INITIALIZED = 1,
  ALREADY_INITIALIZED,
  WRONG_STATE,
  WRONG_PASSWORD,
  INTERNAL_WALLET_ERROR,
  MIXIN_COUNT_TOO_BIG,
  BAD_ADDRESS,
  TRANSACTION_SIZE_TOO_BIG,
  WRONG_AMOUNT,
  SUM_OVERFLOW,
  ZERO_DESTINATION,
  TX_CANCEL_IMPOSSIBLE,
  TX_CANCELLED,
  OPERATION_CANCELLED,
  TX_TRANSFER_IMPOSSIBLE,
  WRONG_VERSION,
  FEE_TOO_SMALL,
  KEY_GENERATION_ERROR,
  INDEX_OUT_OF_RANGE,
  ADDRESS_ALREADY_EXISTS,
  TRACKING_MODE,
  WRONG_PARAMETERS,
  OBJECT_NOT_FOUND,
  WALLET_NOT_FOUND,
  CHANGE_ADDRESS_REQUIRED,
  CHANGE_ADDRESS_NOT_FOUND,
  EXTRA_TOO_LARGE,
};

// custom category:
class WalletErrorCategory : public std::error_category {
public:
  static WalletErrorCategory INSTANCE;

  virtual const char* name() const throw() override {
    return "WalletErrorCategory";
  }

  virtual std::error_condition default_error_condition(int ev) const throw() override {
    return std::error_condition(ev, *this);
  }

  virtual std::string message(int ev) const override {
    switch (ev) {
    case ADDRESS_ALREADY_EXISTS:   return "Address already exists";
    case ALREADY_INITIALIZED:      return "The object is already initialized";
    case BAD_ADDRESS:              return "Bad address";
    case CHANGE_ADDRESS_NOT_FOUND: return "Change address not found";
    case CHANGE_ADDRESS_REQUIRED:  return "Change address required";
    case EXTRA_TOO_LARGE:          return "Transaction extra too large";
    case FEE_TOO_SMALL:            return "Transaction fee is too small";
    case INDEX_OUT_OF_RANGE:       return "Index is out of range";
    case INTERNAL_WALLET_ERROR:    return "Internal error occurred";
    case KEY_GENERATION_ERROR:     return "Cannot generate new key";
    case MIXIN_COUNT_TOO_BIG:      return "MixIn count is too big";
    case NOT_INITIALIZED:          return "Object was not initialized";
    case OBJECT_NOT_FOUND:         return "Object not found";
    case OPERATION_CANCELLED:      return "The operation you've requested has been cancelled";
    case SUM_OVERFLOW:             return "Sum overflow";
    case TRACKING_MODE:            return "The wallet is in tracking mode";
    case TRANSACTION_SIZE_TOO_BIG: return "Transaction size is too big";
    case TX_CANCEL_IMPOSSIBLE:     return "Impossible to cancel transaction";
    case TX_TRANSFER_IMPOSSIBLE:   return "Transaction transfer impossible";
    case WALLET_NOT_FOUND:         return "Requested wallet not found";
    case WRONG_AMOUNT:             return "Wrong amount";
    case WRONG_PARAMETERS:         return "Wrong parameters passed";
    case WRONG_PASSWORD:           return "The wallet container password is incorrect";
    case WRONG_STATE:              return "The wallet is in wrong state (maybe loading or saving), try again later";
    case WRONG_VERSION:            return "Wrong version";
    case ZERO_DESTINATION:         return "The destination is empty";
    default:                       return "Unknown error";
    }
  }

private:
  WalletErrorCategory() {
  }
};

}
}

inline std::error_code make_error_code(CryptoNote::error::WalletErrorCodes e) {
  return std::error_code(static_cast<int>(e), CryptoNote::error::WalletErrorCategory::INSTANCE);
}

namespace std {

template <>
struct is_error_code_enum<CryptoNote::error::WalletErrorCodes>: public true_type {};

}

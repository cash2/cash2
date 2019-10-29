// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2019 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <system_error>

namespace CryptoNote {

namespace error {

enum class WalletHelperErrorCode
{
  WRONG_KEY_FORMAT = 1,
  WRONG_PAYMENT_ID_FORMAT,
  WRONG_HASH_FORMAT,
  OBJECT_NOT_FOUND
};

class WalletHelperErrors : public std::error_category {

public :

  static WalletHelperErrors INSTANCE;

  virtual const char* name() const throw() override
  {
    return "WalletHelperErrors";
  }

  virtual std::error_condition default_error_condition(int ev) const throw() override
  {
    return std::error_condition(ev, *this);
  }

  virtual std::string message(int ev) const override
  {
    WalletHelperErrorCode code = static_cast<WalletHelperErrorCode>(ev);

    switch (code)
    {
      case WalletHelperErrorCode::WRONG_KEY_FORMAT:
        return "Wrong key format";
      case WalletHelperErrorCode::WRONG_PAYMENT_ID_FORMAT:
        return "Wrong payment id format";
      case WalletHelperErrorCode::WRONG_HASH_FORMAT:
        return "Wrong block id format";
      case WalletHelperErrorCode::OBJECT_NOT_FOUND:
        return "Requested object not found";
      default:
        return "Unknown error";
    }
  }

private :

  WalletHelperErrors() {
  }

};

} // end namespace error

} // end namespace CryptoNote

inline std::error_code make_error_code(CryptoNote::error::WalletHelperErrorCode e)
{
  return std::error_code(static_cast<int>(e), CryptoNote::error::WalletHelperErrors::INSTANCE);
}

namespace std {

template <>
struct is_error_code_enum<CryptoNote::error::WalletHelperErrorCode>: public true_type {};

} // end namespace std

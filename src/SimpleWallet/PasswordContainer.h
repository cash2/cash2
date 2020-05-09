// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

namespace Tools
{
  class PasswordContainer
  {
  public:
    static const size_t max_password_size = 1024;

    PasswordContainer();
    PasswordContainer(std::string&& password);
    PasswordContainer(PasswordContainer&& rhs);
    ~PasswordContainer();

    void clear();
    void clear_confirm_password();
    bool empty() const { return m_empty; }
    const std::string& password() const { return m_password; }
    void password(std::string val) { m_password = val; m_empty = false; }
    bool read_password();
    bool read_confirm_password();
    bool passwords_match();

  private:
    bool read_from_file();
    bool read_password_from_tty();
    bool read_confirm_password_from_tty();

  private:
    bool m_empty;
    std::string m_password;
    std::string m_confirm_password;
  };
}

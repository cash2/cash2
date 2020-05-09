// Copyright (c) 2011-2016 The Cryptonote developers
// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StdOutputStream.h"

namespace Common {

StdOutputStream::StdOutputStream(std::ostream& out) : m_outputStream(out) {
}

size_t StdOutputStream::writeSome(const void* data, size_t size) {
  m_outputStream.write(static_cast<const char*>(data), size);
  if (m_outputStream.bad()) {
    return 0;
  }

  return size;
}

}

// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Http/HttpRequest.h"

/*

My Notes

class HttpRequest 
public
  getMethod()
  getUrl()
  getHeaders()
  getBody()
  addHeader()
  setBody()
  setUrl()

*/

using namespace CryptoNote;

// constructor
TEST(HttpRequest, 1)
{
  HttpRequest();
}

// getMethod()
TEST(HttpRequest, 2)
{
  const HttpRequest httpRequest;
  ASSERT_EQ("", httpRequest.getMethod());
}

// setUrl()
TEST(HttpRequest, 3)
{
  HttpRequest httpRequest;
  httpRequest.setUrl("myUrl");
}

// getUrl()
TEST(HttpRequest, 4)
{
  HttpRequest httpRequest;
  httpRequest.setUrl("myUrl");
  ASSERT_EQ("myUrl", httpRequest.getUrl());
}

// addHeader()
TEST(HttpRequest, 5)
{
  HttpRequest httpRequest;

  std::string name = "myName";
  std::string value = "myValue";
  httpRequest.addHeader(name, value);
}

// getHeaders()
TEST(HttpRequest, 6)
{
  HttpRequest httpRequest;

  std::string name = "myName";
  std::string value = "myValue";
  httpRequest.addHeader(name, value);

  HttpRequest::Headers headers = httpRequest.getHeaders();
  ASSERT_EQ("myValue", headers["myName"]);
}

// setBody()
TEST(HttpRequest, 7)
{
  HttpRequest httpRequest;

  std::string body = "Hello World";
  httpRequest.setBody(body);
}

// getBody()
TEST(HttpRequest, 8)
{
  HttpRequest httpRequest;

  std::string body = "Hello World";
  httpRequest.setBody(body);

  ASSERT_EQ("Hello World", httpRequest.getBody());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
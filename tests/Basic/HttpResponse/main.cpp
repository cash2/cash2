// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Http/HttpResponse.h"

/*

My Notes

class HttpResponse
public
  HttpResponse()
  setStatus()
  addHeader()
  setBody()
  getHeaders()
  getStatus()
  getBody()

*/

using namespace CryptoNote;

// constructor
TEST(HttpResponse, 1)
{
  HttpResponse();
}

// setStatus()
TEST(HttpResponse, 2)
{
  HttpResponse httpResponse;

  httpResponse.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
  httpResponse.setStatus(HttpResponse::HTTP_STATUS::STATUS_404);
  httpResponse.setStatus(HttpResponse::HTTP_STATUS::STATUS_500);
}

// getStatus()
TEST(HttpResponse, 3)
{
  HttpResponse httpResponse;

  httpResponse.setStatus(HttpResponse::HTTP_STATUS::STATUS_200);
  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_200, httpResponse.getStatus());

  httpResponse.setStatus(HttpResponse::HTTP_STATUS::STATUS_404);
  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_404, httpResponse.getStatus());

  httpResponse.setStatus(HttpResponse::HTTP_STATUS::STATUS_500);
  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_500, httpResponse.getStatus());
}

// addHeader()
TEST(HttpResponse, 4)
{
  HttpResponse httpResponse;

  std::string name = "myName";
  std::string value = "myValue";
  httpResponse.addHeader(name, value);
}

// getHeaders()
TEST(HttpResponse, 5)
{
  HttpResponse httpResponse;

  std::string name = "myName";
  std::string value = "myValue";
  httpResponse.addHeader(name, value);

  std::map<std::string, std::string> headers = httpResponse.getHeaders();
  ASSERT_EQ("myValue", headers["myName"]);
}

// setBody()
TEST(HttpResponse, 6)
{
  HttpResponse httpResponse;

  std::string body = "Hello World";
  httpResponse.setBody(body);
}

// getBody()
TEST(HttpResponse, 7)
{
  HttpResponse httpResponse;

  std::string body = "Hello World";
  httpResponse.setBody(body);

  ASSERT_EQ("Hello World", httpResponse.getBody());
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
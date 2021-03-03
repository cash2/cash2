// Copyright (c) 2018-2021 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Http/HttpParser.h"

/*

My Notes

class HttpParser
public
  HttpParser()
  receiveRequest()
  receiveResponse()
  parseResponseStatusFromString()

*/

using namespace CryptoNote;

// constructor
TEST(HttpParser, 1)
{
  HttpParser();
}

// receiveRequest
TEST(HttpParser, 2)
{
  HttpParser httpParser;
  std::string str =  "myMethod myUrl myVersion myHeaderName1:myHeaderValue1\r\nmyHeaderName2:myHeaderValue2\r\nContent-Length:49\r\n\r\nmyBodyName1=myBodyValue1&myBodyName2=myBodyValue2";
  std::stringstream ss;
  ss << str;
  HttpRequest httpRequest;

  httpParser.receiveRequest(ss, httpRequest);

  ASSERT_EQ("myMethod", httpRequest.getMethod());
  ASSERT_EQ("myUrl", httpRequest.getUrl());
  ASSERT_EQ("myBodyName1=myBodyValue1&myBodyName2=myBodyValue2", httpRequest.getBody());

  HttpRequest::Headers headers = httpRequest.getHeaders();
  ASSERT_EQ("myHeaderValue1", headers["myheadername1"]);
  ASSERT_EQ("myHeaderValue2", headers["myheadername2"]);
}

// receiveResponse()
TEST(HttpParser, 3)
{
  HttpParser httpParser;
  std::string str =  "HTTP/1.1 200 OK\r\nmyHeaderName1:myHeaderValue1\r\nmyHeaderName2:myHeaderValue2\r\nContent-Length:49\r\n\r\nmyBodyName1=myBodyValue1&myBodyName2=myBodyValue2";
  std::stringstream ss;
  ss << str;
  HttpResponse httpResponse;

  httpParser.receiveResponse(ss, httpResponse);

  // status
  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_200, httpResponse.getStatus());

  // headers
  std::map<std::string, std::string> headers = httpResponse.getHeaders();
  ASSERT_EQ("myHeaderValue1", headers["myheadername1"]);
  ASSERT_EQ("myHeaderValue2", headers["myheadername2"]);

  // body
  ASSERT_EQ("myBodyName1=myBodyValue1&myBodyName2=myBodyValue2", httpResponse.getBody());
}

// parseResponseStatusFromString()
TEST(HttpParser, 4)
{
  HttpParser httpParser;

  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_200, httpParser.parseResponseStatusFromString("200 OK"));
  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_200, httpParser.parseResponseStatusFromString("200 Ok"));
  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_404, httpParser.parseResponseStatusFromString("404 Not Found"));
  ASSERT_EQ(HttpResponse::HTTP_STATUS::STATUS_500, httpParser.parseResponseStatusFromString("500 Internal Server Error"));
  ASSERT_ANY_THROW(httpParser.parseResponseStatusFromString("Hello World"));
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
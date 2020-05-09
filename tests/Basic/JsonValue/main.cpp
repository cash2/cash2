// Copyright (c) 2018-2020 The Cash2 developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include "Common/JsonValue.h"

/*

My Notes

class JsonValue
public
  JsonValue()
  JsonValue(JsonValue)
  JsonValue(JsonValue&&)
  JsonValue(Type)
  JsonValue(Array)
  JsonValue(Array&&)
  JsonValue(Bool)
  JsonValue(Integer)
  JsonValue(Nil)
  JsonValue(Object)
  JsonValue(Object&&)
  JsonValue(Real)
  JsonValue(String)
  JsonValue(String&&)
  JsonValue()
  ~JsonValue()
  operator=(JsonValue)
  operator=(JsonValue&&)
  operator=(Array)
  operator=(Array)
  operator=(Integer)
  operator=(Nil)
  operator=(Object)
  operator=(Object&&)
  operator=(Real)
  operator=(String)
  operator=(String)
  operator=()
  isArray()
  isBool()
  isInteger()
  isNil()
  isObject()
  isReal()
  isString()
  getType()
  getArray()
  getArray const()
  getBool()
  getInteger()
  getObject()
  getObject const()
  getReal()
  getString()
  getString const()
  size()
  operator[]
  operator[]
  pushBack()
  pushBack()
  operator()
  operator()
  contains()
  insert()
  insert()
  set()
  set()
  erase()
  fromString()
  toString()
  operator<<()
  operator>>()

*/

using namespace Common;

// JsonValue()
TEST(JsonValue, 1)
{
  JsonValue();
}

// JsonValue(JsonValue)
TEST(JsonValue, 2)
{
  JsonValue jsonValue1;

  JsonValue jsonValue2(jsonValue1);
}

// JsonValue(JsonValue&&)
TEST(JsonValue, 3)
{
  JsonValue jsonValue1;

  JsonValue jsonValue2(std::move(jsonValue1));
}

// JsonValue(Type)
TEST(JsonValue, 4)
{
  JsonValue jsonValue1(JsonValue::Type::ARRAY);
  JsonValue jsonValue2(JsonValue::Type::NIL);
  JsonValue jsonValue3(JsonValue::Type::OBJECT);
  JsonValue jsonValue4(JsonValue::Type::STRING);
}

// JsonValue(Array)
TEST(JsonValue, 5)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(arr);
}

// JsonValue(Array&&)
TEST(JsonValue, 6)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(std::move(arr));
}

// JsonValue(Bool)
TEST(JsonValue, 7)
{
  JsonValue::Bool b = true;
  JsonValue jsonValue(b);
}

// JsonValue(Integer)
TEST(JsonValue, 8)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue(i);
}

// JsonValue(Nil)
TEST(JsonValue, 9)
{
  JsonValue::Nil n = nullptr;
  JsonValue jsonValue(n);
}

// JsonValue(Object)
TEST(JsonValue, 10)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  JsonValue::Object o;
  o.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2(o);
}

// JsonValue(Object)
TEST(JsonValue, 11)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  JsonValue::Object o;
  o.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2(std::move(o));
}

// JsonValue(Real)
TEST(JsonValue, 12)
{
  JsonValue::Real r = 1.0;
  JsonValue jsonValue(r);
}

// JsonValue(String)
TEST(JsonValue, 13)
{
  JsonValue::String s = "Hello";
  JsonValue jsonValue(s);
}

// JsonValue(String&&)
TEST(JsonValue, 14)
{
  JsonValue::String s = "Hello";
  JsonValue jsonValue(std::move(s));
}

// JsonValue(String)
TEST(JsonValue, 15)
{
  JsonValue jsonValue("Hello");
}

// operator=(JsonValue)
TEST(JsonValue, 16)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  i = 2;
  JsonValue jsonValue2(i);

  JsonValue jsonValue3("Hello");

  jsonValue1 = jsonValue2;
  jsonValue1 = jsonValue3;
}

// operator=(JsonValue&&)
TEST(JsonValue, 17)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  i = 2;
  JsonValue jsonValue2(i);

  JsonValue jsonValue3("Hello");

  jsonValue1 = std::move(jsonValue2);
  jsonValue1 = std::move(jsonValue3);
}

// operator=(Array)
TEST(JsonValue, 18)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue::Integer i = 1;
  JsonValue jsonValue4(i);

  JsonValue jsonValue5 = arr;
  
  jsonValue4 = arr;
}

// operator=(Array&&)
TEST(JsonValue, 19)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue::Integer i = 1;
  JsonValue jsonValue4(i);

  JsonValue jsonValue5 = std::move(arr);
  
  jsonValue4 = std::move(arr);
}

// operator=(Integer)
TEST(JsonValue, 20)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1 = i;

  JsonValue jsonValue2("Hello");
  jsonValue2 = i;
}

// operator=(Nil)
TEST(JsonValue, 21)
{
  JsonValue::Nil n = nullptr;
  JsonValue jsonValue1 = n;

  JsonValue::Integer i = 1;
  JsonValue jsonValue2 = i;

  jsonValue2 = n;
}

// operator=(Object)
TEST(JsonValue, 22)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  JsonValue::Object o;
  o.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2(o);

  JsonValue jsonValue3("Hello");
  jsonValue3 = o;
}

// operator=(Object&&)
TEST(JsonValue, 23)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  JsonValue::Object o;
  o.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2(o);

  JsonValue jsonValue3("Hello");
  jsonValue3 = std::move(o);
}

// operator=(Real)
TEST(JsonValue, 24)
{
  JsonValue::Real r = 1.0;
  JsonValue jsonValue1 = r;

  JsonValue jsonValue2("Hello");
  jsonValue2 = r;
}

// JsonValue(String)
TEST(JsonValue, 25)
{
  JsonValue::String s = "Hello";
  JsonValue jsonValue1 = s;

  JsonValue::Integer i = 1;
  JsonValue jsonValue2(i);

  jsonValue2 = s;
}

// JsonValue(String&&)
TEST(JsonValue, 26)
{
  JsonValue::String s = "Hello";
  JsonValue jsonValue1 = std::move(s);

  JsonValue::Integer i = 1;
  JsonValue jsonValue2(i);

  jsonValue2 = std::move(s);
}

// JsonValue(String)
TEST(JsonValue, 27)
{
  JsonValue jsonValue1 = "Hello";

  JsonValue::Integer i = 1;
  JsonValue jsonValue2(i);

  jsonValue2 = "Hello";
}

// isArray()
TEST(JsonValue, 28)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(arr);

  JsonValue jsonValue5 = "Hello";

  ASSERT_TRUE(jsonValue4.isArray());
  ASSERT_FALSE(jsonValue5.isArray());
}

// isBool()
TEST(JsonValue, 29)
{
  JsonValue::Bool b = true;
  JsonValue jsonValue1(b);
  JsonValue jsonValue2 = "Hello";

  ASSERT_TRUE(jsonValue1.isBool());
  ASSERT_FALSE(jsonValue2.isBool());
}

// isInteger()
TEST(JsonValue, 30)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  JsonValue jsonValue2 = "Hello";

  ASSERT_TRUE(jsonValue1.isInteger());
  ASSERT_FALSE(jsonValue2.isInteger());
}

// isNil()
TEST(JsonValue, 31)
{
  JsonValue jsonValue1 = nullptr;
  JsonValue jsonValue2 = "Hello";

  ASSERT_TRUE(jsonValue1.isNil());
  ASSERT_FALSE(jsonValue2.isNil());
}

// isObject()
TEST(JsonValue, 32)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  JsonValue::Object o;
  o.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2(o);

  JsonValue jsonValue3("Hello");

  ASSERT_FALSE(jsonValue1.isObject());
  ASSERT_TRUE(jsonValue2.isObject());
  ASSERT_FALSE(jsonValue3.isObject());
}

// isReal()
TEST(JsonValue, 33)
{
  JsonValue::Real r = 1.0;
  JsonValue jsonValue1 = r;

  JsonValue jsonValue2("Hello");
  
  ASSERT_TRUE(jsonValue1.isReal());
  ASSERT_FALSE(jsonValue2.isReal());
}

// isString()
TEST(JsonValue, 34)
{
  JsonValue::String s = "Hello";
  JsonValue jsonValue1 = s;

  JsonValue::Integer i = 1;
  JsonValue jsonValue2(i);

  ASSERT_TRUE(jsonValue1.isString());
  ASSERT_FALSE(jsonValue2.isString());
}

// getType()
TEST(JsonValue, 35)
{
  JsonValue::String s = "Hello";
  JsonValue jsonValue1 = s;

  JsonValue::Type type = jsonValue1.getType();

  ASSERT_EQ(JsonValue::Type::STRING, type);
}

// getArray()
TEST(JsonValue, 36)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(arr);

  JsonValue::Array arrRet = jsonValue4.getArray();
}

// getArray const()
TEST(JsonValue, 37)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  const JsonValue jsonValue4(arr);

  JsonValue::Array arrRet = jsonValue4.getArray();
}

// getBool()
TEST(JsonValue, 38)
{
  JsonValue::Bool b1 = true;
  JsonValue jsonValue(b1);

  JsonValue::Bool b2 = jsonValue.getBool();

  ASSERT_EQ(b1, b2);
}

// getInteger()
TEST(JsonValue, 39)
{
  JsonValue::Integer i1 = 10;
  JsonValue jsonValue(i1);

  JsonValue::Integer i2 = jsonValue.getInteger();

  ASSERT_EQ(i1, i2);
}

// getObject()
TEST(JsonValue, 40)
{
  JsonValue::Integer i1 = 1;
  JsonValue jsonValue1(i1);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2 = o1;

  JsonValue::Object o2 = jsonValue2.getObject();

  JsonValue jsonValue3 = o2["jsonValue1"];
  JsonValue::Integer i2 = jsonValue3.getInteger();
  ASSERT_EQ(i1, i2);
}

// getObject const()
TEST(JsonValue, 41)
{
  JsonValue::Integer i1 = 1;
  JsonValue jsonValue1(i1);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);

  const JsonValue jsonValue2 = o1;

  JsonValue::Object o2 = jsonValue2.getObject();

  JsonValue jsonValue3 = o2["jsonValue1"];
  JsonValue::Integer i2 = jsonValue3.getInteger();
  ASSERT_EQ(i1, i2);
}

// getReal()
TEST(JsonValue, 42)
{
  JsonValue::Real r1 = 1.0;
  JsonValue jsonValue1 = r1;

  JsonValue::Real r2 = jsonValue1.getReal();
  
  ASSERT_EQ(r1, r2);
}

// getString()
TEST(JsonValue, 43)
{
  JsonValue::String s1 = "Hello";
  JsonValue jsonValue1 = s1;

  JsonValue::String s2 = jsonValue1.getString();

  ASSERT_EQ(s1, s2);
}

// getString const()
TEST(JsonValue, 44)
{
  JsonValue::String s1 = "Hello";
  const JsonValue jsonValue1 = s1;

  JsonValue::String s2 = jsonValue1.getString();

  ASSERT_EQ(s1, s2);
}

// size()
TEST(JsonValue, 45)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(arr);

  size_t size = jsonValue4.size();
  ASSERT_EQ(arr.size(), size);
}

// operator[]()
TEST(JsonValue, 46)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  i = 2;
  JsonValue jsonValue2(i);
  i = 3;
  JsonValue jsonValue3(i);

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(arr);

  JsonValue jsonValue5 = jsonValue4[0];

  ASSERT_EQ(jsonValue1.getInteger(), jsonValue5.getInteger());
}

// operator[] const()
TEST(JsonValue, 47)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  i = 2;
  JsonValue jsonValue2(i);
  i = 3;
  JsonValue jsonValue3(i);

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  const JsonValue jsonValue4(arr);

  size_t size = jsonValue4.size();
  ASSERT_EQ(arr.size(), size);

  JsonValue jsonValue5 = jsonValue4[0];

  ASSERT_EQ(jsonValue1.getInteger(), jsonValue5.getInteger());
}

// pushBack()
TEST(JsonValue, 48)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(arr);
  
  ASSERT_EQ(3, jsonValue4.size());

  JsonValue::Integer i = 1;
  JsonValue jsonValue5(i);

  JsonValue jsonValue6 = jsonValue4.pushBack(jsonValue5);

  ASSERT_EQ(4, jsonValue4.size());

  // jsonValue6 equals jsonValue5
  ASSERT_EQ(jsonValue5.getInteger(), jsonValue6.getInteger());
}

// pushBack()
TEST(JsonValue, 49)
{
  JsonValue jsonValue1;
  JsonValue jsonValue2;
  JsonValue jsonValue3;

  JsonValue::Array arr = {jsonValue1, jsonValue2, jsonValue3};

  JsonValue jsonValue4(arr);
  
  ASSERT_EQ(3, jsonValue4.size());

  JsonValue::Integer i = 1;
  JsonValue jsonValue5(i);

  JsonValue jsonValue5Copy = jsonValue5;

  JsonValue jsonValue6 = jsonValue4.pushBack(std::move(jsonValue5Copy));

  ASSERT_EQ(4, jsonValue4.size());

  // jsonValue6 equals jsonValue5
  ASSERT_EQ(jsonValue5.getInteger(), jsonValue6.getInteger());
}

// operator()
TEST(JsonValue, 50)
{
  JsonValue::Integer i1 = 1;
  JsonValue jsonValue1(i1);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2 = o1;

  JsonValue jsonValue3 = jsonValue2("jsonValue1");

  // jsonValue3 equals jsonValue1
  JsonValue::Integer i2 = jsonValue3.getInteger();
  ASSERT_EQ(i1, i2);
}

// operator const()
TEST(JsonValue, 51)
{
  JsonValue::Integer i1 = 1;
  JsonValue jsonValue1(i1);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);

  const JsonValue jsonValue2 = o1;

  JsonValue jsonValue3 = jsonValue2("jsonValue1");

  // jsonValue3 equals jsonValue1
  JsonValue::Integer i2 = jsonValue3.getInteger();
  ASSERT_EQ(i1, i2);
}

// contains()
TEST(JsonValue, 52)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2 = o1;

  ASSERT_TRUE(jsonValue2.contains("jsonValue1"));
}

// insert()
TEST(JsonValue, 53)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2 = o1;

  i = 2;
  JsonValue jsonValue3(i);

  jsonValue2.insert("jsonValue3", jsonValue3);
}

// insert(&&)
TEST(JsonValue, 54)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);

  JsonValue jsonValue2 = o1;

  i = 2;
  const JsonValue jsonValue3(i);

  jsonValue2.insert("jsonValue3", std::move(jsonValue3));
}

// set()
TEST(JsonValue, 55)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);
  JsonValue jsonValue3 = o1;

  i = 2;
  JsonValue jsonValue2(i);
  JsonValue::Object o2;
  o1.emplace("jsonValue2", jsonValue2);
  jsonValue3.set("jsonValue1", jsonValue2);

  JsonValue::Object o3 = jsonValue3.getObject();
  JsonValue jsonValue4 = o3["jsonValue1"];
  JsonValue::Integer iRet = jsonValue4.getInteger();
  ASSERT_EQ(2, iRet);
}

// set (&&)
TEST(JsonValue, 56)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);
  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);
  JsonValue jsonValue3 = o1;

  i = 2;
  const JsonValue jsonValue2(i);
  JsonValue::Object o2;
  o1.emplace("jsonValue2", jsonValue2);
  jsonValue3.set("jsonValue1", std::move(jsonValue2));

  JsonValue::Object o3 = jsonValue3.getObject();
  JsonValue jsonValue4 = o3["jsonValue1"];
  JsonValue::Integer iRet = jsonValue4.getInteger();
  ASSERT_EQ(2, iRet);
}

// erase()
TEST(JsonValue, 57)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  i = 2;
  JsonValue jsonValue2(i);

  JsonValue::Object o1;
  o1.emplace("jsonValue1", jsonValue1);
  o1.emplace("jsonValue2", jsonValue2);

  JsonValue jsonValue3 = o1;

  ASSERT_EQ(2, jsonValue3.size());

  jsonValue3.erase("jsonValue1");

  ASSERT_EQ(1, jsonValue3.size());
}

// toString()
TEST(JsonValue, 58)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  std::string jsonString = jsonValue1.toString();

  ASSERT_EQ("1", jsonString);
}

// fromString()
TEST(JsonValue, 59)
{
  JsonValue::Integer i = 1;
  JsonValue jsonValue1(i);

  std::string jsonString = jsonValue1.toString();

  ASSERT_EQ("1", jsonString);

  JsonValue jsonValue2 = jsonValue1.fromString(jsonString);

  ASSERT_TRUE(jsonValue2.isInteger());
}

// operator<<() and operator>>()
TEST(JsonValue, 60)
{
  std::stringstream ss;

  JsonValue::Integer i = 1;
  JsonValue jasonValue1(i);

  ss << jasonValue1;

  JsonValue jsonValue2;
  ss >> jsonValue2;

  ASSERT_TRUE(jsonValue2.isInteger());
}






















int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

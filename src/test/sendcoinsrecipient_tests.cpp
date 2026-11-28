// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The stored layout of SendCoinsRecipient, through SendCoinsRecipientRecord,
// the Qt-free struct its serialisation uses: nVersion, address, label,
// amount, message and two trailing strings.

#include "qt/sendcoinsrecipientrecord.h"

#include "amount.h"
#include "clientversion.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <string>

#include <boost/test/unit_test.hpp>

namespace {

SendCoinsRecipientRecord SampleRecord()
{
    SendCoinsRecipientRecord record;
    record.nVersion = 1;
    record.address = "address";
    record.label = "label";
    record.amount = 12345;
    record.message = "message";
    return record;
}

// SampleRecord() in the stored layout: nVersion 1 (4 bytes, little endian),
// "address", "label" (each with its length byte), amount 12345 (8 bytes,
// little endian), "message", and the two trailing strings, each empty (a
// length byte 0).
const std::string SAMPLE_RECORD_HEX =
    "01000000"
    "07" "61646472657373"
    "05" "6c6162656c"
    "3930000000000000"
    "07" "6d657373616765"
    "00"
    "00";

} // namespace

BOOST_FIXTURE_TEST_SUITE(sendcoinsrecipient_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(read_record_with_every_field_set)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << int(1) << std::string("address") << std::string("label") << CAmount(12345)
       << std::string("message") << std::string("field6") << std::string("field7");

    SendCoinsRecipientRecord record;
    ss >> record;

    BOOST_CHECK_EQUAL(record.nVersion, 1);
    BOOST_CHECK_EQUAL(record.address, "address");
    BOOST_CHECK_EQUAL(record.label, "label");
    BOOST_CHECK_EQUAL(record.amount, 12345);
    BOOST_CHECK_EQUAL(record.message, "message");
    BOOST_CHECK(ss.empty());
}

BOOST_AUTO_TEST_CASE(written_record_layout)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << SampleRecord();

    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), SAMPLE_RECORD_HEX);
}

BOOST_AUTO_TEST_CASE(round_trip)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << SampleRecord();

    SendCoinsRecipientRecord record;
    ss >> record;

    BOOST_CHECK_EQUAL(record.nVersion, 1);
    BOOST_CHECK_EQUAL(record.address, "address");
    BOOST_CHECK_EQUAL(record.label, "label");
    BOOST_CHECK_EQUAL(record.amount, 12345);
    BOOST_CHECK_EQUAL(record.message, "message");
    BOOST_CHECK(ss.empty());
}

BOOST_AUTO_TEST_SUITE_END()

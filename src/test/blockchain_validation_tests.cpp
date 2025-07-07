#include <boost/test/unit_test.hpp>
#include <vector>
#include <string>
#include <ctime>
#include "test_common.h"

using namespace std;

// Block and transaction validation utilities
struct Transaction {
    vector<unsigned char> input_hash;
    uint32_t input_index;
    vector<unsigned char> output_script;
    uint64_t amount;
    uint32_t timestamp;
    
    bool IsValid() const {
        // Basic validation rules
        return !input_hash.empty() && 
               !output_script.empty() && 
               amount > 0 && 
               timestamp > 0;
    }
    
    uint64_t GetHash() const {
        // Simple hash calculation for testing
        uint64_t hash = 0;
        for (unsigned char byte : input_hash) {
            hash = hash * 31 + byte;
        }
        hash ^= input_index;
        hash ^= amount;
        hash ^= timestamp;
        return hash;
    }
};

struct Block {
    uint32_t version;
    vector<unsigned char> prev_hash;
    vector<unsigned char> merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    vector<Transaction> transactions;
    
    bool IsValid() const {
        // Basic block validation
        if (transactions.empty()) return false;
        if (timestamp == 0) return false;
        if (prev_hash.empty()) return false;
        
        // Validate all transactions
        for (const Transaction& tx : transactions) {
            if (!tx.IsValid()) return false;
        }
        
        return true;
    }
    
    vector<unsigned char> CalculateMerkleRoot() const {
        if (transactions.empty()) {
            return vector<unsigned char>(32, 0);
        }
        
        // Simple merkle root calculation for testing
        vector<uint64_t> hashes;
        for (const Transaction& tx : transactions) {
            hashes.push_back(tx.GetHash());
        }
        
        while (hashes.size() > 1) {
            vector<uint64_t> next_level;
            for (size_t i = 0; i < hashes.size(); i += 2) {
                uint64_t left = hashes[i];
                uint64_t right = (i + 1 < hashes.size()) ? hashes[i + 1] : left;
                uint64_t combined = left ^ right;
                next_level.push_back(combined);
            }
            hashes = next_level;
        }
        
        uint64_t root = hashes[0];
        vector<unsigned char> result(8);
        for (int i = 0; i < 8; ++i) {
            result[i] = (root >> (i * 8)) & 0xFF;
        }
        return result;
    }
    
    bool ValidateMerkleRoot() const {
        vector<unsigned char> calculated = CalculateMerkleRoot();
        return calculated == merkle_root;
    }
};

// Utility functions for blockchain validation
bool IsValidTimestamp(uint32_t timestamp) {
    uint32_t current_time = static_cast<uint32_t>(time(nullptr));
    uint32_t max_future_time = current_time + 7200; // 2 hours in future
    uint32_t min_past_time = current_time - 86400 * 30; // 30 days in past
    
    return timestamp <= max_future_time && timestamp >= min_past_time;
}

bool IsValidDifficulty(uint32_t bits) {
    // Simple difficulty validation - bits should be within reasonable range
    return bits > 0 && bits < 0x207FFFFF;
}

uint64_t CalculateBlockReward(uint32_t block_height) {
    // Simple block reward calculation (halving every 210000 blocks)
    uint64_t base_reward = 100000000; // 1 coin = 100000000 satoshis
    uint32_t halvings = block_height / 210000;
    
    if (halvings >= 32) return 0; // All coins mined
    
    return base_reward >> halvings;
}

BOOST_AUTO_TEST_SUITE(blockchain_validation_tests)

BOOST_AUTO_TEST_CASE(transaction_validation)
{
    Transaction valid_tx;
    valid_tx.input_hash = {0x01, 0x02, 0x03, 0x04};
    valid_tx.input_index = 0;
    valid_tx.output_script = {0x76, 0xa9, 0x14}; // OP_DUP OP_HASH160 <20 bytes>
    valid_tx.amount = 100000000; // 1 coin
    valid_tx.timestamp = static_cast<uint32_t>(time(nullptr));
    
    BOOST_CHECK(valid_tx.IsValid());
    
    // Test invalid transactions
    Transaction invalid_tx1 = valid_tx;
    invalid_tx1.amount = 0;
    BOOST_CHECK(!invalid_tx1.IsValid());
    
    Transaction invalid_tx2 = valid_tx;
    invalid_tx2.input_hash.clear();
    BOOST_CHECK(!invalid_tx2.IsValid());
    
    Transaction invalid_tx3 = valid_tx;
    invalid_tx3.output_script.clear();
    BOOST_CHECK(!invalid_tx3.IsValid());
}

BOOST_AUTO_TEST_CASE(transaction_hash_calculation)
{
    Transaction tx1;
    tx1.input_hash = {0x01, 0x02, 0x03, 0x04};
    tx1.input_index = 0;
    tx1.output_script = {0x76, 0xa9, 0x14};
    tx1.amount = 100000000;
    tx1.timestamp = 1234567890;
    
    Transaction tx2 = tx1;
    tx2.amount = 200000000; // Different amount
    
    // Different transactions should have different hashes
    BOOST_CHECK_NE(tx1.GetHash(), tx2.GetHash());
    
    // Same transaction should have same hash
    Transaction tx1_copy = tx1;
    BOOST_CHECK_EQUAL(tx1.GetHash(), tx1_copy.GetHash());
}

BOOST_AUTO_TEST_CASE(block_validation)
{
    Block valid_block;
    valid_block.version = 1;
    valid_block.prev_hash = {0x01, 0x02, 0x03, 0x04};
    valid_block.timestamp = static_cast<uint32_t>(time(nullptr));
    valid_block.bits = 0x1d00ffff;
    valid_block.nonce = 12345;
    
    // Add a valid transaction
    Transaction tx;
    tx.input_hash = {0x05, 0x06, 0x07, 0x08};
    tx.input_index = 0;
    tx.output_script = {0x76, 0xa9, 0x14};
    tx.amount = 100000000;
    tx.timestamp = valid_block.timestamp;
    valid_block.transactions.push_back(tx);
    
    // Calculate and set merkle root
    valid_block.merkle_root = valid_block.CalculateMerkleRoot();
    
    BOOST_CHECK(valid_block.IsValid());
    BOOST_CHECK(valid_block.ValidateMerkleRoot());
    
    // Test invalid blocks
    Block invalid_block1 = valid_block;
    invalid_block1.transactions.clear();
    BOOST_CHECK(!invalid_block1.IsValid());
    
    Block invalid_block2 = valid_block;
    invalid_block2.prev_hash.clear();
    BOOST_CHECK(!invalid_block2.IsValid());
}

BOOST_AUTO_TEST_CASE(merkle_root_calculation)
{
    Block block;
    block.timestamp = static_cast<uint32_t>(time(nullptr));
    block.prev_hash = {0x01, 0x02, 0x03, 0x04};
    
    // Single transaction
    Transaction tx1;
    tx1.input_hash = {0x01, 0x02};
    tx1.input_index = 0;
    tx1.output_script = {0x76, 0xa9};
    tx1.amount = 100000000;
    tx1.timestamp = block.timestamp;
    block.transactions.push_back(tx1);
    
    vector<unsigned char> merkle1 = block.CalculateMerkleRoot();
    BOOST_CHECK_EQUAL(merkle1.size(), 8);
    
    // Two transactions
    Transaction tx2;
    tx2.input_hash = {0x03, 0x04};
    tx2.input_index = 1;
    tx2.output_script = {0x76, 0xa9};
    tx2.amount = 200000000;
    tx2.timestamp = block.timestamp;
    block.transactions.push_back(tx2);
    
    vector<unsigned char> merkle2 = block.CalculateMerkleRoot();
    BOOST_CHECK_EQUAL(merkle2.size(), 8);
    BOOST_CHECK_NE(merkle1, merkle2); // Different merkle roots for different tx sets
}

BOOST_AUTO_TEST_CASE(timestamp_validation)
{
    uint32_t current_time = static_cast<uint32_t>(time(nullptr));
    
    // Valid timestamps
    BOOST_CHECK(IsValidTimestamp(current_time));
    BOOST_CHECK(IsValidTimestamp(current_time - 3600)); // 1 hour ago
    BOOST_CHECK(IsValidTimestamp(current_time + 3600)); // 1 hour in future
    
    // Invalid timestamps
    BOOST_CHECK(!IsValidTimestamp(current_time + 7201)); // Too far in future
    BOOST_CHECK(!IsValidTimestamp(current_time - 86400 * 31)); // Too far in past
    BOOST_CHECK(!IsValidTimestamp(0)); // Invalid zero timestamp
}

BOOST_AUTO_TEST_CASE(difficulty_validation)
{
    // Valid difficulty values
    BOOST_CHECK(IsValidDifficulty(0x1d00ffff));
    BOOST_CHECK(IsValidDifficulty(0x1b0404cb));
    BOOST_CHECK(IsValidDifficulty(1));
    
    // Invalid difficulty values
    BOOST_CHECK(!IsValidDifficulty(0));
    BOOST_CHECK(!IsValidDifficulty(0x207FFFFF));
    BOOST_CHECK(!IsValidDifficulty(0xFFFFFFFF));
}

BOOST_AUTO_TEST_CASE(block_reward_calculation)
{
    // Initial reward
    BOOST_CHECK_EQUAL(CalculateBlockReward(0), 100000000);
    BOOST_CHECK_EQUAL(CalculateBlockReward(100000), 100000000);
    
    // First halving
    BOOST_CHECK_EQUAL(CalculateBlockReward(210000), 50000000);
    BOOST_CHECK_EQUAL(CalculateBlockReward(300000), 50000000);
    
    // Second halving
    BOOST_CHECK_EQUAL(CalculateBlockReward(420000), 25000000);
    
    // Very high block (all coins mined)
    BOOST_CHECK_EQUAL(CalculateBlockReward(32 * 210000), 0);
}

BOOST_AUTO_TEST_SUITE_END()
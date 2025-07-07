#include <boost/test/unit_test.hpp>
#include <vector>
#include <string>
#include <map>
#include "test_common.h"

using namespace std;

// Data structure tests for core blockchain components

// Simple UTXO (Unspent Transaction Output) management
struct UTXO {
    string transaction_id;
    uint32_t output_index;
    uint64_t amount;
    vector<unsigned char> script;
    uint32_t block_height;
    
    bool IsValid() const {
        return !transaction_id.empty() && amount > 0 && !script.empty();
    }
    
    string GetKey() const {
        return transaction_id + ":" + to_string(output_index);
    }
};

class UTXOSet {
private:
    map<string, UTXO> utxos;
    
public:
    bool AddUTXO(const UTXO& utxo) {
        if (!utxo.IsValid()) return false;
        utxos[utxo.GetKey()] = utxo;
        return true;
    }
    
    bool RemoveUTXO(const string& key) {
        return utxos.erase(key) > 0;
    }
    
    bool HasUTXO(const string& key) const {
        return utxos.find(key) != utxos.end();
    }
    
    UTXO GetUTXO(const string& key) const {
        auto it = utxos.find(key);
        return (it != utxos.end()) ? it->second : UTXO{};
    }
    
    size_t Size() const {
        return utxos.size();
    }
    
    uint64_t GetTotalValue() const {
        uint64_t total = 0;
        for (const auto& pair : utxos) {
            total += pair.second.amount;
        }
        return total;
    }
    
    vector<UTXO> GetUTXOsForAmount(uint64_t target_amount) const {
        vector<UTXO> result;
        uint64_t current_total = 0;
        
        for (const auto& pair : utxos) {
            result.push_back(pair.second);
            current_total += pair.second.amount;
            if (current_total >= target_amount) {
                break;
            }
        }
        
        return result;
    }
    
    void Clear() {
        utxos.clear();
    }
};

// Simple memory pool for unconfirmed transactions
struct MemPoolTransaction {
    string tx_id;
    uint64_t fee;
    uint32_t size;
    uint32_t timestamp;
    vector<string> dependencies; // Transaction IDs this depends on
    
    double GetFeeRate() const {
        return size > 0 ? static_cast<double>(fee) / size : 0.0;
    }
    
    bool IsValid() const {
        return !tx_id.empty() && size > 0;
    }
};

class MemoryPool {
private:
    map<string, MemPoolTransaction> transactions;
    
public:
    bool AddTransaction(const MemPoolTransaction& tx) {
        if (!tx.IsValid()) return false;
        
        // Check if dependencies exist (simplified)
        for (const string& dep : tx.dependencies) {
            if (transactions.find(dep) == transactions.end()) {
                return false; // Dependency not found
            }
        }
        
        transactions[tx.tx_id] = tx;
        return true;
    }
    
    bool RemoveTransaction(const string& tx_id) {
        return transactions.erase(tx_id) > 0;
    }
    
    bool HasTransaction(const string& tx_id) const {
        return transactions.find(tx_id) != transactions.end();
    }
    
    size_t Size() const {
        return transactions.size();
    }
    
    vector<MemPoolTransaction> GetTransactionsByFeeRate(size_t max_count = 100) const {
        vector<MemPoolTransaction> result;
        
        for (const auto& pair : transactions) {
            result.push_back(pair.second);
        }
        
        // Sort by fee rate (descending)
        sort(result.begin(), result.end(), 
             [](const MemPoolTransaction& a, const MemPoolTransaction& b) {
                 return a.GetFeeRate() > b.GetFeeRate();
             });
        
        if (result.size() > max_count) {
            result.resize(max_count);
        }
        
        return result;
    }
    
    uint64_t GetTotalFees() const {
        uint64_t total = 0;
        for (const auto& pair : transactions) {
            total += pair.second.fee;
        }
        return total;
    }
    
    void Clear() {
        transactions.clear();
    }
};

// Simple peer management
struct Peer {
    string address;
    uint16_t port;
    uint32_t last_seen;
    uint32_t version;
    bool is_connected;
    uint32_t misbehavior_score;
    
    bool IsValid() const {
        return !address.empty() && port > 0 && version > 0;
    }
    
    string GetIdentifier() const {
        return address + ":" + to_string(port);
    }
    
    bool IsBanned() const {
        return misbehavior_score >= 100;
    }
};

class PeerManager {
private:
    map<string, Peer> peers;
    
public:
    bool AddPeer(const Peer& peer) {
        if (!peer.IsValid()) return false;
        peers[peer.GetIdentifier()] = peer;
        return true;
    }
    
    bool RemovePeer(const string& identifier) {
        return peers.erase(identifier) > 0;
    }
    
    bool HasPeer(const string& identifier) const {
        return peers.find(identifier) != peers.end();
    }
    
    void UpdatePeerScore(const string& identifier, int score_change) {
        auto it = peers.find(identifier);
        if (it != peers.end()) {
            it->second.misbehavior_score = max(0, 
                static_cast<int>(it->second.misbehavior_score) + score_change);
        }
    }
    
    vector<Peer> GetConnectedPeers() const {
        vector<Peer> result;
        for (const auto& pair : peers) {
            if (pair.second.is_connected && !pair.second.IsBanned()) {
                result.push_back(pair.second);
            }
        }
        return result;
    }
    
    size_t Size() const {
        return peers.size();
    }
    
    void Clear() {
        peers.clear();
    }
};

BOOST_AUTO_TEST_SUITE(data_structure_tests)

BOOST_AUTO_TEST_CASE(utxo_basic_operations)
{
    UTXO utxo;
    utxo.transaction_id = "tx123";
    utxo.output_index = 0;
    utxo.amount = 100000000;
    utxo.script = {0x76, 0xa9, 0x14};
    utxo.block_height = 12345;
    
    BOOST_CHECK(utxo.IsValid());
    BOOST_CHECK_EQUAL(utxo.GetKey(), "tx123:0");
    
    // Invalid UTXO
    UTXO invalid_utxo;
    BOOST_CHECK(!invalid_utxo.IsValid());
}

BOOST_AUTO_TEST_CASE(utxo_set_management)
{
    UTXOSet utxo_set;
    
    UTXO utxo1;
    utxo1.transaction_id = "tx1";
    utxo1.output_index = 0;
    utxo1.amount = 100000000;
    utxo1.script = {0x76, 0xa9};
    utxo1.block_height = 100;
    
    UTXO utxo2;
    utxo2.transaction_id = "tx2";
    utxo2.output_index = 1;
    utxo2.amount = 200000000;
    utxo2.script = {0x76, 0xa9};
    utxo2.block_height = 101;
    
    // Add UTXOs
    BOOST_CHECK(utxo_set.AddUTXO(utxo1));
    BOOST_CHECK(utxo_set.AddUTXO(utxo2));
    BOOST_CHECK_EQUAL(utxo_set.Size(), 2);
    
    // Check existence
    BOOST_CHECK(utxo_set.HasUTXO("tx1:0"));
    BOOST_CHECK(utxo_set.HasUTXO("tx2:1"));
    BOOST_CHECK(!utxo_set.HasUTXO("tx3:0"));
    
    // Get UTXOs
    UTXO retrieved = utxo_set.GetUTXO("tx1:0");
    BOOST_CHECK_EQUAL(retrieved.transaction_id, "tx1");
    BOOST_CHECK_EQUAL(retrieved.amount, 100000000);
    
    // Total value
    BOOST_CHECK_EQUAL(utxo_set.GetTotalValue(), 300000000);
    
    // Remove UTXO
    BOOST_CHECK(utxo_set.RemoveUTXO("tx1:0"));
    BOOST_CHECK_EQUAL(utxo_set.Size(), 1);
    BOOST_CHECK(!utxo_set.HasUTXO("tx1:0"));
}

BOOST_AUTO_TEST_CASE(utxo_selection_for_amount)
{
    UTXOSet utxo_set;
    
    // Add multiple UTXOs
    for (int i = 0; i < 5; ++i) {
        UTXO utxo;
        utxo.transaction_id = "tx" + to_string(i);
        utxo.output_index = 0;
        utxo.amount = (i + 1) * 50000000; // 0.5, 1.0, 1.5, 2.0, 2.5 coins
        utxo.script = {0x76, 0xa9};
        utxo.block_height = 100 + i;
        utxo_set.AddUTXO(utxo);
    }
    
    // Get UTXOs for specific amount
    vector<UTXO> selected = utxo_set.GetUTXOsForAmount(200000000); // 2.0 coins
    BOOST_CHECK_GE(selected.size(), 1);
    
    uint64_t total_selected = 0;
    for (const UTXO& utxo : selected) {
        total_selected += utxo.amount;
    }
    BOOST_CHECK_GE(total_selected, 200000000);
}

BOOST_AUTO_TEST_CASE(mempool_basic_operations)
{
    MemoryPool mempool;
    
    MemPoolTransaction tx;
    tx.tx_id = "tx123";
    tx.fee = 10000;
    tx.size = 250;
    tx.timestamp = 1234567890;
    
    BOOST_CHECK(tx.IsValid());
    BOOST_CHECK_EQUAL(tx.GetFeeRate(), 40.0); // 10000 / 250
    
    BOOST_CHECK(mempool.AddTransaction(tx));
    BOOST_CHECK_EQUAL(mempool.Size(), 1);
    BOOST_CHECK(mempool.HasTransaction("tx123"));
}

BOOST_AUTO_TEST_CASE(mempool_fee_rate_sorting)
{
    MemoryPool mempool;
    
    // Add transactions with different fee rates
    for (int i = 0; i < 3; ++i) {
        MemPoolTransaction tx;
        tx.tx_id = "tx" + to_string(i);
        tx.fee = (i + 1) * 5000; // 5000, 10000, 15000
        tx.size = 250;
        tx.timestamp = 1234567890;
        mempool.AddTransaction(tx);
    }
    
    vector<MemPoolTransaction> sorted_txs = mempool.GetTransactionsByFeeRate();
    BOOST_CHECK_EQUAL(sorted_txs.size(), 3);
    
    // Should be sorted by fee rate (descending)
    BOOST_CHECK_GE(sorted_txs[0].GetFeeRate(), sorted_txs[1].GetFeeRate());
    BOOST_CHECK_GE(sorted_txs[1].GetFeeRate(), sorted_txs[2].GetFeeRate());
    
    // Check total fees
    BOOST_CHECK_EQUAL(mempool.GetTotalFees(), 30000); // 5000 + 10000 + 15000
}

BOOST_AUTO_TEST_CASE(mempool_dependency_checking)
{
    MemoryPool mempool;
    
    // Add parent transaction
    MemPoolTransaction parent_tx;
    parent_tx.tx_id = "parent";
    parent_tx.fee = 10000;
    parent_tx.size = 250;
    parent_tx.timestamp = 1234567890;
    mempool.AddTransaction(parent_tx);
    
    // Add child transaction that depends on parent
    MemPoolTransaction child_tx;
    child_tx.tx_id = "child";
    child_tx.fee = 5000;
    child_tx.size = 200;
    child_tx.timestamp = 1234567891;
    child_tx.dependencies = {"parent"};
    
    BOOST_CHECK(mempool.AddTransaction(child_tx));
    
    // Try to add transaction with missing dependency
    MemPoolTransaction orphan_tx;
    orphan_tx.tx_id = "orphan";
    orphan_tx.fee = 5000;
    orphan_tx.size = 200;
    orphan_tx.timestamp = 1234567892;
    orphan_tx.dependencies = {"missing"};
    
    BOOST_CHECK(!mempool.AddTransaction(orphan_tx));
}

BOOST_AUTO_TEST_CASE(peer_management)
{
    PeerManager peer_mgr;
    
    Peer peer;
    peer.address = "192.168.1.1";
    peer.port = 8333;
    peer.last_seen = 1234567890;
    peer.version = 70015;
    peer.is_connected = true;
    peer.misbehavior_score = 0;
    
    BOOST_CHECK(peer.IsValid());
    BOOST_CHECK_EQUAL(peer.GetIdentifier(), "192.168.1.1:8333");
    BOOST_CHECK(!peer.IsBanned());
    
    BOOST_CHECK(peer_mgr.AddPeer(peer));
    BOOST_CHECK_EQUAL(peer_mgr.Size(), 1);
    BOOST_CHECK(peer_mgr.HasPeer("192.168.1.1:8333"));
    
    // Test connected peers
    vector<Peer> connected = peer_mgr.GetConnectedPeers();
    BOOST_CHECK_EQUAL(connected.size(), 1);
    
    // Test misbehavior scoring
    peer_mgr.UpdatePeerScore("192.168.1.1:8333", 50);
    peer_mgr.UpdatePeerScore("192.168.1.1:8333", 60); // Total: 110, should be banned
    
    connected = peer_mgr.GetConnectedPeers();
    BOOST_CHECK_EQUAL(connected.size(), 0); // Banned peer not included
}

BOOST_AUTO_TEST_SUITE_END()
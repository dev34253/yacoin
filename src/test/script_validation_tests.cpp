#include <boost/test/unit_test.hpp>
#include <string>
#include <sstream>
#include <vector>
#include "test_common.h"

using namespace std;

// Script validation utilities
enum OpCode {
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_1 = 0x51,
    OP_16 = 0x60,
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_EQUALVERIFY = 0x88,
    OP_CHECKSIG = 0xac,
    OP_CHECKMULTISIG = 0xae,
    OP_RETURN = 0x6a
};

// Simple script interpreter for testing
class ScriptStack {
private:
    vector<vector<unsigned char>> stack;
    
public:
    void Push(const vector<unsigned char>& data) {
        stack.push_back(data);
    }
    
    vector<unsigned char> Pop() {
        if (stack.empty()) {
            return vector<unsigned char>();
        }
        vector<unsigned char> result = stack.back();
        stack.pop_back();
        return result;
    }
    
    vector<unsigned char> Top() const {
        if (stack.empty()) {
            return vector<unsigned char>();
        }
        return stack.back();
    }
    
    size_t Size() const {
        return stack.size();
    }
    
    bool Empty() const {
        return stack.empty();
    }
    
    void Clear() {
        stack.clear();
    }
    
    bool IsTrue() const {
        if (stack.empty()) return false;
        vector<unsigned char> top = stack.back();
        
        // Empty vector is false
        if (top.empty()) return false;
        
        // Check if all bytes are zero
        for (unsigned char byte : top) {
            if (byte != 0) return true;
        }
        return false;
    }
};

bool ExecuteScript(const vector<unsigned char>& script, ScriptStack& stack) {
    size_t pc = 0; // Program counter
    
    while (pc < script.size()) {
        unsigned char opcode = script[pc++];
        
        if (opcode <= 75) {
            // Push data of opcode length
            if (pc + opcode > script.size()) return false;
            vector<unsigned char> data(script.begin() + pc, script.begin() + pc + opcode);
            stack.Push(data);
            pc += opcode;
        }
        else {
            switch (opcode) {
                case OP_0:
                    stack.Push(vector<unsigned char>());
                    break;
                    
                case OP_1:
                    stack.Push(vector<unsigned char>{1});
                    break;
                    
                case OP_DUP:
                    if (stack.Empty()) return false;
                    stack.Push(stack.Top());
                    break;
                    
                case OP_HASH160:
                    if (stack.Empty()) return false;
                    {
                        vector<unsigned char> data = stack.Pop();
                        // Simplified hash (just first 20 bytes for testing)
                        vector<unsigned char> hash(20, 0);
                        for (size_t i = 0; i < min(data.size(), hash.size()); ++i) {
                            hash[i] = data[i] ^ 0xAA; // Simple hash operation
                        }
                        stack.Push(hash);
                    }
                    break;
                    
                case OP_EQUALVERIFY:
                    if (stack.Size() < 2) return false;
                    {
                        vector<unsigned char> a = stack.Pop();
                        vector<unsigned char> b = stack.Pop();
                        if (a != b) return false;
                    }
                    break;
                    
                case OP_CHECKSIG:
                    if (stack.Size() < 2) return false;
                    {
                        stack.Pop(); // pubkey
                        stack.Pop(); // signature
                        stack.Push(vector<unsigned char>{1}); // Always valid for testing
                    }
                    break;
                    
                case OP_CHECKMULTISIG:
                    if (stack.Size() < 3) return false;
                    {
                        vector<unsigned char> m_data = stack.Pop();
                        if (m_data.empty()) return false;
                        int m = m_data[0];
                        
                        // Pop m public keys
                        for (int i = 0; i < m; ++i) {
                            if (stack.Empty()) return false;
                            stack.Pop();
                        }
                        
                        vector<unsigned char> n_data = stack.Pop();
                        if (n_data.empty()) return false;
                        int n = n_data[0];
                        
                        // Pop n signatures
                        for (int i = 0; i < n; ++i) {
                            if (stack.Empty()) return false;
                            stack.Pop();
                        }
                        
                        stack.Push(vector<unsigned char>{1}); // Always valid for testing
                    }
                    break;
                    
                case OP_RETURN:
                    return false; // Explicit failure
                    
                default:
                    return false; // Unknown opcode
            }
        }
    }
    
    return true;
}

bool IsStandardScript(const vector<unsigned char>& script) {
    if (script.empty()) return false;
    
    // Check for common standard patterns
    
    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (script.size() == 25 &&
        script[0] == OP_DUP &&
        script[1] == OP_HASH160 &&
        script[2] == 20 &&
        script[23] == OP_EQUALVERIFY &&
        script[24] == OP_CHECKSIG) {
        return true;
    }
    
    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if (script.size() == 23 &&
        script[0] == OP_HASH160 &&
        script[1] == 20 &&
        script[22] == OP_EQUALVERIFY) {
        return true;
    }
    
    // Multi-sig: OP_1 ... OP_16 <pubkeys> OP_1 ... OP_16 OP_CHECKMULTISIG
    if (script.size() >= 3) {
        unsigned char first = script[0];
        unsigned char last = script[script.size() - 1];
        if ((first >= OP_1 && first <= OP_16) && last == OP_CHECKMULTISIG) {
            return true;
        }
    }
    
    return false;
}

BOOST_AUTO_TEST_SUITE(script_validation_tests)

BOOST_AUTO_TEST_CASE(script_stack_operations)
{
    ScriptStack stack;
    
    // Test empty stack
    BOOST_CHECK(stack.Empty());
    BOOST_CHECK_EQUAL(stack.Size(), 0);
    BOOST_CHECK(!stack.IsTrue());
    
    // Test push/pop
    vector<unsigned char> data1 = {0x01, 0x02, 0x03};
    stack.Push(data1);
    BOOST_CHECK_EQUAL(stack.Size(), 1);
    BOOST_CHECK(!stack.Empty());
    BOOST_CHECK(stack.IsTrue());
    
    vector<unsigned char> retrieved = stack.Pop();
    BOOST_CHECK_EQUAL(retrieved.size(), data1.size());
    for (size_t i = 0; i < retrieved.size(); ++i) {
        BOOST_CHECK_EQUAL(retrieved[i], data1[i]);
    }
    
    BOOST_CHECK(stack.Empty());
}

BOOST_AUTO_TEST_CASE(script_stack_true_false)
{
    ScriptStack stack;
    
    // Empty stack is false
    BOOST_CHECK(!stack.IsTrue());
    
    // Empty vector is false
    stack.Push(vector<unsigned char>());
    BOOST_CHECK(!stack.IsTrue());
    
    // Zero bytes are false
    stack.Clear();
    stack.Push(vector<unsigned char>{0x00, 0x00});
    BOOST_CHECK(!stack.IsTrue());
    
    // Non-zero bytes are true
    stack.Clear();
    stack.Push(vector<unsigned char>{0x01});
    BOOST_CHECK(stack.IsTrue());
    
    stack.Clear();
    stack.Push(vector<unsigned char>{0x00, 0x01});
    BOOST_CHECK(stack.IsTrue());
}

BOOST_AUTO_TEST_CASE(simple_script_execution)
{
    ScriptStack stack;
    
    // Test OP_1
    vector<unsigned char> script1 = {OP_1};
    BOOST_CHECK(ExecuteScript(script1, stack));
    BOOST_CHECK_EQUAL(stack.Size(), 1);
    BOOST_CHECK(stack.IsTrue());
    
    // Test push data
    stack.Clear();
    vector<unsigned char> script2 = {0x03, 0x01, 0x02, 0x03}; // Push 3 bytes: {0x01, 0x02, 0x03}
    BOOST_CHECK(ExecuteScript(script2, stack));
    BOOST_CHECK_EQUAL(stack.Size(), 1);
    vector<unsigned char> result = stack.Pop();
    vector<unsigned char> expected = {0x01, 0x02, 0x03};
    BOOST_CHECK_EQUAL(result.size(), expected.size());
    for (size_t i = 0; i < result.size(); ++i) {
        BOOST_CHECK_EQUAL(result[i], expected[i]);
    }
}

BOOST_AUTO_TEST_CASE(script_dup_operation)
{
    ScriptStack stack;
    
    // Test OP_DUP
    vector<unsigned char> script = {0x02, 0x01, 0x02, OP_DUP}; // Push {0x01, 0x02}, then DUP
    BOOST_CHECK(ExecuteScript(script, stack));
    BOOST_CHECK_EQUAL(stack.Size(), 2);
    
    vector<unsigned char> top1 = stack.Pop();
    vector<unsigned char> top2 = stack.Pop();
    BOOST_CHECK_EQUAL(top1.size(), top2.size());
    for (size_t i = 0; i < top1.size(); ++i) {
        BOOST_CHECK_EQUAL(top1[i], top2[i]);
    }
}

BOOST_AUTO_TEST_CASE(script_hash160_operation)
{
    ScriptStack stack;
    
    // Test OP_HASH160
    vector<unsigned char> script = {0x02, 0x01, 0x02, OP_HASH160}; // Push {0x01, 0x02}, then HASH160
    BOOST_CHECK(ExecuteScript(script, stack));
    BOOST_CHECK_EQUAL(stack.Size(), 1);
    
    vector<unsigned char> hash = stack.Pop();
    BOOST_CHECK_EQUAL(hash.size(), 20); // HASH160 produces 20-byte hash
}

BOOST_AUTO_TEST_CASE(script_checksig_operation)
{
    ScriptStack stack;
    
    // Test OP_CHECKSIG (simplified - always returns true)
    vector<unsigned char> script = {
        0x02, 0x01, 0x02, // Push signature
        0x02, 0x03, 0x04, // Push pubkey
        OP_CHECKSIG
    };
    BOOST_CHECK(ExecuteScript(script, stack));
    BOOST_CHECK_EQUAL(stack.Size(), 1);
    BOOST_CHECK(stack.IsTrue());
}

BOOST_AUTO_TEST_CASE(standard_script_validation)
{
    // P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    vector<unsigned char> p2pkh_script = {
        OP_DUP, OP_HASH160, 20,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        OP_EQUALVERIFY, OP_CHECKSIG
    };
    BOOST_CHECK(IsStandardScript(p2pkh_script));
    
    // Multi-sig script: OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    vector<unsigned char> multisig_script = {
        OP_1,
        33, // pubkey1 length
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
        33, // pubkey2 length  
        34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
        0x52, // OP_2
        OP_CHECKMULTISIG
    };
    BOOST_CHECK(IsStandardScript(multisig_script));
    
    // Non-standard script
    vector<unsigned char> nonstandard_script = {OP_RETURN, 0x01, 0x02};
    BOOST_CHECK(!IsStandardScript(nonstandard_script));
    
    // Empty script
    vector<unsigned char> empty_script;
    BOOST_CHECK(!IsStandardScript(empty_script));
}

BOOST_AUTO_TEST_CASE(script_execution_failures)
{
    ScriptStack stack;
    
    // Test OP_RETURN (should fail)
    vector<unsigned char> return_script = {OP_RETURN};
    BOOST_CHECK(!ExecuteScript(return_script, stack));
    
    // Test invalid push length
    vector<unsigned char> invalid_script = {0x10, 0x01}; // Push 16 bytes but only 1 available
    BOOST_CHECK(!ExecuteScript(invalid_script, stack));
    
    // Test OP_DUP on empty stack
    vector<unsigned char> dup_empty_script = {OP_DUP};
    BOOST_CHECK(!ExecuteScript(dup_empty_script, stack));
}

BOOST_AUTO_TEST_SUITE_END()
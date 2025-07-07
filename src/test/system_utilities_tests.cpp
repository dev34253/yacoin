#include <boost/test/unit_test.hpp>
#include <vector>
#include <string>
#include <map>
#include <ctime>
#include "test_common.h"

using namespace std;

// Time and synchronization utilities
class TimeManager {
private:
    int64_t offset;
    bool use_mock_time;
    int64_t mock_time;
    
public:
    TimeManager() : offset(0), use_mock_time(false), mock_time(0) {}
    
    void SetMockTime(int64_t time) {
        mock_time = time;
        use_mock_time = true;
    }
    
    void DisableMockTime() {
        use_mock_time = false;
    }
    
    void AddTimeOffset(int64_t delta) {
        offset += delta;
    }
    
    int64_t GetTime() const {
        if (use_mock_time) {
            return mock_time + offset;
        }
        return static_cast<int64_t>(time(nullptr)) + offset;
    }
    
    int64_t GetTimeMillis() const {
        return GetTime() * 1000;
    }
    
    string FormatTime(int64_t timestamp) const {
        time_t t = static_cast<time_t>(timestamp);
        char buffer[100];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", gmtime(&t));
        return string(buffer);
    }
    
    bool IsInRange(int64_t timestamp, int64_t tolerance = 3600) const {
        int64_t current = GetTime();
        return abs(timestamp - current) <= tolerance;
    }
};

// Configuration management
class ConfigManager {
private:
    map<string, string> settings;
    
public:
    void Set(const string& key, const string& value) {
        settings[key] = value;
    }
    
    string Get(const string& key, const string& default_value = "") const {
        auto it = settings.find(key);
        return (it != settings.end()) ? it->second : default_value;
    }
    
    int GetInt(const string& key, int default_value = 0) const {
        string value = Get(key);
        if (value.empty()) return default_value;
        try {
            return stoi(value);
        } catch (...) {
            return default_value;
        }
    }
    
    bool GetBool(const string& key, bool default_value = false) const {
        string value = Get(key);
        if (value.empty()) return default_value;
        return value == "true" || value == "1" || value == "yes";
    }
    
    double GetDouble(const string& key, double default_value = 0.0) const {
        string value = Get(key);
        if (value.empty()) return default_value;
        try {
            return stod(value);
        } catch (...) {
            return default_value;
        }
    }
    
    bool Has(const string& key) const {
        return settings.find(key) != settings.end();
    }
    
    void Remove(const string& key) {
        settings.erase(key);
    }
    
    void Clear() {
        settings.clear();
    }
    
    size_t Size() const {
        return settings.size();
    }
    
    vector<string> GetKeys() const {
        vector<string> keys;
        for (const auto& pair : settings) {
            keys.push_back(pair.first);
        }
        return keys;
    }
    
    bool LoadFromString(const string& config_string) {
        Clear();
        
        size_t start = 0;
        while (start < config_string.length()) {
            size_t end = config_string.find('\n', start);
            if (end == string::npos) end = config_string.length();
            
            string line = config_string.substr(start, end - start);
            
            // Remove comments and trim
            size_t comment_pos = line.find('#');
            if (comment_pos != string::npos) {
                line = line.substr(0, comment_pos);
            }
            
            // Find key=value
            size_t eq_pos = line.find('=');
            if (eq_pos != string::npos) {
                string key = line.substr(0, eq_pos);
                string value = line.substr(eq_pos + 1);
                
                // Trim whitespace
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                if (!key.empty()) {
                    Set(key, value);
                }
            }
            
            start = end + 1;
        }
        
        return true;
    }
};

// Lock manager for thread safety simulation
class LockManager {
private:
    map<string, bool> locks;
    
public:
    bool TryLock(const string& resource) {
        if (locks[resource]) {
            return false; // Already locked
        }
        locks[resource] = true;
        return true;
    }
    
    void Unlock(const string& resource) {
        locks[resource] = false;
    }
    
    bool IsLocked(const string& resource) const {
        auto it = locks.find(resource);
        return (it != locks.end()) && it->second;
    }
    
    void Clear() {
        locks.clear();
    }
    
    size_t GetLockCount() const {
        size_t count = 0;
        for (const auto& pair : locks) {
            if (pair.second) count++;
        }
        return count;
    }
};

// Simple logger
class Logger {
public:
    enum Level {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3
    };
    
private:
    Level min_level;
    vector<string> messages;
    
    string LevelToString(Level level) const {
        switch (level) {
            case DEBUG: return "DEBUG";
            case INFO: return "INFO";
            case WARNING: return "WARNING";
            case ERROR: return "ERROR";
            default: return "UNKNOWN";
        }
    }
    
public:
    Logger(Level level = INFO) : min_level(level) {}
    
    void Log(Level level, const string& message) {
        if (level >= min_level) {
            string log_entry = "[" + LevelToString(level) + "] " + message;
            messages.push_back(log_entry);
        }
    }
    
    void Debug(const string& message) { Log(DEBUG, message); }
    void Info(const string& message) { Log(INFO, message); }
    void Warning(const string& message) { Log(WARNING, message); }
    void Error(const string& message) { Log(ERROR, message); }
    
    void SetLevel(Level level) { min_level = level; }
    Level GetLevel() const { return min_level; }
    
    const vector<string>& GetMessages() const { return messages; }
    
    void Clear() { messages.clear(); }
    
    size_t GetMessageCount(Level level) const {
        size_t count = 0;
        string level_str = "[" + LevelToString(level) + "]";
        for (const string& message : messages) {
            if (message.find(level_str) == 0) {
                count++;
            }
        }
        return count;
    }
};

BOOST_AUTO_TEST_SUITE(system_utilities_tests)

BOOST_AUTO_TEST_CASE(time_manager_basic_operations)
{
    TimeManager tm;
    
    // Test basic time operations
    int64_t time1 = tm.GetTime();
    int64_t time2 = tm.GetTime();
    BOOST_CHECK_GE(time2, time1); // Time should not go backward
    
    // Test time formatting
    string formatted = tm.FormatTime(1234567890);
    BOOST_CHECK(!formatted.empty());
    BOOST_CHECK(formatted.find("2009") != string::npos); // Unix timestamp 1234567890 is in 2009
}

BOOST_AUTO_TEST_CASE(time_manager_mock_time)
{
    TimeManager tm;
    
    // Test mock time
    tm.SetMockTime(1000000000);
    BOOST_CHECK_EQUAL(tm.GetTime(), 1000000000);
    BOOST_CHECK_EQUAL(tm.GetTimeMillis(), 1000000000000);
    
    // Test time offset with mock time
    tm.AddTimeOffset(3600); // Add 1 hour
    BOOST_CHECK_EQUAL(tm.GetTime(), 1000003600);
    
    // Disable mock time
    tm.DisableMockTime();
    int64_t real_time = tm.GetTime();
    BOOST_CHECK_GT(real_time, 1500000000); // Should be much later than 2017
}

BOOST_AUTO_TEST_CASE(time_manager_range_checking)
{
    TimeManager tm;
    tm.SetMockTime(1000000000);
    
    // Test time range checking
    BOOST_CHECK(tm.IsInRange(1000000000)); // Exact match
    BOOST_CHECK(tm.IsInRange(1000001800, 3600)); // Within 1 hour
    BOOST_CHECK(!tm.IsInRange(1000007200, 3600)); // 2 hours away, outside 1 hour tolerance
}

BOOST_AUTO_TEST_CASE(config_manager_basic_operations)
{
    ConfigManager config;
    
    // Test basic set/get
    config.Set("key1", "value1");
    BOOST_CHECK_EQUAL(config.Get("key1"), "value1");
    BOOST_CHECK_EQUAL(config.Get("missing", "default"), "default");
    
    // Test has/remove
    BOOST_CHECK(config.Has("key1"));
    BOOST_CHECK(!config.Has("missing"));
    
    config.Remove("key1");
    BOOST_CHECK(!config.Has("key1"));
    
    // Test size and clear
    config.Set("a", "1");
    config.Set("b", "2");
    BOOST_CHECK_EQUAL(config.Size(), 2);
    
    config.Clear();
    BOOST_CHECK_EQUAL(config.Size(), 0);
}

BOOST_AUTO_TEST_CASE(config_manager_type_conversions)
{
    ConfigManager config;
    
    // Test integer conversion
    config.Set("int_value", "42");
    BOOST_CHECK_EQUAL(config.GetInt("int_value"), 42);
    BOOST_CHECK_EQUAL(config.GetInt("missing", 100), 100);
    
    config.Set("invalid_int", "not_a_number");
    BOOST_CHECK_EQUAL(config.GetInt("invalid_int", 200), 200);
    
    // Test boolean conversion
    config.Set("bool_true1", "true");
    config.Set("bool_true2", "1");
    config.Set("bool_true3", "yes");
    config.Set("bool_false", "false");
    
    BOOST_CHECK(config.GetBool("bool_true1"));
    BOOST_CHECK(config.GetBool("bool_true2"));
    BOOST_CHECK(config.GetBool("bool_true3"));
    BOOST_CHECK(!config.GetBool("bool_false"));
    BOOST_CHECK(!config.GetBool("missing"));
    
    // Test double conversion
    config.Set("double_value", "3.14159");
    BOOST_CHECK_CLOSE(config.GetDouble("double_value"), 3.14159, 0.00001);
    BOOST_CHECK_EQUAL(config.GetDouble("missing", 2.71), 2.71);
}

BOOST_AUTO_TEST_CASE(config_manager_string_parsing)
{
    ConfigManager config;
    
    string config_string = R"(
# This is a comment
key1=value1
key2 = value2 with spaces
key3=123
# Another comment
bool_setting=true
empty_value=

invalid_line_no_equals
key4=value4
)";
    
    BOOST_CHECK(config.LoadFromString(config_string));
    
    BOOST_CHECK_EQUAL(config.Get("key1"), "value1");
    BOOST_CHECK_EQUAL(config.Get("key2"), "value2 with spaces");
    BOOST_CHECK_EQUAL(config.GetInt("key3"), 123);
    BOOST_CHECK(config.GetBool("bool_setting"));
    BOOST_CHECK_EQUAL(config.Get("empty_value"), "");
    BOOST_CHECK_EQUAL(config.Get("key4"), "value4");
    BOOST_CHECK(!config.Has("invalid_line_no_equals"));
    
    // Test getting all keys
    vector<string> keys = config.GetKeys();
    BOOST_CHECK_GE(keys.size(), 5);
}

BOOST_AUTO_TEST_CASE(lock_manager_operations)
{
    LockManager lock_mgr;
    
    // Test basic locking
    BOOST_CHECK(lock_mgr.TryLock("resource1"));
    BOOST_CHECK(lock_mgr.IsLocked("resource1"));
    BOOST_CHECK(!lock_mgr.TryLock("resource1")); // Already locked
    
    // Test unlocking
    lock_mgr.Unlock("resource1");
    BOOST_CHECK(!lock_mgr.IsLocked("resource1"));
    BOOST_CHECK(lock_mgr.TryLock("resource1")); // Should work now
    
    // Test multiple resources
    BOOST_CHECK(lock_mgr.TryLock("resource2"));
    BOOST_CHECK_EQUAL(lock_mgr.GetLockCount(), 2);
    
    // Test clear
    lock_mgr.Clear();
    BOOST_CHECK_EQUAL(lock_mgr.GetLockCount(), 0);
}

BOOST_AUTO_TEST_CASE(logger_basic_operations)
{
    Logger logger(Logger::INFO);
    
    // Test logging at different levels
    logger.Debug("Debug message"); // Should be filtered out
    logger.Info("Info message");
    logger.Warning("Warning message");
    logger.Error("Error message");
    
    const vector<string>& messages = logger.GetMessages();
    BOOST_CHECK_EQUAL(messages.size(), 3); // Debug filtered out
    
    BOOST_CHECK_EQUAL(logger.GetMessageCount(Logger::DEBUG), 0);
    BOOST_CHECK_EQUAL(logger.GetMessageCount(Logger::INFO), 1);
    BOOST_CHECK_EQUAL(logger.GetMessageCount(Logger::WARNING), 1);
    BOOST_CHECK_EQUAL(logger.GetMessageCount(Logger::ERROR), 1);
}

BOOST_AUTO_TEST_CASE(logger_level_filtering)
{
    Logger logger(Logger::ERROR);
    
    logger.Debug("Debug message");
    logger.Info("Info message");
    logger.Warning("Warning message");
    logger.Error("Error message");
    
    // Only ERROR level should be logged
    BOOST_CHECK_EQUAL(logger.GetMessages().size(), 1);
    BOOST_CHECK_EQUAL(logger.GetMessageCount(Logger::ERROR), 1);
    
    // Change level and test
    logger.SetLevel(Logger::DEBUG);
    logger.Debug("New debug message");
    BOOST_CHECK_EQUAL(logger.GetMessages().size(), 2);
    
    // Test clear
    logger.Clear();
    BOOST_CHECK_EQUAL(logger.GetMessages().size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <iostream>
#include <vector>
#include <iomanip>

// Stream operator for vector<unsigned char> to fix Boost Test printing
namespace std {
    inline ostream& operator<<(ostream& os, const vector<unsigned char>& vec) {
        os << "[";
        for (size_t i = 0; i < vec.size(); ++i) {
            if (i > 0) os << ", ";
            os << "0x" << hex << setfill('0') << setw(2) << static_cast<int>(vec[i]);
        }
        os << "]";
        return os;
    }
}

#endif // TEST_COMMON_H
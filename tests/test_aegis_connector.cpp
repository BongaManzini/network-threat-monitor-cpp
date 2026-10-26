#include "AegisConnector.hpp"
#include <cassert>
#include <iostream>

void test_url_parsing() {
    std::cout << "[TEST] Running test_url_parsing...\n";
    AegisConnector conn1("http://192.168.1.50:8080");
    assert(conn1.getHost() == "192.168.1.50");
    assert(conn1.getPort() == 8080);

    AegisConnector conn2("http://localhost:5000/");
    assert(conn2.getHost() == "localhost");
    assert(conn2.getPort() == 5000);

    AegisConnector conn3("127.0.0.1:9000");
    assert(conn3.getHost() == "127.0.0.1");
    assert(conn3.getPort() == 9000);

    std::cout << "  ✓ test_url_parsing PASSED\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Running C++ AegisConnector Unit Tests \n";
    std::cout << "========================================\n";
    test_url_parsing();
    std::cout << "========================================\n";
    std::cout << "  All AegisConnector Tests PASSED       \n";
    std::cout << "========================================\n";
    return 0;
}

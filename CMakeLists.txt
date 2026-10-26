cmake_minimum_required(VERSION 3.10)
project(AegisCPPNetworkMonitor VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

set(COMMON_SOURCES
    src/ThreatDetector.cpp
    src/Sniffer.cpp
    src/AegisConnector.cpp
)

# Main Executable
add_executable(network_monitor src/main.cpp ${COMMON_SOURCES})

if(WIN32)
    target_link_libraries(network_monitor PRIVATE ws2_32 iphlpapi)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(network_monitor PRIVATE Threads::Threads)
endif()

# Tests
enable_testing()

add_executable(test_threat_detector tests/test_threat_detector.cpp src/ThreatDetector.cpp)
if(WIN32)
    target_link_libraries(test_threat_detector PRIVATE ws2_32)
else()
    target_link_libraries(test_threat_detector PRIVATE Threads::Threads)
endif()
add_test(NAME ThreatDetectorTest COMMAND test_threat_detector)

add_executable(test_aegis_connector tests/test_aegis_connector.cpp src/AegisConnector.cpp src/ThreatDetector.cpp)
if(WIN32)
    target_link_libraries(test_aegis_connector PRIVATE ws2_32)
else()
    target_link_libraries(test_aegis_connector PRIVATE Threads::Threads)
endif()
add_test(NAME AegisConnectorTest COMMAND test_aegis_connector)

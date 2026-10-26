CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS ?= -pthread

# Windows MinGW detection
ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32 -liphlpapi
    TARGET_EXT = .exe
else
    TARGET_EXT =
endif

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests

COMMON_SRCS = $(SRC_DIR)/Platform.cpp $(SRC_DIR)/ThreatDetector.cpp $(SRC_DIR)/Sniffer.cpp $(SRC_DIR)/AegisConnector.cpp
COMMON_OBJS = $(OBJ_DIR)/ThreatDetector.o $(OBJ_DIR)/Sniffer.o $(OBJ_DIR)/AegisConnector.o

MAIN_TARGET = $(BIN_DIR)/network_monitor$(TARGET_EXT)
TEST_DETECTOR_TARGET = $(BIN_DIR)/test_threat_detector$(TARGET_EXT)
TEST_CONNECTOR_TARGET = $(BIN_DIR)/test_aegis_connector$(TARGET_EXT)

.PHONY: all clean test dirs

all: dirs $(MAIN_TARGET)

dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(OBJ_DIR)/ThreatDetector.o: $(SRC_DIR)/ThreatDetector.cpp $(INC_DIR)/ThreatDetector.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/Sniffer.o: $(SRC_DIR)/Sniffer.cpp $(INC_DIR)/Sniffer.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/AegisConnector.o: $(SRC_DIR)/AegisConnector.cpp $(INC_DIR)/AegisConnector.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/main.o: $(SRC_DIR)/main.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MAIN_TARGET): dirs $(COMMON_OBJS) $(OBJ_DIR)/main.o
	$(CXX) $(OBJ_DIR)/main.o $(COMMON_OBJS) $(LDFLAGS) -o $@

# Unit test targets
$(TEST_DETECTOR_TARGET): dirs $(OBJ_DIR)/ThreatDetector.o $(TEST_DIR)/test_threat_detector.cpp
	$(CXX) $(CXXFLAGS) $(TEST_DIR)/test_threat_detector.cpp $(OBJ_DIR)/ThreatDetector.o $(LDFLAGS) -o $@

$(TEST_CONNECTOR_TARGET): dirs $(OBJ_DIR)/AegisConnector.o $(OBJ_DIR)/ThreatDetector.o $(TEST_DIR)/test_aegis_connector.cpp
	$(CXX) $(CXXFLAGS) $(TEST_DIR)/test_aegis_connector.cpp $(OBJ_DIR)/AegisConnector.o $(OBJ_DIR)/ThreatDetector.o $(LDFLAGS) -o $@

test: dirs $(TEST_DETECTOR_TARGET) $(TEST_CONNECTOR_TARGET)
	@echo "=== Running Threat Detector Unit Test ==="
	@./$(TEST_DETECTOR_TARGET)
	@echo ""
	@echo "=== Running Aegis Connector Unit Test ==="
	@./$(TEST_CONNECTOR_TARGET)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

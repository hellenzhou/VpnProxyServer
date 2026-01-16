cmake_minimum_required(VERSION 3.15)
project(VpnProxyServer VERSION 2.0.0 LANGUAGES CXX)

# ===== 编译选项 =====
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译优化
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# 启用所有警告
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# ===== 依赖查找 =====

# Threads (required)
find_package(Threads REQUIRED)

# Boost.Asio (optional, 推荐)
find_package(Boost 1.70 COMPONENTS system)
if(Boost_FOUND)
    add_definitions(-DUSE_BOOST_ASIO)
    message(STATUS "Using Boost.Asio for networking")
else()
    message(WARNING "Boost not found, using epoll (Linux only)")
endif()

# Google Test (for testing)
find_package(GTest)
if(GTest_FOUND)
    enable_testing()
    message(STATUS "Google Test found, tests enabled")
endif()

# spdlog (for logging)
find_package(spdlog)
if(NOT spdlog_FOUND)
    message(STATUS "spdlog not found, using simple logger")
endif()

# ===== 源文件 =====

set(CORE_SOURCES
    core/VpnServer.cpp
    core/Config.cpp
    core/EventLoop.cpp
)

set(NETWORK_SOURCES
    network/UdpSocket.cpp
    network/SocketAddress.cpp
    network/AsyncReceiver.cpp
    network/AsyncSender.cpp
)

set(PACKET_SOURCES
    packet/PacketParser.cpp
    packet/PacketBuilder.cpp
    packet/PacketValidator.cpp
    packet/ProtocolHandler.cpp
)

set(FORWARDING_SOURCES
    forwarding/Forwarder.cpp
    forwarding/NATTable.cpp
    forwarding/SessionManager.cpp
    forwarding/DNSCache.cpp
)

set(RESOURCE_SOURCES
    resource/ThreadPool.cpp
    resource/ObjectPool.cpp
    resource/MemoryPool.cpp
)

set(UTIL_SOURCES
    util/Logger.cpp
    util/Error.cpp
    util/Metrics.cpp
)

# 所有源文件
set(ALL_SOURCES
    ${CORE_SOURCES}
    ${NETWORK_SOURCES}
    ${PACKET_SOURCES}
    ${FORWARDING_SOURCES}
    ${RESOURCE_SOURCES}
    ${UTIL_SOURCES}
)

# ===== 静态库 =====
add_library(vpn_server_lib STATIC ${ALL_SOURCES})

target_include_directories(vpn_server_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(vpn_server_lib PUBLIC
    Threads::Threads
)

if(Boost_FOUND)
    target_link_libraries(vpn_server_lib PUBLIC
        Boost::system
    )
endif()

if(spdlog_FOUND)
    target_link_libraries(vpn_server_lib PUBLIC
        spdlog::spdlog
    )
endif()

# ===== 可执行文件 =====
add_executable(vpn_server main.cpp)
target_link_libraries(vpn_server PRIVATE vpn_server_lib)

# ===== 测试 =====
if(GTest_FOUND)
    add_subdirectory(tests)
endif()

# ===== 性能测试 =====
add_executable(benchmark benchmark/benchmark_main.cpp)
target_link_libraries(benchmark PRIVATE vpn_server_lib)

# ===== 安装 =====
install(TARGETS vpn_server DESTINATION bin)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        DESTINATION include/vpn_server
        FILES_MATCHING PATTERN "*.h")

# ===== 文档 =====
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOXYGEN_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs)
    doxygen_add_docs(docs
        ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation"
    )
endif()

# ===== 代码格式化 =====
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    file(GLOB_RECURSE ALL_CXX_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/*.h
    )
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i ${ALL_CXX_FILES}
        COMMENT "Running clang-format"
    )
endif()

# ===== 静态分析 =====
find_program(CLANG_TIDY clang-tidy)
if(CLANG_TIDY)
    set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY})
endif()

# ===== 打印配置信息 =====
message(STATUS "")
message(STATUS "VPN Proxy Server Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Boost: ${Boost_FOUND}")
message(STATUS "  GTest: ${GTest_FOUND}")
message(STATUS "  spdlog: ${spdlog_FOUND}")
message(STATUS "  Doxygen: ${DOXYGEN_FOUND}")
message(STATUS "")

cmake_minimum_required(VERSION 3.14)

project(rsa LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(OPENSSL_DIR "/usr/local/Cellar/openssl@1.1")

find_package(Qt5Core)

add_executable(rsa
  main.cpp
  rsaalgorithm.h
  rsaalgorithm.cpp

)
target_include_directories(${PROJECT_NAME}

    PUBLIC ${OPENSSL_DIR}/1.1.1i/include
    )
target_link_libraries(rsa Qt${QT_VERSION_MAJOR}::Core
    ${OPENSSL_DIR}/1.1.1i/lib/libssl.a
    ${OPENSSL_DIR}/1.1.1i/lib/libcrypto.a)

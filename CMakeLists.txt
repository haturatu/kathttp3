cmake_minimum_required(VERSION 3.22.1)
project(kathttp VERSION 0.1.0 LANGUAGES C CXX)

option(KATHTTP_BUILD_TESTS "Build host unit tests" ON)
option(KATHTTP_BUILD_JNI "Build the JNI bridge" OFF)
option(KATHTTP_SANITIZE "Enable address and undefined sanitizers" OFF)
option(KATHTTP_ANALYSIS_ONLY "Build compile-only targets for static analysis" OFF)
option(KATHTTP_ENABLE_IWYU "Run include-what-you-use during CMake builds" OFF)
set(KATHTTP_ANALYSIS_DEPS_INCLUDE_DIR "" CACHE PATH
    "Pinned Android dependency include directory used by host static analysis")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

if(KATHTTP_ANALYSIS_ONLY)
  # clang-tidy/cppcheck need a faithful compilation database, but do not need
  # to link ngtcp2/nghttp3.  Keeping this mode link-free makes analysis jobs
  # quick and independent of Android prebuilt artifacts.
  set(KATHTTP_DEP_TARGETS)
  if(KATHTTP_ANALYSIS_DEPS_INCLUDE_DIR)
    if(NOT EXISTS "${KATHTTP_ANALYSIS_DEPS_INCLUDE_DIR}/ngtcp2/ngtcp2.h")
      message(FATAL_ERROR
        "KATHTTP_ANALYSIS_DEPS_INCLUDE_DIR does not contain pinned ngtcp2 headers: "
        "${KATHTTP_ANALYSIS_DEPS_INCLUDE_DIR}")
    endif()
    set(KATHTTP_DEP_INCLUDE_DIR "${KATHTTP_ANALYSIS_DEPS_INCLUDE_DIR}")
  endif()
elseif(ANDROID)
  set(KATHTTP_DEPS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/android-deps" CACHE PATH "Root containing <ABI>/include and <ABI>/lib pinned dependencies")
  if(NOT KATHTTP_DEPS_ROOT)
    message(FATAL_ERROR "Android requires -DKATHTTP_DEPS_ROOT=<prebuilt root>; see README.md")
  endif()
  add_library(ngtcp2 STATIC IMPORTED)
  set_target_properties(ngtcp2 PROPERTIES IMPORTED_LOCATION "${KATHTTP_DEPS_ROOT}/${ANDROID_ABI}/lib/libngtcp2.a")
  add_library(nghttp3 STATIC IMPORTED)
  set_target_properties(nghttp3 PROPERTIES IMPORTED_LOCATION "${KATHTTP_DEPS_ROOT}/${ANDROID_ABI}/lib/libnghttp3.a")
  add_library(ngtcp2_crypto STATIC IMPORTED)
  set_target_properties(ngtcp2_crypto PROPERTIES IMPORTED_LOCATION "${KATHTTP_DEPS_ROOT}/${ANDROID_ABI}/lib/libngtcp2_crypto_boringssl.a")
  add_library(ssl STATIC IMPORTED)
  set_target_properties(ssl PROPERTIES IMPORTED_LOCATION "${KATHTTP_DEPS_ROOT}/${ANDROID_ABI}/lib/libssl.a")
  add_library(crypto STATIC IMPORTED)
  set_target_properties(crypto PROPERTIES IMPORTED_LOCATION "${KATHTTP_DEPS_ROOT}/${ANDROID_ABI}/lib/libcrypto.a")
  set(KATHTTP_DEP_TARGETS ngtcp2 nghttp3 ngtcp2_crypto ssl crypto)
  set(KATHTTP_DEP_INCLUDE_DIR "${KATHTTP_DEPS_ROOT}/${ANDROID_ABI}/include")
  add_compile_definitions(KATHTTP_USE_BORINGSSL)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(NGTCP2 REQUIRED IMPORTED_TARGET libngtcp2)
  pkg_check_modules(NGHTTP3 REQUIRED IMPORTED_TARGET libnghttp3)
  if(KATHTTP_USE_BORINGSSL)
    pkg_check_modules(NGTCP2_CRYPTO REQUIRED IMPORTED_TARGET libngtcp2_crypto_boringssl)
    add_compile_definitions(KATHTTP_USE_BORINGSSL)
  else()
    pkg_check_modules(NGTCP2_CRYPTO REQUIRED IMPORTED_TARGET libngtcp2_crypto_ossl)
  endif()
  set(KATHTTP_DEP_TARGETS PkgConfig::NGTCP2 PkgConfig::NGHTTP3 PkgConfig::NGTCP2_CRYPTO)
endif()

set(KATHTTP_CORE_SOURCES
  src/core/cookie_jar.cc src/core/dns.cc
  src/core/engine.cc src/core/header_list.cc src/core/http3_session.cc
  src/core/quic_client.cc src/core/redirect.cc src/core/request.cc
  src/core/tls.cc src/core/cert_verifier.cc
  src/core/udp_socket.cc src/core/url.cc)

if(KATHTTP_ANALYSIS_ONLY)
  # Keep the production sources in compile_commands.json for clang-tidy, but
  # do not make them part of the default build.  This lets the sanitizer job
  # exercise the dependency-free unit-test target without requiring a host
  # ngtcp2/nghttp3 installation.
  add_library(kathttp OBJECT EXCLUDE_FROM_ALL ${KATHTTP_CORE_SOURCES})
else()
  add_library(kathttp SHARED ${KATHTTP_CORE_SOURCES})
endif()
target_include_directories(kathttp PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(kathttp PRIVATE src/core)
if(KATHTTP_DEP_INCLUDE_DIR)
  target_include_directories(kathttp SYSTEM PRIVATE "${KATHTTP_DEP_INCLUDE_DIR}")
endif()
target_compile_definitions(kathttp PRIVATE KATHTTP_BUILDING_LIBRARY)
if(KATHTTP_ANALYSIS_ONLY AND KATHTTP_DEP_INCLUDE_DIR)
  # Analyse against exactly the Android production backend, not distro
  # packages whose ngtcp2/nghttp3 API version can differ from our pins.
  target_compile_definitions(kathttp PRIVATE KATHTTP_USE_BORINGSSL)
endif()
target_compile_options(kathttp PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
  -Wformat=2 -Wundef -Wcast-align -Wnull-dereference -Wdouble-promotion)
if(NOT KATHTTP_ANALYSIS_ONLY)
  target_link_libraries(kathttp PRIVATE ${KATHTTP_DEP_TARGETS})
endif()
if(NOT ANDROID)
  target_link_libraries(kathttp PRIVATE pthread)
endif()
if(ANDROID AND NOT KATHTTP_ANALYSIS_ONLY)
  target_link_libraries(kathttp PRIVATE log)
endif()
if(ANDROID)
  # NDK r27 defaults to 4 KB ELF load-segment alignment.  Android 15 devices
  # can use 16 KB pages, where an unaligned libkathttp.so fails to load.
  # Keep both linker options explicit so the AAR is compatible regardless of
  # whether this CMake project is invoked through Gradle or directly.
  target_link_options(kathttp PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384")
endif()
if(KATHTTP_SANITIZE AND NOT ANDROID)
  target_compile_options(kathttp PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(kathttp PRIVATE -fsanitize=address,undefined)
endif()

if(KATHTTP_ENABLE_IWYU)
  find_program(KATHTTP_IWYU_EXECUTABLE NAMES include-what-you-use REQUIRED)
  set_property(TARGET kathttp PROPERTY CXX_INCLUDE_WHAT_YOU_USE
               "${KATHTTP_IWYU_EXECUTABLE}")
endif()

if(KATHTTP_BUILD_JNI)
  target_sources(kathttp PRIVATE src/jni/kathttp_jni.cc
                             src/jni/android_cert_verifier.cc)
  if(NOT ANDROID)
    find_package(JNI REQUIRED)
    target_include_directories(kathttp PRIVATE ${JNI_INCLUDE_DIRS})
  endif()
endif()

if(KATHTTP_BUILD_TESTS AND NOT ANDROID)
  enable_testing()
  add_executable(kathttp_core_tests tests/core/core_tests.cc
    src/core/url.cc src/core/header_list.cc src/core/redirect.cc
    src/core/cookie_jar.cc src/core/dns.cc)
  target_include_directories(kathttp_core_tests PRIVATE src/core)
  target_compile_options(kathttp_core_tests PRIVATE -Wall -Wextra -Wpedantic)
  target_link_libraries(kathttp_core_tests PRIVATE pthread)
  if(KATHTTP_SANITIZE)
    target_compile_options(kathttp_core_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(kathttp_core_tests PRIVATE -fsanitize=address,undefined)
  endif()
  add_test(NAME kathttp_core_tests COMMAND kathttp_core_tests)
endif()

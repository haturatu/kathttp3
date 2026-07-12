#!/usr/bin/env bash
set -euo pipefail

readonly NGTCP2_VERSION="v1.24.0"
readonly NGHTTP3_VERSION="v1.17.0"
# This is the BoringSSL revision used by ngtcp2 v1.24.0 upstream CI.
readonly BORINGSSL_REVISION="3c6315e00ab02d7bc9b8922aff1f85d8f81ee130"
readonly ANDROID_API=26
readonly ALL_ABIS=(arm64-v8a armeabi-v7a x86_64 x86)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="${ROOT_DIR}/third_party/src"
BUILD_DIR="${ROOT_DIR}/third_party/build-android"
OUTPUT_DIR="${ROOT_DIR}/third_party/android-deps"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
declare -a ABIS=()
CLEAN=0

usage() {
  cat <<EOF
Usage: $0 [--clean] [--abi ABI]... [--jobs N]

Builds pinned BoringSSL, nghttp3 and ngtcp2 static libraries with Android NDK.
Supported ABIs: ${ALL_ABIS[*]}
EOF
}

while (($#)); do
  case "$1" in
    --clean) CLEAN=1; shift ;;
    --abi) [[ $# -ge 2 ]] || { echo "--abi requires a value" >&2; exit 2; }; ABIS+=("$2"); shift 2 ;;
    --jobs) [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || { echo "--jobs requires a positive integer" >&2; exit 2; }; JOBS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if ((${#ABIS[@]} == 0)); then ABIS=("${ALL_ABIS[@]}"); fi
for abi in "${ABIS[@]}"; do
  [[ " ${ALL_ABIS[*]} " == *" ${abi} "* ]] || { echo "Unsupported ABI: ${abi}" >&2; exit 2; }
done

find_ndk() {
  local candidate sdk best=""
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
    [[ -n "$candidate" && -f "$candidate/build/cmake/android.toolchain.cmake" ]] && { printf '%s\n' "$candidate"; return; }
  done
  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}"; do
    [[ -n "$sdk" ]] || continue
    if [[ -f "$sdk/ndk/27.0.12077973/build/cmake/android.toolchain.cmake" ]]; then
      printf '%s\n' "$sdk/ndk/27.0.12077973"; return
    fi
    best="$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | sort -V | tail -1)"
    [[ -n "$best" && -f "$best/build/cmake/android.toolchain.cmake" ]] && { printf '%s\n' "$best"; return; }
  done
  if [[ -f "${ROOT_DIR}/local.properties" ]]; then
    candidate="$(sed -n 's/^ndk\.dir=//p' "${ROOT_DIR}/local.properties" | tail -1 | sed 's/\\:/:/g; s/\\\\/\\/g')"
    [[ -n "$candidate" && -f "$candidate/build/cmake/android.toolchain.cmake" ]] && { printf '%s\n' "$candidate"; return; }
  fi
  echo "Android NDK was not found. Set ANDROID_NDK_HOME, ANDROID_SDK_ROOT, or ANDROID_HOME." >&2
  exit 2
}

NDK="$(find_ndk)"
TOOLCHAIN="${NDK}/build/cmake/android.toolchain.cmake"
echo "Using Android NDK: ${NDK}"
if command -v ninja >/dev/null 2>&1; then
  CMAKE_GENERATOR=("-G" "Ninja")
else
  CMAKE_GENERATOR=("-G" "Unix Makefiles")
fi

if ((CLEAN)); then
  rm -rf "${BUILD_DIR}"
  for abi in "${ABIS[@]}"; do rm -rf "${OUTPUT_DIR:?}/${abi}"; done
fi
mkdir -p "${SOURCE_DIR}" "${BUILD_DIR}" "${OUTPUT_DIR}" "${ROOT_DIR}/.tmp"
export TMPDIR="${ROOT_DIR}/.tmp"

checkout_source() {
  local name="$1" url="$2" revision="$3" dir="${SOURCE_DIR}/$1"
  if [[ ! -d "$dir/.git" ]]; then
    rm -rf "$dir"
    git clone --filter=blob:none --no-checkout "$url" "$dir"
  fi
  if ! git -C "$dir" cat-file -e "${revision}^{commit}" 2>/dev/null; then
    git -C "$dir" fetch --depth 1 origin "$revision"
  fi
  git -C "$dir" checkout --detach --force "$revision" >&2
  git -C "$dir" submodule update --init --recursive --depth 1 >&2
  printf '%s\n' "$dir"
}

BORINGSSL_SRC="$(checkout_source boringssl https://boringssl.googlesource.com/boringssl "${BORINGSSL_REVISION}")"
NGHTTP3_SRC="$(checkout_source nghttp3 https://github.com/ngtcp2/nghttp3.git "${NGHTTP3_VERSION}")"
NGTCP2_SRC="$(checkout_source ngtcp2 https://github.com/ngtcp2/ngtcp2.git "${NGTCP2_VERSION}")"

build_abi() {
  local abi="$1" prefix="${OUTPUT_DIR}/${abi}"
  local bssl_build="${BUILD_DIR}/boringssl-${abi}"
  local h3_build="${BUILD_DIR}/nghttp3-${abi}"
  local tcp2_build="${BUILD_DIR}/ngtcp2-${abi}"
  mkdir -p "${prefix}/include" "${prefix}/lib"

  echo "==> [${abi}] BoringSSL ${BORINGSSL_REVISION}"
  cmake -S "${BORINGSSL_SRC}" -B "${bssl_build}" "${CMAKE_GENERATOR[@]}" \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" -DANDROID_ABI="${abi}" \
    -DANDROID_PLATFORM="android-${ANDROID_API}" -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DBORINGSSL_ALLOW_CXX_RUNTIME=ON
  cmake --build "${bssl_build}" --target ssl crypto --parallel "${JOBS}"
  cp -f "${bssl_build}/libssl.a" "${prefix}/lib/libssl.a"
  cp -f "${bssl_build}/libcrypto.a" "${prefix}/lib/libcrypto.a"
  rm -rf "${prefix}/include/openssl"
  cp -R "${BORINGSSL_SRC}/include/openssl" "${prefix}/include/openssl"

  echo "==> [${abi}] nghttp3 ${NGHTTP3_VERSION}"
  cmake -S "${NGHTTP3_SRC}" -B "${h3_build}" "${CMAKE_GENERATOR[@]}" \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" -DANDROID_ABI="${abi}" \
    -DANDROID_PLATFORM="android-${ANDROID_API}" -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${prefix}" \
    -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_LIB_ONLY=ON \
    -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF
  cmake --build "${h3_build}" --parallel "${JOBS}"
  cmake --install "${h3_build}"

  echo "==> [${abi}] ngtcp2 ${NGTCP2_VERSION} + BoringSSL"
  cmake -S "${NGTCP2_SRC}" -B "${tcp2_build}" "${CMAKE_GENERATOR[@]}" \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN}" -DANDROID_ABI="${abi}" \
    -DANDROID_PLATFORM="android-${ANDROID_API}" -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${prefix}" \
    -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_LIB_ONLY=ON \
    -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF \
    -DENABLE_OPENSSL=OFF -DENABLE_BORINGSSL=ON \
    -DBORINGSSL_INCLUDE_DIR="${prefix}/include" \
    -DBORINGSSL_LIBRARIES="${prefix}/lib/libssl.a;${prefix}/lib/libcrypto.a"
  cmake --build "${tcp2_build}" --parallel "${JOBS}"
  cmake --install "${tcp2_build}"

  for lib in libssl.a libcrypto.a libnghttp3.a libngtcp2.a libngtcp2_crypto_boringssl.a; do
    [[ -s "${prefix}/lib/${lib}" ]] || { echo "Missing output: ${prefix}/lib/${lib}" >&2; exit 1; }
  done
  printf '%s\n' "BoringSSL=${BORINGSSL_REVISION}" "nghttp3=${NGHTTP3_VERSION}" "ngtcp2=${NGTCP2_VERSION}" "android_api=${ANDROID_API}" > "${prefix}/versions.txt"
  echo "==> [${abi}] complete: ${prefix}"
}

for abi in "${ABIS[@]}"; do build_abi "$abi"; done

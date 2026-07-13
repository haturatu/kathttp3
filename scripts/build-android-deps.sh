#!/usr/bin/env bash
set -euo pipefail

readonly ANDROID_API=26
readonly BUILD_RECIPE_VERSION=3
readonly ANDROID_CMAKE_VERSION=3.22.1
readonly ANDROID_CMAKE_ARCHIVE_URL="https://dl.google.com/android/repository/cmake-3.22.1-linux.zip"
readonly ANDROID_CMAKE_ARCHIVE_SHA256="9196644852a978012caf7a4067ba1898debf6cc204c3341562771e31080d6869"
readonly ALL_ABIS=(arm64-v8a armeabi-v7a x86_64 x86)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load the single source of truth for dependency revisions.
readonly VERSIONS_FILE="${ROOT_DIR}/third_party/versions.env"
if [[ ! -f "${VERSIONS_FILE}" ]]; then
  echo "Missing ${VERSIONS_FILE}" >&2
  exit 1
fi
set -a
# shellcheck source=/dev/null
source "${VERSIONS_FILE}"
set +a
readonly NGTCP2_VERSION="${KATHTTP3_NGTCP2_VERSION}"
readonly NGHTTP3_VERSION="${KATHTTP3_NGHTTP3_VERSION}"
# This is the BoringSSL revision used by ngtcp2 v1.24.0 upstream CI.
readonly BORINGSSL_REVISION="${KATHTTP3_BORINGSSL_REVISION}"
SOURCE_DIR="${ROOT_DIR}/third_party/src"
BUILD_DIR="${ROOT_DIR}/third_party/build-android"
OUTPUT_DIR="${ROOT_DIR}/third_party/android-deps"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
ABI_PARALLELISM=1
declare -a ABIS=()
CLEAN=0

usage() {
  cat <<EOF
Usage: $0 [--clean] [--abi ABI]... [--jobs N] [--parallel-abis N]

Builds pinned BoringSSL, nghttp3 and ngtcp2 static libraries with Android NDK.
Supported ABIs: ${ALL_ABIS[*]}.  --jobs is the per-ABI build parallelism;
--parallel-abis controls independent ABI builds (default: 1).
EOF
}

while (($#)); do
  case "$1" in
    --clean) CLEAN=1; shift ;;
    --abi) [[ $# -ge 2 ]] || { echo "--abi requires a value" >&2; exit 2; }; ABIS+=("$2"); shift 2 ;;
    --jobs) [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || { echo "--jobs requires a positive integer" >&2; exit 2; }; JOBS="$2"; shift 2 ;;
    --parallel-abis) [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || { echo "--parallel-abis requires a positive integer" >&2; exit 2; }; ABI_PARALLELISM="$2"; shift 2 ;;
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

find_sdkmanager() {
  local candidate sdk ndk_sdk
  # Prefer explicit SDK locations, but also derive the SDK root from an NDK
  # installed at <sdk>/ndk/<revision>.  The latter is useful on JitPack where
  # AGP resolves the NDK before this script is invoked.
  ndk_sdk="$(cd "${NDK}/../.." && pwd)"
  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "${ndk_sdk}"; do
    [[ -n "${sdk}" ]] || continue
    for candidate in "${sdk}/cmdline-tools/latest/bin/sdkmanager" \
      "${sdk}/cmdline-tools/bin/sdkmanager" "${sdk}/tools/bin/sdkmanager"; do
      if [[ -x "${candidate}" ]]; then
        printf '%s\n' "${candidate}"
        return
      fi
    done
  done
  return 1
}

find_android_sdk_root() {
  local ndk_sdk sdk
  ndk_sdk="$(cd "${NDK}/../.." && pwd)"
  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "${ndk_sdk}"; do
    [[ -n "${sdk}" && -d "${sdk}" ]] || continue
    printf '%s\n' "${sdk}"
    return
  done
  return 1
}

install_cmake_archive() {
  local archive sdk target
  sdk="$(find_android_sdk_root)" || {
    echo "Android SDK root was not found while bootstrapping CMake." >&2
    return 1
  }
  target="${sdk}/cmake/${ANDROID_CMAKE_VERSION}"
  archive="$(mktemp "${TMPDIR:-/tmp}/kathttp3-cmake.XXXXXX")"

  echo "Downloading Android SDK CMake ${ANDROID_CMAKE_VERSION} from its pinned official archive." >&2
  curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
    "${ANDROID_CMAKE_ARCHIVE_URL}" --output "${archive}"
  printf '%s  %s\n' "${ANDROID_CMAKE_ARCHIVE_SHA256}" "${archive}" | sha256sum -c - >&2
  mkdir -p "${target}"
  if command -v unzip >/dev/null 2>&1; then
    unzip -q -o "${archive}" -d "${target}"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
      "${archive}" "${target}"
  else
    echo "Neither unzip nor python3 is available to extract the CMake archive." >&2
    return 1
  fi
  rm -f "${archive}"
  chmod +x "${target}/bin/cmake"
}

ensure_cmake() {
  local candidate sdk sdkmanager ndk_sdk
  if command -v cmake >/dev/null 2>&1; then
    return
  fi

  ndk_sdk="$(cd "${NDK}/../.." && pwd)"
  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "${ndk_sdk}"; do
    [[ -n "${sdk}" ]] || continue
    candidate="${sdk}/cmake/${ANDROID_CMAKE_VERSION}/bin"
    if [[ -x "${candidate}/cmake" ]]; then
      export PATH="${candidate}:${PATH}"
      return
    fi
  done

  # JitPack's legacy sdkmanager fails under Java 17 because its JAXB classes
  # are absent.  The official archive has the same fixed SDK package layout,
  # so install it directly instead of relying on the host Java runtime.
  install_cmake_archive

  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "${ndk_sdk}"; do
    [[ -n "${sdk}" ]] || continue
    candidate="${sdk}/cmake/${ANDROID_CMAKE_VERSION}/bin"
    if [[ -x "${candidate}/cmake" ]]; then
      export PATH="${candidate}:${PATH}"
      return
    fi
  done

  # Keep a standard SDK Manager fallback for unusual SDK layouts after the
  # archive attempt.  Its failure is intentionally non-fatal here.
  if sdkmanager="$(find_sdkmanager 2>/dev/null)"; then
    "${sdkmanager}" --install "cmake;${ANDROID_CMAKE_VERSION}" || true
  fi

  echo "Android SDK CMake ${ANDROID_CMAKE_VERSION} was installed but could not be located." >&2
  exit 2
}

ensure_cmake
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
    git clone --no-checkout "$url" "$dir"
  fi
  if ! git -C "$dir" cat-file -e "${revision}^{commit}" 2>/dev/null; then
    git -C "$dir" fetch --depth 1 origin "$revision"
  fi
  git -C "$dir" checkout --detach --force "$revision" >&2
  # Pinned nghttp3/ngtcp2 tags can reference submodule commits that are older
  # than the submodule's tip.  A shallow update cannot resolve those commits
  # on JitPack, so retain the history needed for an exact checkout.
  git -C "$dir" submodule update --init --recursive >&2
  printf '%s\n' "$dir"
}

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
  printf '%s\n' "BoringSSL=${BORINGSSL_REVISION}" "nghttp3=${NGHTTP3_VERSION}" "ngtcp2=${NGTCP2_VERSION}" "android_api=${ANDROID_API}" "build_recipe=${BUILD_RECIPE_VERSION}" > "${prefix}/versions.txt"
  echo "==> [${abi}] complete: ${prefix}"
}

abi_is_complete() {
  local abi="$1"
  local prefix="${OUTPUT_DIR}/${abi}"
  local versions="${prefix}/versions.txt"
  [[ -f "${versions}" ]] || return 1
  grep -Fqx "BoringSSL=${BORINGSSL_REVISION}" "${versions}" || return 1
  grep -Fqx "nghttp3=${NGHTTP3_VERSION}" "${versions}" || return 1
  grep -Fqx "ngtcp2=${NGTCP2_VERSION}" "${versions}" || return 1
  grep -Fqx "android_api=${ANDROID_API}" "${versions}" || return 1
  grep -Fqx "build_recipe=${BUILD_RECIPE_VERSION}" "${versions}" || return 1
  [[ -d "${prefix}/include/openssl" ]] || return 1
  local lib
  for lib in libssl.a libcrypto.a libnghttp3.a libngtcp2.a libngtcp2_crypto_boringssl.a; do
    [[ -s "${prefix}/lib/${lib}" ]] || return 1
  done
}

needs_build=0
for abi in "${ABIS[@]}"; do
  if ! abi_is_complete "${abi}"; then
    needs_build=1
    break
  fi
done

if ((needs_build)); then
  BORINGSSL_SRC="$(checkout_source boringssl https://boringssl.googlesource.com/boringssl "${BORINGSSL_REVISION}")"
  NGHTTP3_SRC="$(checkout_source nghttp3 https://github.com/ngtcp2/nghttp3.git "${NGHTTP3_VERSION}")"
  NGTCP2_SRC="$(checkout_source ngtcp2 https://github.com/ngtcp2/ngtcp2.git "${NGTCP2_VERSION}")"
fi

build_or_skip_abi() {
  local abi="$1"
  # CMake and compiler temporary files are isolated per ABI as well.  This
  # permits multiple ABI builds without sharing a writable temporary path.
  (
    export TMPDIR="${ROOT_DIR}/.tmp/${abi}"
    mkdir -p "${TMPDIR}"
    if abi_is_complete "${abi}"; then
      echo "==> [${abi}] cached output is complete; skipping rebuild"
    else
      build_abi "${abi}"
    fi
  )
}

BUILD_PIDS=""
active_builds=0
for abi in "${ABIS[@]}"; do
  build_or_skip_abi "${abi}" &
  BUILD_PIDS+=" $!"
  ((active_builds += 1))
  # Limit simultaneously active ABI builds.  Each build uses --jobs workers,
  # so this avoids oversubscribing small GitHub-hosted runners.
  if ((active_builds >= ABI_PARALLELISM)); then
    for pid in ${BUILD_PIDS}; do
      wait "${pid}"
    done
    BUILD_PIDS=""
    active_builds=0
  fi
done
for pid in ${BUILD_PIDS:-}; do
  wait "${pid}"
done

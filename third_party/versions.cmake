# Load dependency versions from versions.env (the single source of truth).
# scripts/build-android-deps.sh sources the same file; keep them in sync by
# editing versions.env only. This file exists so CMake consumers can read the
# pinned revisions via cache variables.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/versions.env" _kathttp3_version_lines)
foreach(_kathttp3_line ${_kathttp3_version_lines})
  if(_kathttp3_line MATCHES "^(KATHTTP3_[A-Z0-9_]+)=(.+)$")
    set(${CMAKE_MATCH_1} "${CMAKE_MATCH_2}" CACHE STRING "KatHttp3 pinned dependency version")
  endif()
endforeach()

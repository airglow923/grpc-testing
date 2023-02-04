#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)
CMAKE=$(command -v cmake &>/dev/null && echo "cmake" || echo "cmake3")
CMAKE_GENERATOR=$(command -v ninja &>/dev/null && echo "Ninja" || echo "Unix Makefiles")

BUILD_DIR=${CMAKE_BUILD_DIR:-"${ROOT_DIR}/build"}
BUILD_TYPE=${CMAKE_BUILD_TYPE:-"Release"}
INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX:-"/opt/hyundeok/"}
ASAN_OPTIONS="${ASAN_OPTIONS:-allow_user_poisoning=1,use_sigaltstack=0,halt_on_error=1,detect_stack_use_after_return=1,alloc_dealloc_mismatch=0}"
CMAKE_OPTIONS=${CMAKE_OPTIONS:-}

do_clean=
do_rm_build_dir=

while getopts "o:t:adbcCT" arg; do
  case "$arg" in
  o)
    BUILD_DIR=${OPTARG}
    ;;

  t)
    BUILD_TYPE=${OPTARG}
    ;;

  a)
    CMAKE_OPTIONS="-D DO_ADDRESS_SANITIZER=1 ${CMAKE_OPTIONS}"

    export ASAN_OPTIONS
    ;;

  T)
    CMAKE_OPTIONS="-D DO_THREAD_SANITIZER=1 ${CMAKE_OPTIONS}"
    ;;

  d)
    CMAKE_OPTIONS="-D DO_COVERAGE=1 ${CMAKE_OPTIONS}"
    ;;

  b)
    CMAKE_OPTIONS="-D DO_TEST=1 ${CMAKE_OPTIONS}"
    ;;

  c)
    do_clean=1
    ;;

  C)
    do_rm_build_dir=1
    ;;

  *)
    echo -e \\n"Option -$OPTARG not allowed."
    ;;
  esac
done

shift $((OPTIND - 1))

mkdir -p build

if [ $do_rm_build_dir ]; then
  rm -rf "${BUILD_DIR}"
fi

if [ ! $do_rm_build_dir ] && [ $do_clean ]; then
  ${CMAKE} --build "${BUILD_DIR}" --target clean
fi

${CMAKE} \
  -B "${BUILD_DIR}" \
  -G "${CMAKE_GENERATOR}" \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
  "${CMAKE_OPTIONS}" \
  "${ROOT_DIR}"

${CMAKE} --build "${BUILD_DIR}" -j "$(nproc)"

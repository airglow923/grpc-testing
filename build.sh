#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)
CMAKE=$(command -v cmake &>/dev/null && echo "cmake" || echo "cmake3")
CMAKE_GENERATOR=$(command -v ninja &>/dev/null && echo "Ninja" || echo "Unix Makefiles")

BUILD_DIR=${CMAKE_BUILD_DIR:-"${ROOT_DIR}/build"}
BUILD_TYPE=${CMAKE_BUILD_TYPE:-"Release"}
INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX:-"/opt/hyundeok/"}
ASAN_OPTIONS="${ASAN_OPTIONS:-allow_user_poisoning=1,use_sigaltstack=0,halt_on_error=1,detect_stack_use_after_return=1,alloc_dealloc_mismatch=0}"
TSAN_OPTIONS="${TSAN_OPTIONS:-}"
CMAKE_OPTIONS=${CMAKE_OPTIONS:-}

usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [OPTIONS...]
Script description here.
Available options:
-h, --help              Print this help and exit
-o, --build-dir         Set build directory; default to "build"
-t, --build-type        Set CMAKE_BUILD_TYPE
-a, --asan              Enable Address Sanitizer
-T, --tsan              Enable Thread Sanitizer
-d, --coverage          Enable coverage
-c, --clean             Run "${CMAKE} --build BUILD_DIR --target clean"
-C, --remove-build-dir  Remove BUILD_DIR
-i, --install           Install
-u, --uninstall         Uninstall
EOF
  exit
}

msg() {
  echo >&2 -e "${1-}"
}

die() {
  local msg=$1
  local code=${2-1}
  msg "$msg"
  exit "$code"
}

is_true() {
  if [ "${1}" = "1" ] || [ "${1}" = "true" ]; then
    echo "1"
  else
    echo "0"
  fi
}

is_false() {
  if [ "${1}" = "0" ] || [ "${1}" = "false" ]; then
    echo "1"
  else
    echo "0"
  fi
}

parse_params() {
  do_clean=false
  do_rm_build_dir=false
  install=false
  uninstall=false

  while :; do
    case "${1-}" in
    -h | --help)
      usage
      ;;

    -o | --build-dir)
      BUILD_DIR="${2-}"
      shift
      ;;

    -t | --build-type)
      BUILD_DIR="${2-}"
      shift
      ;;

    -a | --asan)
      CMAKE_OPTIONS="-D DO_ADDRESS_SANITIZER=1 ${CMAKE_OPTIONS}"
      export ASAN_OPTIONS
      ;;

    -T | --tsan)
      CMAKE_OPTIONS="-D DO_THREAD_SANITIZER=1 ${CMAKE_OPTIONS}"
      export TSAN_OPTIONS
      ;;

    -d | --coverage)
      CMAKE_OPTIONS="-D DO_COVERAGE=1 ${CMAKE_OPTIONS}"
      ;;

    -c | --clean)
      do_clean=true
      ;;

    -C | --remove-build-dir)
      do_rm_build_dir=true
      ;;

    -i | --install)
      install=true
      ;;

    -u | --uninstall)
      uninstall=true
      ;;

    -?*)
      die "Unknown option: $1"
      ;;

    *)
      break
      ;;
    esac
    shift
  done

  if (($(is_true "${install}"))) && (($(is_true "${uninstall}"))); then
    die "Please select either install or uninstall."
  fi

  return 0
}

parse_params "$@"

mkdir -p "${BUILD_DIR}"

if (($(is_true "${uninstall}"))); then
  "${CMAKE}" --build "${BUILD_DIR}" --target uninstall
  exit
fi

if (($(is_true "${do_rm_build_dir}"))); then
  rm -rf "${BUILD_DIR}"
fi

if (($(is_false "${do_rm_build_dir}"))) && (($(is_true "${do_clean}"))); then
  ${CMAKE} --build "${BUILD_DIR}" --target clean
fi

"${CMAKE}" \
  -B "${BUILD_DIR}" \
  -G "${CMAKE_GENERATOR}" \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
  "${CMAKE_OPTIONS}" \
  "${ROOT_DIR}"

${CMAKE} --build "${BUILD_DIR}" -j "$(nproc)"

if (($(is_true "${install}"))); then
  "${CMAKE}" --build "${BUILD_DIR}" --target install
fi

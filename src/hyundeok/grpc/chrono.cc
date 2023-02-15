#include "hyundeok/grpc/chrono.h"

#include <chrono>
#include <locale>
#include <string>

#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ostream.h>

namespace hyundeok::grpc {

auto
GetLocalTimestampIso8601() -> std::string {
  std::chrono::time_point t = std::chrono::system_clock::now();

  return fmt::format(std::locale::classic(), "{:%FT%TZ}", t);
}

} // namespace hyundeok::grpc

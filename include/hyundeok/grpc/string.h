#pragma once

#include <string>

namespace hyundeok::grpc {

auto
BytesToString(unsigned char *data, std::size_t len) -> std::string;

} // namespace hyundeok::grpc

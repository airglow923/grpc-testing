#pragma once

#include <string>
#include <string_view>

namespace hyundeok::grpc {

auto
PemX509Read(std::string_view path, std::string_view pass) -> std::string;

auto
PemPrivateKeyRead(std::string_view path, std::string_view pass) -> std::string;

auto
PemPublicKeyRead(std::string_view path, std::string_view password)
    -> std::string;

auto
PemPublicKeyReadHex(std::string_view path, std::string_view pass)
    -> std::string;

} // namespace hyundeok::grpc

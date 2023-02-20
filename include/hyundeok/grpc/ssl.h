#pragma once

#include <chrono>
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

auto
PemX509NewRoot(std::string_view country, std::string_view state,
               std::string_view locality, std::string_view organisation,
               std::string_view organisational_unit,
               std::string_view common_name, const std::chrono::seconds &expiry)
    -> std::string;

} // namespace hyundeok::grpc

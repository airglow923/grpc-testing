#pragma once

#include <string>
#include <string_view>

namespace hyundeok::grpc {

auto
GetPubKeyFromPem(std::string_view path, std::string_view password)
    -> std::string;

}

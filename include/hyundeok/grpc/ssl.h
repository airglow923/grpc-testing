#pragma once

#include <cstddef>

#include <chrono>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>

#include <openssl/evp.h>
#include <openssl/types.h>
#include <openssl/x509.h>

namespace hyundeok::grpc {

using SmartEvpPkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using SmartEvpPkeyCtx =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using SmartX509 = std::unique_ptr<X509, decltype(&X509_free)>;
using SmartX509Name = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using SmartX509Extension =
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using SmartFile = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

auto
X509New(EVP_PKEY *pubkey, EVP_PKEY *privkey, const X509_NAME *issuer_name,
        const X509_NAME *subject_name,
        const std::initializer_list<std::pair<int, std::string>> &exs,
        const std::chrono::seconds &expiry) -> SmartX509;
auto
X509Read(std::string_view path, std::string_view pass) -> SmartX509;

auto
X509ReadPubKey(std::string_view path, std::string_view password) -> std::string;

auto
X509Write(const X509 *x509, std::string_view dest) -> int;

auto
EvpPkeyReadPrivKey(std::string_view path, std::string_view pass)
    -> SmartEvpPkey;

auto
EvpPkeyWritePrivKey(const EVP_PKEY *pkey, const EVP_CIPHER *enc,
                    std::string_view pass, std::string_view dest) -> int;

} // namespace hyundeok::grpc

#include "hyundeok/grpc/ssl.h"

#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include <fmt/ostream.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "hyundeok/grpc/string.h"

namespace hyundeok::grpc {

auto
GetPubKeyFromPem(std::string_view path, std::string_view password)
    -> std::string {
  std::unique_ptr<std::FILE, int (*)(FILE *)> fp{std::fopen(path.data(), "r"),
                                                 std::fclose};

  if (fp.get() == nullptr) {
    fmt::print(std::cerr, "Cannot open file '{}'\n", path);
    return {};
  }

  std::unique_ptr<X509, void (*)(X509 *)> cert{
      PEM_read_X509(fp.get(), nullptr, nullptr,
                    const_cast<std::string_view::pointer>(password.data())),
      X509_free};

  if (cert.get() == nullptr) {
    fmt::print(std::cerr, "PEM_read_X509 failed\n");
    return {};
  }

  std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> pkey{
      X509_get_pubkey(cert.get()), EVP_PKEY_free};

  if (pkey.get() == nullptr) {
    fmt::print(std::cerr, "X509_get_pubkey failed\n");
    return {};
  }

  std::size_t len = EVP_PKEY_get_size(pkey.get());

  if (len == 0) {
    fmt::print(std::cerr, "EVP_PKEY_get_size failed\n");
    return {};
  }

  std::unique_ptr<unsigned char[]> pub{new unsigned char[len]};

  if (pub.get() == nullptr) {
    fmt::print(std::cerr, "operator new failed\n");
    return {};
  }

  int ret = EVP_PKEY_get_raw_public_key(pkey.get(), pub.get(), &len);

  if (ret != 1) {
    fmt::print("EVP_PKEY_get_raw_public_key failed\n");
    return {};
  }

  return BytesToString(pub.get(), len);
}

} // namespace hyundeok::grpc

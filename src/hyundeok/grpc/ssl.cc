#include "hyundeok/grpc/ssl.h"

#include <chrono>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/ostream.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#include "hyundeok/grpc/string.h"

namespace hyundeok::grpc {

namespace internal {

static char OpenSslErrBuf[120];

auto
EvpPkeyEd25519New() -> SmartEvpPkey {
  int ret;

  SmartEvpPkeyCtx pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                       EVP_PKEY_CTX_free};

  if (pctx.get() == nullptr) {
    fmt::print("EVP_PKEY_CTX_new_id failed\n");
    return {nullptr, nullptr};
  }

  ret = EVP_PKEY_paramgen_init(pctx.get());

  if (ret != 1) {
    fmt::print("EVP_PKEY_paramgen_init failed\n");
    return {nullptr, nullptr};
  }

  ret = EVP_PKEY_keygen_init(pctx.get());

  if (ret != 1) {
    fmt::print("EVP_PKEY_keygen_init failed\n");
    return {nullptr, nullptr};
  }

  EVP_PKEY *ppkey = EVP_PKEY_new();

  ret = EVP_PKEY_keygen(pctx.get(), &ppkey);

  SmartEvpPkey pkey{ppkey, EVP_PKEY_free};

  if (ret != 1) {
    fmt::print("EVP_PKEY_keygen failed\n");
    return {nullptr, nullptr};
  }

  return pkey;
}

auto
X509NameAppendEntry(X509_NAME *name, const char *field, std::string_view value)
    -> int {
  return X509_NAME_add_entry_by_txt(
      name, field, MBSTRING_ASC,
      reinterpret_cast<const unsigned char *>(value.data()), value.size(), -1,
      0);
}

auto
X509NameNew(const std::string &country, const std::string &state,
            const std::string &locality, const std::string &organisation,
            const std::string &organisational_unit,
            const std::string &common_name) -> SmartX509Name {
  int ret;

  SmartX509Name name{X509_NAME_new(), X509_NAME_free};

  if (name.get() == nullptr) {
    fmt::print("X509_NAME_new failed\n");
    return {nullptr, nullptr};
  }

  ret = X509NameAppendEntry(name.get(), "C", country);

  if (ret != 1) {
    fmt::print("X509NameAppendEntry with country failed\n");
    return {nullptr, nullptr};
  }

  ret = X509NameAppendEntry(name.get(), "ST", state);

  if (ret != 1) {
    fmt::print("X509NameAppendEntry with state failed\n");
    return {nullptr, nullptr};
  }

  ret = X509NameAppendEntry(name.get(), "L", locality);

  if (ret != 1) {
    fmt::print("X509NameAppendEntry with locality failed\n");
    return {nullptr, nullptr};
  }

  ret = X509NameAppendEntry(name.get(), "O", organisation);

  if (ret != 1) {
    fmt::print("X509NameAppendEntry with organisation failed\n");
    return {nullptr, nullptr};
  }

  ret = X509NameAppendEntry(name.get(), "OU", organisational_unit);

  if (ret != 1) {
    fmt::print("X509NameAppendEntry with organisational unit failed\n");
    return {nullptr, nullptr};
  }

  ret = X509NameAppendEntry(name.get(), "CN", common_name);

  if (ret != 1) {
    fmt::print("X509NameAppendEntry with common name failed\n");
    return {nullptr, nullptr};
  }

  return name;
}

auto
X509ExtensionAdd(X509 *cert, int nid, std::string_view value) -> int {
  SmartX509Extension ex{
      X509V3_EXT_conf_nid(nullptr, nullptr, nid, value.data()),
      X509_EXTENSION_free};

  if (ex.get() == nullptr) {
    fmt::print("X509V3_EXT_conf_nid failed\n");
    return 0;
  }

  return X509_add_ext(cert, ex.get(), -1);
}
auto
X509NewClient(const X509 *ca, EVP_PKEY *ca_priv_key,
              const X509_NAME *subject_name, const std::chrono::seconds &expiry)
    -> SmartX509 {
  int ret;

  ret = X509_check_private_key(ca, ca_priv_key);

  if (ret != 1) {
    fmt::print("X509_check_private_key failed");
    return {nullptr, nullptr};
  }

  auto *issuer_name = X509_get_subject_name(ca);

  if (issuer_name == nullptr) {
    fmt::print("X509_get_subject_name failed");
    return {nullptr, nullptr};
  }

  auto pubkey = EvpPkeyEd25519New();

  if (pubkey.get() == nullptr) {
    fmt::print("EvpPkeyEd25519New failed\n");
    return {nullptr, nullptr};
  }

  return X509New(pubkey.get(), ca_priv_key, issuer_name, subject_name, {},
                 expiry);
}

} // namespace internal

auto
X509New(EVP_PKEY *pubkey, EVP_PKEY *privkey, const X509_NAME *issuer_name,
        const X509_NAME *subject_name,
        const std::initializer_list<std::pair<int, std::string>> &exs,
        const std::chrono::seconds &expiry) -> SmartX509 {
  int ret;

  SmartX509 x509{X509_new(), X509_free};

  if (x509.get() == nullptr) {
    fmt::print("X509_new failed: %s\n",
               ERR_error_string(ERR_get_error(), internal::OpenSslErrBuf));
    return {nullptr, nullptr};
  }

  // not so important
  X509_set_version(x509.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);

  ASN1_TIME *asn1_time_ret = X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);

  if (asn1_time_ret == nullptr) {
    fmt::print("X509_gmtime_adj failed\n");
    return {nullptr, nullptr};
  }

  asn1_time_ret =
      X509_gmtime_adj(X509_get_notAfter(x509.get()), expiry.count());

  if (asn1_time_ret == nullptr) {
    fmt::print("X509_gmtime_adj failed\n");
    return {nullptr, nullptr};
  }

  ret = X509_set_issuer_name(x509.get(), issuer_name);

  if (ret != 1) {
    fmt::print("X509_set_issuer_name failed\n");
    return {nullptr, nullptr};
  }

  ret = X509_set_subject_name(x509.get(), subject_name);

  if (ret != 1) {
    fmt::print("X509_set_subject_name failed\n");
    return {nullptr, nullptr};
  }

  ret = X509_set_pubkey(x509.get(), pubkey);

  if (ret != 1) {
    fmt::print("X509_set_pubkey failed\n");
    return {nullptr, nullptr};
  }

  for (auto &&[nid, ex] : exs) {
    ret = internal::X509ExtensionAdd(x509.get(), nid, ex.data());

    if (ret != 1) {
      fmt::print("X509ExtensionAdd failed");
      return {nullptr, nullptr};
    }
  }

  ret = X509_sign(x509.get(), privkey, nullptr);

  if (ret == 0) {
    fmt::print("X509_sign failed");
    return {nullptr, nullptr};
  }

  return x509;
}

auto
X509Read(std::string_view path, std::string_view pass) -> SmartX509 {
  SmartFile fp{std::fopen(path.data(), "r"), std::fclose};

  if (fp.get() == nullptr) {
    fmt::print(std::cerr, "Cannot open file '%s'\n", path);
    return {nullptr, nullptr};
  }

  return SmartX509{PEM_read_X509(fp.get(), nullptr, nullptr,
                                 const_cast<char *>(pass.data())),
                   X509_free};
}

auto
X509ReadPubKey(std::string_view path, std::string_view pass) -> std::string {
  auto x509{X509Read(path, pass)};

  if (x509.get() == nullptr) {
    fmt::print(std::cerr, "PEM_read_X509 failed\n");
    return {};
  }

  SmartEvpPkey pkey{X509_get_pubkey(x509.get()), EVP_PKEY_free};

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

auto
X509Write(const X509 *x509, std::string_view dest) -> int {
  SmartFile fp{std::fopen(dest.data(), "w"), std::fclose};

  if (fp.get() == nullptr) {
    fmt::print(std::cerr, "Cannot open file '%s'\n", dest);
    return 0;
  }

  return PEM_write_X509(fp.get(), x509);
}

auto
EvpPkeyReadPrivKey(std::string_view path, std::string_view pass)
    -> SmartEvpPkey {
  SmartFile fp{std::fopen(path.data(), "r"), std::fclose};

  if (fp.get() == nullptr) {
    fmt::print(std::cerr, "Cannot open file '%s'\n", path);
    return {nullptr, nullptr};
  }

  return SmartEvpPkey{PEM_read_PrivateKey(fp.get(), nullptr, nullptr,
                                          const_cast<char *>(pass.data())),
                      EVP_PKEY_free};
}

auto
EvpPkeyWritePrivKey(const EVP_PKEY *pkey, const EVP_CIPHER *enc,
                    std::string_view pass, std::string_view dest) -> int {
  SmartFile fp{std::fopen(dest.data(), "w"), std::fclose};

  if (fp == nullptr) {
    fmt::print(std::cerr, "Cannot open file '%s'\n", dest);
    return 0;
  }

  return PEM_write_PrivateKey(
      fp.get(), pkey, enc, reinterpret_cast<const unsigned char *>(pass.data()),
      pass.size(), nullptr, nullptr);
}

} // namespace hyundeok::grpc

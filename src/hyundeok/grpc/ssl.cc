#include "hyundeok/grpc/ssl.h"

#include <chrono>
#include <initializer_list>
#include <iostream>
#include <istream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/ostream.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#include "hyundeok/grpc/string.h"

namespace hyundeok::grpc {

namespace internal {

using SmartEvpPkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using SmartEvpPkeyCtx =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using SmartX509 = std::unique_ptr<X509, decltype(&X509_free)>;
using SmartX509Name = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using SmartX509Extension =
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using SmartFile = std::unique_ptr<std::FILE, decltype(&std::fclose)>;
using SmartBio = std::unique_ptr<BIO, decltype(&BIO_free)>;

static char OpenSslErrBuf[120];

auto
EvpPkeyEd25519New() -> SmartEvpPkey {
  SmartEvpPkeyCtx pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                       EVP_PKEY_CTX_free};

  if (pctx.get() == nullptr) {
    fmt::print(std::cerr, "EVP_PKEY_CTX_new_id failed\n");
    return {nullptr, nullptr};
  }

  if (EVP_PKEY_paramgen_init(pctx.get()) != 1) {
    fmt::print(std::cerr, "EVP_PKEY_paramgen_init failed\n");
    return {nullptr, nullptr};
  }

  if (EVP_PKEY_keygen_init(pctx.get()) != 1) {
    fmt::print(std::cerr, "EVP_PKEY_keygen_init failed\n");
    return {nullptr, nullptr};
  }

  EVP_PKEY *ppkey = EVP_PKEY_new();

  SmartEvpPkey pkey{ppkey, EVP_PKEY_free};

  if (EVP_PKEY_keygen(pctx.get(), &ppkey) != 1) {
    fmt::print(std::cerr, "EVP_PKEY_keygen failed\n");
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
X509NameNew(std::string_view country, std::string_view state,
            std::string_view locality, std::string_view organisation,
            std::string_view organisational_unit, std::string_view common_name)
    -> SmartX509Name {
  SmartX509Name name{X509_NAME_new(), X509_NAME_free};

  if (name.get() == nullptr) {
    fmt::print(std::cerr, "X509_NAME_new failed\n");
    return {nullptr, nullptr};
  }

  if (X509NameAppendEntry(name.get(), "C", country) != 1) {
    fmt::print(std::cerr, "X509NameAppendEntry with country failed\n");
    return {nullptr, nullptr};
  }

  if (X509NameAppendEntry(name.get(), "ST", state) != 1) {
    fmt::print(std::cerr, "X509NameAppendEntry with state failed\n");
    return {nullptr, nullptr};
  }

  if (X509NameAppendEntry(name.get(), "L", locality) != 1) {
    fmt::print(std::cerr, "X509NameAppendEntry with locality failed\n");
    return {nullptr, nullptr};
  }

  if (X509NameAppendEntry(name.get(), "O", organisation) != 1) {
    fmt::print(std::cerr, "X509NameAppendEntry with organisation failed\n");
    return {nullptr, nullptr};
  }

  if (X509NameAppendEntry(name.get(), "OU", organisational_unit) != 1) {
    fmt::print(std::cerr,
               "X509NameAppendEntry with organisational unit failed\n");
    return {nullptr, nullptr};
  }

  if (X509NameAppendEntry(name.get(), "CN", common_name) != 1) {
    fmt::print(std::cerr, "X509NameAppendEntry with common name failed\n");
    return {nullptr, nullptr};
  }

  return name;
}

auto
X509ExtensionAdd(X509 *issuer, X509 *subject, int nid, std::string_view value)
    -> int {
  X509V3_CTX ctx;

  X509V3_set_ctx(&ctx, issuer ? issuer : subject, subject, nullptr, nullptr, 0);

  SmartX509Extension ex{X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.data()),
                        X509_EXTENSION_free};

  if (ex.get() == nullptr) {
    fmt::print(std::cerr, "X509V3_EXT_conf_nid failed\n");
    return 0;
  }

  return X509_add_ext(subject, ex.get(), -1);
}

auto
PemX509New(X509 *issuer, EVP_PKEY *issuer_pkey, EVP_PKEY *subject_pkey,
           const X509_NAME *subject_name,
           const std::initializer_list<std::pair<int, std::string>> &exs,
           const std::chrono::seconds &expiry) -> SmartX509 {
  SmartX509 x509{X509_new(), X509_free};

  if (x509.get() == nullptr) {
    fmt::print(std::cerr, "X509_new failed: {}\n",
               ERR_error_string(ERR_get_error(), internal::OpenSslErrBuf));
    return {nullptr, nullptr};
  }

  // not so important
  X509_set_version(x509.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);

  ASN1_TIME *asn1_time_ret = X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);

  if (asn1_time_ret == nullptr) {
    fmt::print(std::cerr, "X509_gmtime_adj failed\n");
    return {nullptr, nullptr};
  }

  asn1_time_ret =
      X509_gmtime_adj(X509_get_notAfter(x509.get()), expiry.count());

  if (asn1_time_ret == nullptr) {
    fmt::print(std::cerr, "X509_gmtime_adj failed\n");
    return {nullptr, nullptr};
  }

  if (issuer == nullptr) {
    if (X509_set_issuer_name(x509.get(), subject_name) != 1) {
      fmt::print(std::cerr, "X509_set_issuer_name failed\n");
      return {nullptr, nullptr};
    }
  } else {
    auto *issuer_name = X509_get_subject_name(issuer);

    if (issuer_name == nullptr) {
      fmt::print(std::cerr, "X509_get_subject_name failed\n");
      return {nullptr, nullptr};
    }

    if (X509_set_issuer_name(x509.get(), issuer_name) != 1) {
      fmt::print(std::cerr, "X509_set_issuer_name failed\n");
      return {nullptr, nullptr};
    }
  }

  if (X509_set_subject_name(x509.get(), subject_name) != 1) {
    fmt::print(std::cerr, "X509_set_subject_name failed\n");
    return {nullptr, nullptr};
  }

  if (X509_set_pubkey(x509.get(), subject_pkey) != 1) {
    fmt::print(std::cerr, "X509_set_pubkey failed\n");
    return {nullptr, nullptr};
  }

  for (auto &&[nid, ex] : exs) {
    if (internal::X509ExtensionAdd(issuer, x509.get(), nid, ex.data()) != 1) {
      fmt::print(std::cerr, "X509ExtensionAdd failed\n");
      return {nullptr, nullptr};
    }
  }

  if (X509_sign(x509.get(), issuer_pkey, nullptr) == 0) {
    fmt::print(std::cerr, "X509_sign failed\n");
    return {nullptr, nullptr};
  }

  return x509;
}

auto
PemReadX509(std::string_view path, std::string_view pass) -> SmartX509 {
  SmartFile fp{std::fopen(path.data(), "r"), std::fclose};

  if (fp.get() == nullptr) {
    fmt::print(std::cerr, "Cannot open file '{}'\n", path);
    return {nullptr, nullptr};
  }

  return {PEM_read_X509(fp.get(), nullptr, nullptr,
                        const_cast<char *>(pass.data())),
          X509_free};
}

auto
PemWriteX509(const X509 *x509, std::string_view dest) -> int {
  SmartFile fp{std::fopen(dest.data(), "w"), std::fclose};

  if (fp.get() == nullptr) {
    fmt::print(std::cerr, "Cannot open file '{}'\n", dest);
    return 0;
  }

  return PEM_write_X509(fp.get(), x509);
}

auto
PemReadPrivateKey(std::string_view path, std::string_view pass)
    -> SmartEvpPkey {
  SmartFile fp{std::fopen(path.data(), "r"), std::fclose};

  if (fp.get() == nullptr) {
    fmt::print(std::cerr, "Cannot open file '{}'\n", path);
    return {nullptr, nullptr};
  }

  return {PEM_read_PrivateKey(fp.get(), nullptr, nullptr,
                              const_cast<char *>(pass.data())),
          EVP_PKEY_free};
}

auto
PEMWritePrivateKey(const EVP_PKEY *pkey, const EVP_CIPHER *enc,
                   std::string_view pass, std::string_view dest) -> int {
  SmartFile fp{std::fopen(dest.data(), "w"), std::fclose};

  if (fp == nullptr) {
    fmt::print(std::cerr, "Cannot open file '{}'\n", dest);
    return 0;
  }

  return PEM_write_PrivateKey(
      fp.get(), pkey, enc, reinterpret_cast<const unsigned char *>(pass.data()),
      pass.size(), nullptr, nullptr);
}

auto
PemX509Read(X509 *x509) -> std::string {
  internal::SmartBio bio{BIO_new(BIO_s_mem()), BIO_free};

  if (bio.get() == nullptr) {
    fmt::print(std::cerr, "BIO_new failed\n");
    return {};
  }

  if (PEM_write_bio_X509(bio.get(), x509) != 1) {
    fmt::print(std::cerr, "PEM_write_bio_X509 failed\n");
    return {};
  }

  BUF_MEM *bio_buf;

  if (BIO_get_mem_ptr(bio.get(), &bio_buf) != 1) {
    fmt::print(std::cerr, "BIO_get_mem_ptr failed\n");
    return {};
  }

  return {bio_buf->data, bio_buf->length};
}

} // namespace internal

auto
PemX509Read(std::string_view path, std::string_view pass) -> std::string {
  auto x509{internal::PemReadX509(path, pass)};

  if (x509.get() == nullptr) {
    fmt::print(std::cerr, "internal::X509Read failed\n");
    return {};
  }

  return internal::PemX509Read(x509.get());
}

auto
PemPrivateKeyRead(std::string_view path, std::string_view pass) -> std::string {
  auto pkey{internal::PemReadPrivateKey(path, pass)};

  if (pkey.get() == nullptr) {
    fmt::print(std::cerr, "EvpPkeyReadPrivateKey failed\n");
    return {};
  }

  internal::SmartBio bio{BIO_new(BIO_s_mem()), BIO_free};

  if (bio.get() == nullptr) {
    fmt::print(std::cerr, "BIO_new failed\n");
    return {};
  }

  if (PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr, 0,
                               nullptr, nullptr) != 1) {
    fmt::print(std::cerr, "PEM_write_bio_PrivateKey failed\n");
    return {};
  }

  BUF_MEM *bio_buf;

  if (BIO_get_mem_ptr(bio.get(), &bio_buf) != 1) {
    fmt::print(std::cerr, "BIO_get_mem_ptr failed\n");
    return {};
  }

  return {bio_buf->data, bio_buf->length};
}

auto
PemPublicKeyRead(std::string_view path, std::string_view pass) -> std::string {
  auto x509{internal::PemReadX509(path, pass)};

  if (x509.get() == nullptr) {
    fmt::print(std::cerr, "PEM_read_X509 failed\n");
    return {};
  }

  internal::SmartEvpPkey pkey{X509_get_pubkey(x509.get()), EVP_PKEY_free};

  if (pkey.get() == nullptr) {
    fmt::print(std::cerr, "X509_get_pubkey failed\n");
    return {};
  }

  internal::SmartBio bio{BIO_new(BIO_s_mem()), BIO_free};

  if (bio.get() == nullptr) {
    fmt::print(std::cerr, "BIO_new failed\n");
    return {};
  }

  if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) != 1) {
    fmt::print(std::cerr, "PEM_write_bio_PUBKEY failed\n");
    return {};
  }

  BUF_MEM *bio_buf;

  if (BIO_get_mem_ptr(bio.get(), &bio_buf) != 1) {
    fmt::print(std::cerr, "BIO_get_mem_ptr failed\n");
    return {};
  }

  return {bio_buf->data, bio_buf->length};
}

auto
PemPublicKeyReadHex(std::string_view path, std::string_view pass)
    -> std::string {
  auto x509{internal::PemReadX509(path, pass)};

  if (x509.get() == nullptr) {
    fmt::print(std::cerr, "PEM_read_X509 failed\n");
    return {};
  }

  internal::SmartEvpPkey pkey{X509_get_pubkey(x509.get()), EVP_PKEY_free};

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
PemX509NewRoot(std::string_view country, std::string_view state,
               std::string_view locality, std::string_view organisation,
               std::string_view organisational_unit,
               std::string_view common_name, const std::chrono::seconds &expiry)
    -> std::string {
  auto name{internal::X509NameNew(country, state, locality, organisation,
                                  organisational_unit, common_name)};

  if (name.get() == nullptr) {
    fmt::print(std::cerr, "X509NameNew failed\n");
    return {};
  }

  auto pkey{internal::EvpPkeyEd25519New()};

  if (pkey.get() == nullptr) {
    fmt::print(std::cerr, "EvpPkeyEd25519New failed\n");
    return {};
  }

  auto x509{internal::PemX509New(
      nullptr, pkey.get(), pkey.get(), name.get(),
      {{NID_subject_key_identifier, "hash"},
       {NID_authority_key_identifier, "keyid:always,issuer:always"},
       {NID_basic_constraints, "critical,CA:TRUE"},
       {NID_key_usage, "critical,digitalSignature,cRLSign,keyCertSign"}},
      expiry)};

  if (x509.get() == nullptr) {
    fmt::print(std::cerr, "PemX509New failed\n");
    return {};
  }

  return internal::PemX509Read(x509.get());
}

} // namespace hyundeok::grpc

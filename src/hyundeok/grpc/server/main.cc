#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_credentials_options.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include "hyundeok/grpc/chrono.h"
#include "hyundeok/grpc/ssl.h"

#include "ssl_exchange.grpc.pb.h"

using grpc_impl::experimental::TlsCredentialsOptions;
using grpc_impl::experimental::TlsKeyMaterialsConfig;
using grpc_impl::experimental::TlsServerCredentials;

using hyundeok::grpc::GetLocalTimestampIso8601;
using hyundeok::grpc::PemPrivateKeyRead;
using hyundeok::grpc::PemPublicKeyReadHex;
using hyundeok::grpc::PemX509Read;
using hyundeok::grpc::SslExchange;
using hyundeok::grpc::SslPublicKey;

class SslExchangeServiceImpl final : public SslExchange::Service {
  auto
  ExchangeSslPublicKey([[maybe_unused]] grpc::ServerContext *context,
                       const SslPublicKey *in, SslPublicKey *out)
      -> grpc::Status override {
    fmt::print("Received client public key: {} on {}\n", in->pubkey(),
               GetLocalTimestampIso8601());

    auto pubkey{PemPublicKeyReadHex("/tmp/gen-keys-server.pem", "")};

    out->set_pubkey(pubkey);

    fmt::print("Sending server public key:  {} on {}\n", pubkey,
               GetLocalTimestampIso8601());

    return grpc::Status::OK;
  }
};

auto
main(int argc, char **argv) -> int {
  if (argc < 5) {
    fmt::print(std::cerr, "Usage: {} PORT SERVER_PEM SERVER_KEY ROOT_PEM\n",
               argv[0]);
    return -1;
  }

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();

  auto key_materials{std::make_shared<TlsKeyMaterialsConfig>()};

  key_materials->set_key_materials(
      PemX509Read(argv[4], ""),
      {{PemPrivateKeyRead(argv[3], ""), PemX509Read(argv[2], "")}});

  auto tls_opts{TlsCredentialsOptions(
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY, key_materials,
      nullptr)};

  auto tls_creds{TlsServerCredentials(tls_opts)};

  auto server_addr{fmt::format("localhost:{}", argv[1])};
  grpc::ServerBuilder builder;
  SslExchangeServiceImpl service;

  builder.AddListeningPort(server_addr, tls_creds);
  builder.RegisterService(&service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  fmt::print("Server listening on {}\n", server_addr);

  server->Wait();
}

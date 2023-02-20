#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include "hyundeok/grpc/chrono.h"
#include "hyundeok/grpc/ssl.h"

#include "ssl_exchange.grpc.pb.h"

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
  if (argc < 3) {
    fmt::print(std::cerr, "Usage: {} PATH_TO_PEM PATH_TO_PRIVATE_KEY\n",
               argv[0]);
    return -1;
  }

  constexpr auto server_addr{"localhost:50051"};
  SslExchangeServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();

  auto ssl_opts{grpc::SslServerCredentialsOptions(
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY)};
  ssl_opts.pem_key_cert_pairs.push_back(
      {PemPrivateKeyRead(argv[2], ""), PemX509Read(argv[1], "")});

  auto ssl_creds{grpc::SslServerCredentials(ssl_opts)};

  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_addr, ssl_creds);
  builder.RegisterService(&service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  fmt::print("Server listening on {}\n", server_addr);

  server->Wait();
}

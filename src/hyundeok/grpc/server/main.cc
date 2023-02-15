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
using hyundeok::grpc::GetPubKeyFromPem;
using hyundeok::grpc::SslExchange;
using hyundeok::grpc::SslPublicKey;

class SslExchangeServiceImpl final : public SslExchange::Service {
  auto
  ExchangeSslPublicKey([[maybe_unused]] grpc::ServerContext *context,
                       const SslPublicKey *in, SslPublicKey *out)
      -> grpc::Status {
    fmt::print("Received client public key: {} on {}\n", in->pubkey(),
               GetLocalTimestampIso8601());

    auto pubkey{GetPubKeyFromPem("/tmp/gen-keys-server.pem", "")};

    out->set_pubkey(pubkey);

    fmt::print("Sending server public key:  {} on {}\n", pubkey,
               GetLocalTimestampIso8601());

    return grpc::Status::OK;
  }
};

auto
main([[maybe_unused]] int arc, [[maybe_unused]] char **argv) -> int {
  constexpr auto server_addr{"localhost:50051"};
  SslExchangeServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();

  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  fmt::print("Server listening on {}\n", server_addr);

  server->Wait();
}

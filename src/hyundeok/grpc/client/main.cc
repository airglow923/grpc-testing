#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include "hyundeok/grpc/chrono.h"
#include "hyundeok/grpc/ssl.h"

#include "ssl_exchange.grpc.pb.h"

using hyundeok::grpc::GetLocalTimestampIso8601;
using hyundeok::grpc::SslExchange;
using hyundeok::grpc::SslPublicKey;
using hyundeok::grpc::X509ReadPubKey;

class SslExchangeClient {
public:
  SslExchangeClient(std::shared_ptr<grpc::Channel> channel)
      : stub_(SslExchange::NewStub(channel)) {}

  auto
  ExchangeSslPublicKey() -> std::string {
    SslPublicKey client_pubkey;

    client_pubkey.set_pubkey(X509ReadPubKey("/tmp/gen-keys-client.pem", ""));

    fmt::print("Sending client public key:  {} on {}\n", client_pubkey.pubkey(),
               GetLocalTimestampIso8601());

    SslPublicKey server_pubkey;
    grpc::ClientContext context;

    grpc::Status status =
        stub_->ExchangeSslPublicKey(&context, client_pubkey, &server_pubkey);

    if (status.ok()) {
      return fmt::format("Received server public key: {} on {}",
                         server_pubkey.pubkey(), GetLocalTimestampIso8601());
    } else {
      fmt::print(std::cerr, "{}: {}\n", status.error_code(),
                 status.error_message());
      return "RPC failed";
    }
  }

private:
  std::unique_ptr<SslExchange::Stub> stub_;
};

auto
main([[maybe_unused]] int argc, [[maybe_unused]] char **argv) -> int {
  SslExchangeClient client(grpc::CreateChannel(
      "localhost:50051", grpc::InsecureChannelCredentials()));

  fmt::print("{}\n", client.ExchangeSslPublicKey());
}

#include <iostream>
#include <memory>
#include <string>
#include <string_view>

#include <grpcpp/grpcpp.h>

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

class SslExchangeClient {
public:
  SslExchangeClient(std::shared_ptr<grpc::Channel> channel)
      : stub_(SslExchange::NewStub(channel)) {}

  auto
  ExchangeSslPublicKey(std::string_view cert_path) -> std::string {
    SslPublicKey client_pubkey;

    client_pubkey.set_pubkey(PemPublicKeyReadHex(cert_path, ""));

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
main(int argc, char **argv) -> int {
  if (argc < 3) {
    fmt::print(std::cerr, "Usage: {} PATH_TO_PEM PATH_TO_PRIVATE_KEY\n",
               argv[0]);
    return -1;
  }

  auto ssl_opts{grpc::SslCredentialsOptions()};
  ssl_opts.pem_private_key = PemPrivateKeyRead(argv[2], "");
  ssl_opts.pem_cert_chain = PemX509Read(argv[1], "");

  auto ssl_creds{grpc::SslCredentials(ssl_opts)};
  auto channel{grpc::CreateChannel("localhost:50051", ssl_creds)};

  SslExchangeClient client{channel};

  fmt::print("{}\n", client.ExchangeSslPublicKey(argv[1]));
}

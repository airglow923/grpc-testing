#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_credentials_options.h>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include "hyundeok/grpc/chrono.h"
#include "hyundeok/grpc/ssl.h"

#include "ssl_exchange.grpc.pb.h"

using grpc_impl::experimental::TlsCredentials;
using grpc_impl::experimental::TlsCredentialsOptions;
using grpc_impl::experimental::TlsKeyMaterialsConfig;

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

    fmt::print("Thread ID: {}\n", std::this_thread::get_id());
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
  using namespace std::chrono_literals;

  if (argc < 5) {
    fmt::print(std::cerr, "Usage: {} PORT CLIENT_PEM CLIENT_KEY ROOT_PEM\n",
               argv[0]);
    return -1;
  }

  auto key_materials{std::make_shared<TlsKeyMaterialsConfig>()};

  key_materials->set_key_materials(
      PemX509Read(argv[4], ""),
      {{PemPrivateKeyRead(argv[3], ""), PemX509Read(argv[2], "")}});

  auto tls_opts{TlsCredentialsOptions(GRPC_TLS_SERVER_VERIFICATION,
                                      key_materials, nullptr, nullptr)};

  auto tls_creds{TlsCredentials(tls_opts)};
  auto channel{
      grpc::CreateChannel(fmt::format("localhost:{}", argv[1]), tls_creds)};

  SslExchangeClient client{channel};

  for (;;) {
    fmt::print("{}\n", client.ExchangeSslPublicKey(argv[2]));
    std::this_thread::sleep_for(2s);
  }
}

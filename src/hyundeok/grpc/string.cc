#include "hyundeok/grpc/string.h"

#include <string>

namespace hyundeok::grpc {

namespace internal {

inline constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

}

auto
BytesToString(unsigned char *data, std::size_t len) -> std::string {
  std::string s(len * 2, ' ');

  for (std::size_t i = 0; i != len; ++i) {
    s[2 * i] = internal::hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = internal::hexmap[data[i] & 0x0F];
  }

  return s;
}

} // namespace hyundeok::grpc

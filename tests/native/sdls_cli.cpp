// sdls_cli.cpp - builds the satellite SDLS library on the PC for the
// interop tests with Python (tests/test_interop_f2.py).
//
//   g++ -std=c++17 -Wall -Wextra -Isatellite/satellite_f2
//       satellite/satellite_f2/ccsds.cpp satellite/satellite_f2/sdls.cpp
//       tests/native/sdls_cli.cpp -lmbedcrypto -o build/sdls_cli
//
// Usage:
//   sdls_cli tc <key_hex> <last_iv> <frame_hex>...
//        processes the frames in order, like the satellite, and prints one line
//        per frame: "OK <N(S)> <iv> <packet_hex>", "TC <error>" or "SEC <code>"
//   sdls_cli tm <key_hex> <iv> <seq> <data_hex> <mc> <vc> <vr>
//        builds a protected TM frame
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "ccsds.h"
#include "sdls.h"

using namespace ccsds;
using namespace sdls;

static std::vector<uint8_t> fromHex(const char* s) {
  std::vector<uint8_t> out;
  size_t n = strlen(s);
  for (size_t i = 0; i + 1 < n; i += 2) {
    char b[3] = {s[i], s[i + 1], 0};
    out.push_back((uint8_t)strtoul(b, nullptr, 16));
  }
  return out;
}

static void printHex(const uint8_t* p, size_t n) {
  for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

int main(int argc, char** argv) {
  if (argc >= 5 && strcmp(argv[1], "tc") == 0) {
    auto key = fromHex(argv[2]);
    SecurityAssociation sa;
    if (key.size() != KEY_LEN || !saInit(sa, SPI_TC, key.data())) return 2;
    ivFromCounter(strtoull(argv[3], nullptr, 10), sa.lastIv);
    for (int i = 4; i < argc; i++) {
      auto frame = fromHex(argv[i]);
      TcFrame f;
      TcError e = parseTcFrame(frame.data(), frame.size(), f);
      if (e != TC_OK) {
        printf("TC %d\n", (int)e);
        continue;
      }
      uint8_t plain[256], iv[IV_LEN];
      size_t plainLen = 0;
      SecError s = processTc(sa, frame.data(), f, plain, sizeof(plain), plainLen, iv);
      if (s != SEC_OK) {
        printf("SEC %d\n", (int)s);
        continue;
      }
      printf("OK %d %llu ", f.seq, (unsigned long long)ivToCounter(iv));
      printHex(plain, plainLen);
      printf("\n");
    }
    return 0;
  }
  if (argc >= 9 && strcmp(argv[1], "tm") == 0) {
    auto key = fromHex(argv[2]);
    SecurityAssociation sa;
    if (key.size() != KEY_LEN || !saInit(sa, SPI_TM, key.data())) return 2;
    uint8_t iv[IV_LEN];
    ivFromCounter(strtoull(argv[3], nullptr, 10), iv);
    auto data = fromHex(argv[5]);
    uint8_t pkt[128];
    size_t pl = buildSpacePacket(pkt, sizeof(pkt), 0, APID_SAT, (uint16_t)atoi(argv[4]), data.data(), data.size());
    uint8_t frame[TM_FRAME_LEN];
    if (pl == 0 || buildSecureTmFrame(sa, frame, (uint8_t)atoi(argv[6]), (uint8_t)atoi(argv[7]), pkt, pl,
                                      buildClcw(VCID, (uint8_t)atoi(argv[8])), iv) == 0) {
      printf("ERR build\n");
      return 0;
    }
    printHex(frame, TM_FRAME_LEN);
    printf("\n");
    return 0;
  }
  fprintf(stderr, "usage: sdls_cli tc|tm ...\n");
  return 2;
}

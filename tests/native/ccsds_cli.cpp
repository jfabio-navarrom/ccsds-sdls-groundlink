// ccsds_cli.cpp - builds the satellite CCSDS library on the PC for
// the interop tests with Python (tests/test_interop.py).
//
//   g++ -std=c++17 -Wall -Wextra -Isatellite/satellite_f1
//       satellite/satellite_f1/ccsds.cpp tests/native/ccsds_cli.cpp -o build/ccsds_cli
//
// Usage:
//   ccsds_cli crc <hex>
//   ccsds_cli tc <hex>                         -> parses a TC frame
//   ccsds_cli tm <seq> <datahex> <mc> <vc> <vr> -> builds a TM frame
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "ccsds.h"

using namespace ccsds;

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
  if (argc >= 3 && strcmp(argv[1], "crc") == 0) {
    auto d = fromHex(argv[2]);
    printf("%04x\n", crc16(d.data(), d.size()));
    return 0;
  }
  if (argc >= 3 && strcmp(argv[1], "tc") == 0) {
    auto d = fromHex(argv[2]);
    TcFrame f;
    TcError e = parseTcFrame(d.data(), d.size(), f);
    if (e != TC_OK) {
      printf("ERR %d\n", (int)e);
      return 0;
    }
    SpacePacket p;
    if (!parseSpacePacket(f.data, f.dataLen, p)) {
      printf("ERR packet\n");
      return 0;
    }
    printf("OK %d %d %d %d %d %d %d ", (int)f.bypass, f.scid, f.vcid, f.seq, p.type, p.apid, p.seqCount);
    printHex(p.data, p.dataLen);
    printf("\n");
    return 0;
  }
  if (argc >= 7 && strcmp(argv[1], "tm") == 0) {
    uint16_t seq = (uint16_t)atoi(argv[2]);
    auto data = fromHex(argv[3]);
    uint8_t pkt[256];
    size_t pl = buildSpacePacket(pkt, sizeof(pkt), 0, APID_SAT, seq, data.data(), data.size());
    uint8_t frame[TM_FRAME_LEN];
    if (pl == 0 || buildTmFrame(frame, (uint8_t)atoi(argv[4]), (uint8_t)atoi(argv[5]), pkt, pl,
                                buildClcw(VCID, (uint8_t)atoi(argv[6]))) == 0) {
      printf("ERR build\n");
      return 0;
    }
    printHex(frame, TM_FRAME_LEN);
    printf("\n");
    return 0;
  }
  fprintf(stderr, "usage: ccsds_cli crc|tc|tm ...\n");
  return 2;
}

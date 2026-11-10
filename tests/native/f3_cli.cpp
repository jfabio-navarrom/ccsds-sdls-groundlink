// f3_cli.cpp - builds the satellite FARM-1 and OTAR (phase 3) on the PC for
// the interop tests with Python (tests/test_f3.py).
//
//   g++ -std=c++17 -Wall -Wextra -Isatellite/satellite_f3 satellite/satellite_f3/ccsds.cpp
//       satellite/satellite_f3/sdls.cpp satellite/satellite_f3/farm.cpp tests/native/f3_cli.cpp
//       -lmbedcrypto -o build/f3_cli
//
// Usage:
//   f3_cli farm <op>...      op = ad:<N(S)> | bd | bc:<hex>; prints "<result> <clcw hex>"
//   f3_cli otar <kek_hex> <id> <block_hex>    -> "OK <tc_hex> <tm_hex>" or "ERR"
//   f3_cli fp <kek_hex>                       -> KEK fingerprint
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "farm.h"
#include "sdls.h"

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

static bool kekCtx(const char* hex, mbedtls_gcm_context& ctx) {
  auto k = fromHex(hex);
  mbedtls_gcm_init(&ctx);
  return k.size() == sdls::KEY_LEN && mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, k.data(), 256) == 0;
}

int main(int argc, char** argv) {
  if (argc >= 2 && strcmp(argv[1], "farm") == 0) {
    farm::State s;
    for (int i = 2; i < argc; i++) {
      farm::Result r;
      if (strncmp(argv[i], "ad:", 3) == 0) {
        r = farm::onAd(s, (uint8_t)atoi(argv[i] + 3));
      } else if (strcmp(argv[i], "bd") == 0) {
        r = farm::onBd(s);
      } else {
        auto d = fromHex(argv[i] + 3);
        r = farm::onBc(s, d.data(), d.size());
      }
      printf("%d %08lx\n", (int)r, (unsigned long)farm::clcw(s, 0));
    }
    return 0;
  }
  if (argc >= 5 && strcmp(argv[1], "otar") == 0) {
    mbedtls_gcm_context kek;
    if (!kekCtx(argv[2], kek)) return 2;
    auto block = fromHex(argv[4]);
    uint8_t tc[sdls::KEY_LEN], tm[sdls::KEY_LEN];
    if (block.size() != sdls::OTAR_BLOCK_LEN || !sdls::otarUnwrap(kek, (uint8_t)atoi(argv[3]), block.data(), tc, tm)) {
      printf("ERR\n");
      return 0;
    }
    printf("OK ");
    printHex(tc, sizeof(tc));
    printf(" ");
    printHex(tm, sizeof(tm));
    printf("\n");
    return 0;
  }
  if (argc >= 3 && strcmp(argv[1], "fp") == 0) {
    mbedtls_gcm_context kek;
    uint8_t fp[8];
    if (!kekCtx(argv[2], kek) || !sdls::kekFingerprint(kek, fp)) return 2;
    printHex(fp, 8);
    printf("\n");
    return 0;
  }
  fprintf(stderr, "usage: f3_cli farm|otar|fp ...\n");
  return 2;
}

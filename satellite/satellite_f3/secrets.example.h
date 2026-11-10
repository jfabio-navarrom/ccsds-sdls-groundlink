// Copy this file as "secrets.h" (in this same folder, as a new tab
// in the Arduino IDE). secrets.h is in .gitignore: it is never pushed to GitHub.
//
// 1) Your Wi-Fi:
#define WIFI_SSID "your_wifi_name"
#define WIFI_PASS "your_wifi_password"

// 2) The keys. Do NOT make them up: run on the PC
//        py tools\gen_keys_f3.py
//    and replace these three lines with the ones it prints (32 bytes each).
//    SDLS_KEK is the master key: it is only used to receive new keys (OTAR).
// #define SDLS_KEK {0x00, 0x00, ...}
// #define SDLS_TC_KEY {0x00, 0x00, ...}
// #define SDLS_TM_KEY {0x00, 0x00, ...}

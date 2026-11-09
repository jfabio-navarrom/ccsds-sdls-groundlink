// Copia este archivo como "secrets.h" (en esta misma carpeta, como pestana
// nueva del Arduino IDE). secrets.h esta en .gitignore: nunca se sube a GitHub.
//
// 1) Tu Wi-Fi:
#define WIFI_SSID "nombre_de_tu_wifi"
#define WIFI_PASS "contrasena_de_tu_wifi"

// 2) Las claves. NO las inventes: ejecuta en el PC
//        py tools\gen_keys_f3.py
//    y sustituye estas tres lineas por las que imprime (32 bytes cada una).
//    SDLS_KEK es la clave maestra: solo sirve para recibir claves nuevas (OTAR).
// #define SDLS_KEK {0x00, 0x00, ...}
// #define SDLS_TC_KEY {0x00, 0x00, ...}
// #define SDLS_TM_KEY {0x00, 0x00, ...}

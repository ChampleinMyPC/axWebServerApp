/**
 * Copyright (C) 2025, Axis Communications AB, Lund, Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <axsdk/axstorage.h>

#include "civetweb.h"
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>



#include <glib-unix.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <curl/curl.h>

#define PORT "2001"
#define HTTP_TARGET "http://192.168.1.45:3000/api/enregistrements/ingest-batch-from-acap"

volatile sig_atomic_t application_running = 1;

__attribute__((noreturn)) __attribute__((format(printf, 1, 2))) static void
panic(const char* format, ...) {
    va_list arg;
    va_start(arg, format);
    vsyslog(LOG_ERR, format, arg);
    va_end(arg);
    exit(1);
}

static void stop_application(int status) {
    (void)status;
    application_running = 0;
}

// static int root_handler(struct mg_connection* conn, void* cb_data __attribute__((unused))) {
//     mg_send_file(conn, "html/index.html");
//     return 1;
// }

// Adapter avec tes globals existants
static char g_sd_root[256] = "/var/spool/storage/areas/SD_DISK/axstorage";
static char g_serial[64]   = "B8A44F46CE99"; // rempli au boot via VAPIX (get serial)

// --- utils: parse YYYY-MM-DD from ISO "YYYY-MM-DDTHH:MM:SSZ"
static void iso_to_date(const char* iso, char ymd[11]) {
  // ymd = "YYYY-MM-DD"
  if (!iso || strlen(iso) < 10) { strcpy(ymd, "1970-01-01"); return; }
  memcpy(ymd, iso, 10); ymd[10] = '\0';
}

// --- util: renvoie 1 si le filename est un fichier de 15 min et timestamp dans [start,end]
static int match_counts_file(const char* fname, const char* serial, const char* startIso, const char* endIso) {
  // attendu: counts_<SERIAL>_<YYYYMMDD>T<HHMM>Z_15min_<...>.json
  // on extrait le fragment "<YYYYMMDD>T<HHMM>Z"
  const char* p = strstr(fname, "counts_");
  if (!p) return 0;
  // Check serial
  char needle[64]; snprintf(needle, sizeof needle, "counts_%.48s_", serial);
  if (!strstr(fname, needle)) return 0;

//   const char* t = strrchr(fname, '_'); // dernier underscore
  // On préfère chercher le premier timestamp après "counts_<serial>_"
  const char* after = fname + strlen("counts_") + strlen(serial) + 1;
  // after pointe sur "<YYYYMMDD>T<HHMM>Z_15min_..."
  // on prend 16 chars: "YYYYMMDDTHHMMZ"
  char ts[17] = {0};
  if (strlen(after) < 16) return 0;
  memcpy(ts, after, 15); // "YYYYMMDDTHHMMZ" (15) – on garde 15 pour comparer "YYYYMMDDTHHMMZ"
  ts[15] = '\0';

  // Convertit start/end: "YYYY-MM-DDTHH:MM:SSZ" -> "YYYYMMDDTHHMMZ" (pour comparaison lexicographique simple)
  char A[17]={0}, B[17]={0};
  if (strlen(startIso) < 16 || strlen(endIso) < 16) return 0;

  // start
  snprintf(A, sizeof A, "%.4s%.2s%.2sT%.2s%.2sZ",
    startIso,         // YYYY
    startIso+5,       // MM
    startIso+8,       // DD
    startIso+11,      // HH
    startIso+14       // MM
  );
  // end
  snprintf(B, sizeof B, "%.4s%.2s%.2sT%.2s%.2sZ",
    endIso, endIso+5, endIso+8, endIso+11, endIso+14
  );

  return (strcmp(ts, A) >= 0) && (strcmp(ts, B) <= 0);
}

// --- /list : GET ?start=...&end=...
static int ListHandler(struct mg_connection* conn, void* cb) {
  (void)cb;
  
  const struct mg_request_info* ri = mg_get_request_info(conn);
  syslog(LOG_INFO, "Civet hit: %s", ri->local_uri);
  if (strcmp(ri->request_method, "GET")) { mg_send_http_error(conn, 405, "Method Not Allowed"); return 405; }
  
  char startIso[64]={0}, endIso[64]={0};
  mg_get_var(ri->query_string ? ri->query_string : "", ri->query_string ? (int)strlen(ri->query_string) : 0,
  "start", startIso, sizeof(startIso));
  mg_get_var(ri->query_string ? ri->query_string : "", ri->query_string ? (int)strlen(ri->query_string) : 0,
  "end", endIso, sizeof(endIso));
  if (!*startIso || !*endIso) { mg_send_http_error(conn, 400, "start/end manquants"); return 400; }
  
  // dossier jour (UTC)
  char ymdStart[11], ymdEnd[11];
  iso_to_date(startIso, ymdStart);
  iso_to_date(endIso,   ymdEnd);
  
  // pour simplifier: on parcourt tous les jours de [ymdStart..ymdEnd] dans le répertoire
  // (ici, exemple naïf: on visitera les deux dossiers ymdStart et ymdEnd; à étendre pour >1 jour)
  const char* days[3] = { ymdStart, ymdEnd, NULL };
  
  // buffer JSON
  char json[65536]; size_t off = 0;
  off += (size_t)snprintf(json+off, sizeof(json)-off, "{ \"files\": [");
  
  int first = 1;
  for (int di=0; days[di]; ++di) {
      char daydir[512];
      snprintf(daydir, sizeof daydir, "%s/aoa_counts/%s/%s", g_sd_root, g_serial, days[di]);
      
      DIR* d = opendir(daydir);
      if (!d) continue;
      struct dirent* e;
      while ((e = readdir(d))) {
          if (e->d_name[0] == '.') continue;
          if (!strstr(e->d_name, ".json")) continue;
          if (!match_counts_file(e->d_name, g_serial, startIso, endIso)) continue;
          
          char full[1024];
          snprintf(full, sizeof full, "%s/%s", daydir, e->d_name);
          struct stat st;
          if (stat(full, &st) != 0) continue;
          
          if (!first) off += (size_t)snprintf(json+off, sizeof(json)-off, ",");
          first = 0;
          
          // ts (reprise du nom)
          char tsFrag[20] = {0};
          // pour l’affichage, on remonte la portion "YYYYMMDDTHHMMZ"
          const char* after = strstr(e->d_name, g_serial);
          if (after) {
              after += strlen(g_serial) + 1; // saute "SERIAL_"
              memcpy(tsFrag, after, 15);
            } else {
                strcpy(tsFrag, "YYYYMMDDTHHMMZ");
            }
            
            off += (size_t)snprintf(json+off, sizeof(json)-off,
            "{\"path\":\"%s\",\"ts\":\"%s\",\"size\":%ld}",
            full, tsFrag, (long)st.st_size);
            if (off > sizeof(json) - 256) break; // garde-fou
        }
        closedir(d);
    }
    
    off += (size_t)snprintf(json+off, sizeof(json)-off, "]}");
    
    // mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
  mg_printf(conn,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %zu\r\n\r\n%.*s",
    off, (int)off, json);
  return 200;
}

// --- util: envoi HTTP de chaque fichier vers ton backend existant
// static int try_ship_file_to_node(const char* path);
// … (branche ta libcurl “ship_file_to_server” déjà utilisée)
// Envoie JSON -> Node
static gboolean http_post_json(const char* api_key, const char* json, long* http_code_out) {
  CURL *curl = curl_easy_init();
  if (!curl) return FALSE;

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  if (api_key) {
    char h[256]; snprintf(h, sizeof h, "X-API-Key: %s", api_key);
    headers = curl_slist_append(headers, h);
  }

  curl_easy_setopt(curl, CURLOPT_URL, HTTP_TARGET);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

  CURLcode rc = curl_easy_perform(curl);
  long http_code = 0;
  if (http_code_out) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code_out) *http_code_out = http_code;

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  return (rc == CURLE_OK);
}

// Lit un fichier et l'envoie (puis, si succès 200/201, on peut le renommer ".sent")
static int try_ship_file_to_node(const char* filepath, const char* api_key) {
  gchar *contents = NULL; gsize len = 0;
  if (!g_file_get_contents(filepath, &contents, &len, NULL)) {
    syslog(LOG_WARNING, "Cannot read %s to ship", filepath);
    return -1;
  }
  long code = 0;
  gboolean ok = http_post_json(api_key, contents, &code);
  if (ok && (code == 200 || code == 201)) {
    syslog(LOG_INFO, "Shipped OK %s (HTTP %ld)", filepath, code);
    gchar* sent = g_strconcat(filepath, ".sent", NULL);
    g_rename(filepath, sent); // garde une trace, évite de supprimer brutalement
    g_free(sent);
    return 0;
  } else {
    syslog(LOG_WARNING, "Ship failed %s (HTTP %ld)", filepath, code);
  }
  g_free(contents);
    return -1;
}

static int SendHandler(struct mg_connection* conn, void* cb) {
  (void)cb;
//   mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
  
  const struct mg_request_info* ri = mg_get_request_info(conn);
  syslog(LOG_INFO, "Civet hit: %s", ri->local_uri);
  if (strcmp(ri->request_method, "POST")) { mg_send_http_error(conn, 405, "Method Not Allowed"); return 405; }

  // lit JSON body: { "files": ["abs/path/file1.json", ...] }
  char body[65536]; int n = mg_read(conn, body, sizeof(body)-1);
  if (n < 0) n = 0; 
  body[n] = '\0';

  // parsing ultra-léger (recherche de chemins entre guillemets) – remplace par un parseur JSON si tu préfères
  char shipped[32768] = {0}; size_t so = 0;
  int ok = 0, ko = 0;

  const char* p = body;
  while ((p = strstr(p, "\"/"))) {
    const char* q = strchr(p+1, '"');
    if (!q) break;
    char path[1024] = {0};
    size_t len = (size_t)(q - (p+1));
    if (len > sizeof(path)-1) len = sizeof(path)-1;
    memcpy(path, p+1, len); path[len] = '\0';
    p = q+1;

    int rc = try_ship_file_to_node(path, NULL);
    if (rc == 0) {
      if (so > 0) so += (size_t)snprintf(shipped+so, sizeof(shipped)-so, ",");
      so += (size_t)snprintf(shipped+so, sizeof(shipped)-so, "\"%s\"", path);
      ok++;
    } else {
      ko++;
    }
  }

  char json[2048];
  int L = snprintf(json, sizeof json,
    "{ \"ok\": true, \"shipped\": [%.*s], \"failedCount\": %d }", (int)so, shipped, ko);

  mg_printf(conn,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %d\r\n\r\n%.*s",
    L, L, json);
  return 200;
}

// --- Root (optionnel si tu sers juste index.html en settingPage, sinon renvoie un lien)
// static int RootHandler(struct mg_connection *conn, void *cb) {
//   (void)cb;
//   const char* html = "<html><body><a href=\"http://192.168.1.51/local/web_server_rev_proxy/index.html\">Ouvrir l’UI</a></body></html>";
//   mg_printf(conn,
//     "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s",
//     strlen(html), html);
//   return 200;
// }

// --- bootstrap CivetWeb (à mettre dans ton main de cette app UI)
// static struct mg_mgr* start_http_ui(void) {
//   const char* opts[] = { "listening_ports","2001", "num_threads","2", NULL };
//   struct mg_mgr* ctx = mg_start(NULL, NULL, opts);
//   if (!ctx) return NULL;
//   return ctx;
// }
// *******************************************************************************
static int WebSocketConnectHandler(const struct mg_connection *conn, void *cb) {
    syslog(LOG_INFO, "WebSocket connect");
    // jaffiche un prop de conn et cb
    syslog(LOG_INFO, "WebSocket connect %s le conn %p", mg_get_request_info(conn)->local_uri, cb);
    // syslog(LOG_INFO, "WebSocket connect %s le cb %p", );
    
    return 1; // accepter la connexion
}

static void WebSocketReadyHandler(struct mg_connection *conn, void *cb) {
    syslog(LOG_INFO, "WebSocket connect %s le conn %p", mg_get_request_info(conn)->local_uri, cb);
    const char *welcome = "Bienvenue sur le WebSocket ACAP!";
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, welcome, strlen(welcome));
}

static int WebSocketDataHandler(struct mg_connection *conn, int flags, char *data, size_t data_len, void *cb) {
    syslog(LOG_INFO, "WebSocket connect %s le conn %p", mg_get_request_info(conn)->local_uri, cb);
    syslog(LOG_INFO, "WebSocket data: %.*s", (int)data_len, data);
    syslog(LOG_INFO, "WebSocket data len: %d", flags);
    // Echo du message
    mg_websocket_write(conn, MG_WEBSOCKET_OPCODE_TEXT, data, data_len);
    
    return 1;
}

static void WebSocketCloseHandler(const struct mg_connection *conn, void *cb) {
    syslog(LOG_INFO, "WebSocket closed");
    syslog(LOG_INFO, "WebSocket connect %s le conn %p", mg_get_request_info(conn)->local_uri, cb);
}
static struct mg_context* start_server_unix(void) {
  // S’assurer que le dossier existe
  g_mkdir_with_parents("/var/run", 0775);
  // Nettoyer l’ancien fichier socket si présent
  unlink("/var/run/my_web_server.sock");

  const char *options[] = {
    "listening_ports", "unix:/var/run/my_web_server.sock",
    // Optionnel: rendre le socket accessible au groupe http/apps
    "unix_socket_mode", "0660",
    NULL
  };
  struct mg_callbacks cb; memset(&cb, 0, sizeof cb);
  return mg_start(&cb, NULL, options);
}

// *******************************************************************************

int main(void) {
    signal(SIGTERM, stop_application);
    signal(SIGINT, stop_application);

    mg_init_library(0);

    struct mg_context* cxt = start_server_unix();

    if (!cxt) {
      syslog(LOG_INFO, "Erreur lors du démarrage : mg_start a retourné NULL");
      syslog(LOG_ERR, "Erreur lors du démarrage : mg_start a retourné NULL");
      panic("Something went wrong wen starting the web server");
    }

    syslog(LOG_INFO, "Server has started");

    mg_set_request_handler(cxt, "/list",  ListHandler, NULL);
    mg_set_request_handler(cxt, "/send",  SendHandler, NULL);
    mg_set_websocket_handler(cxt, "/ws",
    WebSocketConnectHandler,
    WebSocketReadyHandler,
    WebSocketDataHandler,
    WebSocketCloseHandler,
    NULL);

    // Boucle principale
    while (application_running) {
        sleep(1);
    }

    mg_stop(cxt);
    mg_exit_library();

    return EXIT_SUCCESS;
}

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
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>
#include <dirent.h>
#include <glib-unix.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <sys/stat.h>

#define PORT        "2001"
// #define HTTP_TARGET "https://api.mycarcounter.fr/api/enregistrements/ingest-batch-from-acap"
#define HTTP_TARGET "http://localhost:3000/api/enregistrements/ingest-batch-from-acap"
#define DEFAULT_RELEASE_URL "https://api.github.com/repos/ChampleinMyPC/axWebServerApp/releases/latest"

#define USER "champlein"
#define PASS "696969"
#define APP_ID "web_server_rev_proxy"


gboolean download_and_install_eap(const char* release_url,
                                    const char* user,
                                    const char* pass,
                                    char err[256]);




gboolean should_check_update_biweekly(const char* stamp_path, int days);  // 14 par défaut
gboolean touch_update_stamp(const char* stamp_path, char err[128]);
// gboolean update_from_github(const char* org, const char* repo,
//                             const char* must_contain,
//                             const char* token, // nullable
//                             const char* cam_user, const char* cam_pass,
//                             char err[256]);
static char* resolve_latest_eap_url(const char* org, const char* repo,
                                    const char* must_contain,
                                    const char* oauth_token,
                                    char err[256]);


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
static char g_serial[64]   = "B8A44F46CE99";  // rempli au boot via VAPIX (get serial)

// --- utils: parse YYYY-MM-DD from ISO "YYYY-MM-DDTHH:MM:SSZ"
static void iso_to_date(const char* iso, char ymd[11]) {
    // ymd = "YYYY-MM-DD"
    if (!iso || strlen(iso) < 10) {
        strcpy(ymd, "1970-01-01");
        return;
    }
    memcpy(ymd, iso, 10);
    ymd[10] = '\0';
}

// --- util: renvoie 1 si le filename est un fichier de 15 min et timestamp dans [start,end]
static int
match_counts_file(const char* fname, const char* serial, const char* startIso, const char* endIso) {
    // attendu: counts_<SERIAL>_<YYYYMMDD>T<HHMM>Z_15min_<...>.json
    // on extrait le fragment "<YYYYMMDD>T<HHMM>Z"
    const char* p = strstr(fname, "counts_");
    if (!p)
        return 0;
    // Check serial
    char needle[64];
    snprintf(needle, sizeof needle, "counts_%.48s_", serial);
    if (!strstr(fname, needle))
        return 0;

    //   const char* t = strrchr(fname, '_'); // dernier underscore
    // On préfère chercher le premier timestamp après "counts_<serial>_"
    const char* after = fname + strlen("counts_") + strlen(serial) + 1;
    // after pointe sur "<YYYYMMDD>T<HHMM>Z_15min_..."
    // on prend 16 chars: "YYYYMMDDTHHMMZ"
    char ts[17] = {0};
    if (strlen(after) < 16)
        return 0;
    memcpy(ts, after, 15);  // "YYYYMMDDTHHMMZ" (15) – on garde 15 pour comparer "YYYYMMDDTHHMMZ"
    ts[15] = '\0';

    // Convertit start/end: "YYYY-MM-DDTHH:MM:SSZ" -> "YYYYMMDDTHHMMZ" (pour comparaison
    // lexicographique simple)
    char A[17] = {0}, B[17] = {0};
    if (strlen(startIso) < 16 || strlen(endIso) < 16)
        return 0;

    // start
    snprintf(A,
             sizeof A,
             "%.4s%.2s%.2sT%.2s%.2sZ",
             startIso,       // YYYY
             startIso + 5,   // MM
             startIso + 8,   // DD
             startIso + 11,  // HH
             startIso + 14   // MM
    );
    // end
    snprintf(B,
             sizeof B,
             "%.4s%.2s%.2sT%.2s%.2sZ",
             endIso,
             endIso + 5,
             endIso + 8,
             endIso + 11,
             endIso + 14);

    return (strcmp(ts, A) >= 0) && (strcmp(ts, B) <= 0);
}

// --- /list : GET ?start=...&end=...
// Gestionnaire pour la route /list qui liste les fichiers JSON de comptages dans la plage de dates
// spécifiée. Paramètres de requête : start (ISO date) et end (ISO date). Retourne une réponse JSON
// avec la liste des fichiers correspondants, incluant chemin, timestamp et taille.
static int ListHandler(struct mg_connection* conn, void* cb) {
    (void)cb;  // Paramètre callback non utilisé

    // Récupération des informations de la requête
    const struct mg_request_info* ri = mg_get_request_info(conn);
    syslog(LOG_INFO, "Civet hit: %s", ri->local_uri);

    // Vérification que la méthode est GET
    if (strcmp(ri->request_method, "GET")) {
        mg_send_http_error(conn, 405, "Method Not Allowed");
        return 405;
    }

    // Extraction des paramètres start et end de la chaîne de requête
    char startIso[64] = {0}, endIso[64] = {0};
    mg_get_var(ri->query_string ? ri->query_string : "",
               ri->query_string ? (int)strlen(ri->query_string) : 0,
               "start",
               startIso,
               sizeof(startIso));
    mg_get_var(ri->query_string ? ri->query_string : "",
               ri->query_string ? (int)strlen(ri->query_string) : 0,
               "end",
               endIso,
               sizeof(endIso));

    // Vérification que start et end sont fournis
    if (!*startIso || !*endIso) {
        mg_send_http_error(conn, 400, "start/end manquants");
        return 400;
    }

    // Conversion des dates ISO en format YYYY-MM-DD
    char ymdStart[11], ymdEnd[11];
    iso_to_date(startIso, ymdStart);
    iso_to_date(endIso, ymdEnd);

    // Pour simplifier, on parcourt seulement les jours start et end (à étendre pour une plage plus
    // large)
    // const char* days[3] = {ymdStart, ymdEnd, NULL};
    //on parcour tous les jours entre start et end
    GDate start, end;
    g_date_set_parse(&start, ymdStart);
    g_date_set_parse(&end, ymdEnd);
    if (!g_date_valid(&start) || !g_date_valid(&end) || g_date_compare(&start, &end) > 0) {
        mg_send_http_error(conn, 400, "start/end invalides");
        return 400;
    }
    // Construire la liste des jours entre start et end
    char* days[32] = {0};  // supporte jusqu'à 31 jours
    int di = 0;
    for (GDate d = start; g_date_compare(&d, &end) <= 0; g_date_add_days(&d, 1)) {
        if (di >= 31)
            break;  // garde-fou
        
        // ✅ formater correctement sans accéder aux champs internes
        char buf[11]; // "YYYY-MM-DD" + '\0'
        g_date_strftime(buf, sizeof(buf), "%Y-%m-%d", &d);  // threadsafe pour GDate

        days[di] = g_strdup(buf);
        syslog(LOG_INFO, "Searching days from %s", days[di]);
        di++;
    }
    days[di] = NULL;  // Terminaison de la liste
    syslog(LOG_INFO, "Searching days from %s to %s", ymdStart, ymdEnd);

    // Initialisation du buffer JSON pour la réponse
    char json[65536];
    size_t off = 0;
    off += (size_t)snprintf(json + off, sizeof(json) - off, "{ \"files\": [");

    int first = 1;  // Indicateur pour la première entrée dans le tableau JSON
    for (int di = 0; days[di]; ++di) {
        // Construction du chemin du répertoire du jour
        char daydir[512];
        snprintf(daydir, sizeof daydir, "%s/aoa_counts/%s/%s", g_sd_root, g_serial, days[di]);

        // Ouverture du répertoire
        DIR* d = opendir(daydir);
        if (!d)
            continue;  // Si le répertoire n'existe pas, passer au suivant

        struct dirent* e;
        while ((e = readdir(d))) {
            // Ignorer les fichiers cachés et non JSON
            if (e->d_name[0] == '.')
                continue;
            if (!strstr(e->d_name, ".json"))
                continue;

            // Vérifier si le fichier correspond aux critères (série et plage temporelle)
            if (!match_counts_file(e->d_name, g_serial, startIso, endIso))
                continue;

            // Construction du chemin complet du fichier
            char full[1024];
            snprintf(full, sizeof full, "%s/%s", daydir, e->d_name);

            // Récupération des informations du fichier (taille, etc.)
            struct stat st;
            if (stat(full, &st) != 0)
                continue;

            // Ajout d'une virgule si ce n'est pas le premier élément
            if (!first)
                off += (size_t)snprintf(json + off, sizeof(json) - off, ",");
            first = 0;

            // Extraction du timestamp du nom du fichier
            char tsFrag[20]   = {0};
            const char* after = strstr(e->d_name, g_serial);
            if (after) {
                after += strlen(g_serial) + 1;  // Saute "SERIAL_"
                memcpy(tsFrag, after, 15);      // Copie "YYYYMMDDTHHMMZ"
            } else {
                strcpy(tsFrag, "YYYYMMDDTHHMMZ");  // Valeur par défaut
            }

            // Ajout de l'entrée JSON pour ce fichier
            off += (size_t)snprintf(json + off,
                                    sizeof(json) - off,
                                    "{\"path\":\"%s\",\"ts\":\"%s\",\"size\":%ld}",
                                    full,
                                    tsFrag,
                                    (long)st.st_size);

            // Garde-fou pour éviter le débordement du buffer
            if (off > sizeof(json) - 256)
                break;
        }
        closedir(d);  // Fermeture du répertoire
    }

    // Fermeture du tableau JSON
    off += (size_t)snprintf(json + off, sizeof(json) - off, "]}");

    // Envoi de la réponse HTTP avec le JSON
    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: application/json\r\n"
              "Access-Control-Allow-Origin: *\r\n"
              "Content-Length: %lu\r\n\r\n%.*s",
              (unsigned long)off,
              (int)off,
              json);
    return 200;
}

// --- util: envoi HTTP de chaque fichier vers ton backend existant
// static int try_ship_file_to_node(const char* path);
// … (branche ta libcurl “ship_file_to_server” déjà utilisée)
// Envoie JSON -> Node
static gboolean http_post_json(const char* api_key, const char* json, long* http_code_out) {
    CURL* curl = curl_easy_init();
    if (!curl)
        return FALSE;

    struct curl_slist* headers = NULL;
    headers                    = curl_slist_append(headers, "Content-Type: application/json");
    if (api_key) {
        char h[256];
        snprintf(h, sizeof h, "X-API-Key: %s", api_key);
        headers = curl_slist_append(headers, h);
    }

    curl_easy_setopt(curl, CURLOPT_URL, HTTP_TARGET);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    CURLcode rc    = curl_easy_perform(curl);
    long http_code = 0;
    if (http_code_out)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code_out)
        *http_code_out = http_code;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return (rc == CURLE_OK);
}

// Lit un fichier et l'envoie (puis, si succès 200/201, on peut le renommer ".sent")
static int try_ship_file_to_node(const char* filepath, const char* api_key) {
    // on entre dans la fonction ship
    syslog(LOG_INFO, "try_ship_file_to_node %s", filepath);
    gchar* contents = NULL;
    gsize len       = 0;
    if (!g_file_get_contents(filepath, &contents, &len, NULL)) {
        syslog(LOG_WARNING, "Cannot read %s to ship", filepath);
        return -1;
    }
    long code   = 0;
    gboolean ok = http_post_json(api_key, contents, &code);
    if (ok && (code == 200 || code == 201)) {
        syslog(LOG_INFO, "Shipped OK %s (HTTP %ld)", filepath, code);
        gchar* sent = g_strconcat(filepath, ".sent", NULL);
        g_rename(filepath, sent);  // garde une trace, évite de supprimer brutalement
        g_free(sent);
        return 0;
    } else {
        syslog(LOG_WARNING, "Ship failed %s (HTTP %ld)", filepath, code);
    }
    g_free(contents);
    return -1;
}

/**
 * Handler pour la route /send
 * Cette fonction traite une requête POST contenant un corps JSON avec une liste de fichiers à
 * envoyer. Elle gère les préflights CORS, lit le corps de la requête, extrait les chemins des
 * fichiers, tente de les envoyer via try_ship_file_to_node, puis renvoie un JSON avec les
 * résultats.
 */
static int SendHandler(struct mg_connection* conn, void* cb) {
  (void)cb;
  const struct mg_request_info* ri = mg_get_request_info(conn);
  syslog(LOG_INFO, "Civet hit: %s %s", ri->request_method, ri->local_uri);

  // 1) Préflight CORS
  if (!strcmp(ri->request_method, "OPTIONS")) {
    mg_printf(conn,
      "HTTP/1.1 204 No Content\r\n"
      "Access-Control-Allow-Origin: *\r\n"
      "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
      "Access-Control-Allow-Headers: Content-Type, X-API-Key\r\n"
      "Content-Length: 0\r\n\r\n");
    return 204;
  }

  // 2) POST obligatoire
  if (strcmp(ri->request_method, "POST")) {
    mg_send_http_error(conn, 405, "Method Not Allowed");
    return 405;
  }

  // 3) Lire exactement Content-Length octets
  long long need = ri->content_length;              // CivetWeb fournit la taille
  if (need <= 0 || need > 1<<20) {                  // garde-fou (<=1MB)
    mg_send_http_error(conn, 400, "Bad or missing Content-Length");
    return 400;
  }
  char *body = (char*)malloc((size_t)need + 1);
  if (!body) { mg_send_http_error(conn, 500, "OOM"); return 500; }

  size_t got = 0;
  while (got < (size_t)need) {
    int r = mg_read(conn, body + got, (size_t)need - got);
    if (r <= 0) { free(body); mg_send_http_error(conn, 400, "Body read failed"); return 400; }
    got += (size_t)r;
  }
  body[got] = '\0';

  // 4) Parcours très simple des chemins dans le JSON: { "files": ["...","..."] }
  const char* p = body;
  char shipped[32768] = {0}; size_t so = 0;
  int ok = 0, ko = 0;

  while ((p = strstr(p, "\"/"))) {
    const char* q = strchr(p+1, '"');
    if (!q) break;
    size_t len = (size_t)(q - (p+1));
    if (len > 1000) len = 1000;

    char path[1024]; memcpy(path, p+1, len); path[len] = '\0';
    p = q + 1;

    int rc = try_ship_file_to_node(path, NULL);     // envoie via cURL
    if (rc == 0) {
      if (so) so += (size_t)snprintf(shipped+so, sizeof(shipped)-so, ",");
      so += (size_t)snprintf(shipped+so, sizeof(shipped)-so, "\"%s\"", path);
      ok++;
    } else {
      ko++;
    }
  }
  free(body);
  char resp[128];
  int n = snprintf(resp, sizeof resp,
                   "{ \"ok\": true, \"sent\": %d, \"failed\": %d }",
                   ok, ko);
  if (n < 0) n = 0;
  if (n > (int)sizeof(resp)) n = (int)sizeof(resp);

  mg_printf(conn,
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Headers: Content-Type, X-Requested-With\r\n"
    "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
    "Connection: close\r\n"
    "Content-Length: %d\r\n\r\n%.*s",
    n, n, resp);
  return 200;
}

// *******************************************************************************




// *******************************************************************************
// updater.c
// #include "updater.h"
// #include <curl/curl.h>
// #include <string.h>
// #include <stdio.h>

static size_t sink(void* ptr, size_t sz, size_t nm, void* stream) {
  return fwrite(ptr, sz, nm, (FILE*)stream);
}

static gboolean http_download(const char* url, const char* out_path, char err[256]) {
  CURL* c = curl_easy_init();
  if (!c) { g_snprintf(err,256,"curl init fail"); return FALSE; }
  FILE* f = fopen(out_path, "wb");
  if (!f) { g_snprintf(err,256,"open %s fail", out_path); curl_easy_cleanup(c); return FALSE; }

  curl_easy_setopt(c, CURLOPT_URL, url);
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(c, CURLOPT_USERAGENT, "acap-updater/1.0");
  CURLcode rc = curl_easy_perform(c);
  curl_easy_cleanup(c);
  fclose(f);
  if (rc != CURLE_OK) { g_snprintf(err,256,"download rc=%d", rc); unlink(out_path); return FALSE; }
  return TRUE;
}
// always comment code
#include <curl/curl.h>

// petit buffer mémoire pour récupérer les réponses HTTP
struct mem { char *p; size_t n; };
static size_t write_cb(char *ptr, size_t sz, size_t nm, void *ud){
  struct mem *m=(struct mem*)ud; size_t add=sz*nm;
  char *np=(char*)realloc(m->p, m->n+add+1); if(!np) return 0;
  m->p=np; memcpy(m->p+m->n, ptr, add); m->n+=add; m->p[m->n]=0; return add;
}

/**
 * axis_app_version
 * - Interroge VAPIX: /axis-cgi/applications/list.cgi?format=json
 * - Trouve l'objet avec "id":"<app_name>" et extrait "version":"x.y.z"
 * - out reçoit la version (chaine non vide) si trouvée.
 * Retour: TRUE si ok (version trouvée), FALSE sinon (err rempli).
 */

static gboolean axis_app_version_xml(const char* user, const char* pass,
                                     const char* app_id,
                                     char* out, size_t outsz, char err[256]) {
  struct mem { char *p; size_t n; } m = {0};
  CURL* c = curl_easy_init();
  if(!c){ snprintf(err,256,"curl init"); return FALSE; }

  // list.cgi renvoie XML par défaut
  curl_easy_setopt(c, CURLOPT_URL, "http://127.0.0.1/axis-cgi/applications/list.cgi");
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);   // ton callback qui accumule dans m
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &m);
  // auth digest au besoin (si 127.0.0.1 n'est pas libre)
  if (user && pass) {
    curl_easy_setopt(c, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
    curl_easy_setopt(c, CURLOPT_USERNAME, user);
    curl_easy_setopt(c, CURLOPT_PASSWORD, pass);
  }
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);

  CURLcode rc = curl_easy_perform(c);
  long http=0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http);
  curl_easy_cleanup(c);

  if (rc!=CURLE_OK || http!=200) {
    snprintf(err,256,"list.cgi rc=%d http=%ld", rc, http);
    free(m.p); return FALSE;
  }
  if (!m.p || !*m.p) { snprintf(err,256,"empty body"); free(m.p); return FALSE; }

  // Cherche le bloc <application ... Name="app_id" ... Version="X.Y.Z" ... />
  char needle[128];
  snprintf(needle, sizeof needle, "Name=\"%s\"", app_id);
  const char* p = strstr(m.p, needle);
  if (!p) { snprintf(err,256,"app '%s' not found", app_id); free(m.p); return FALSE; }

  const char* v = strstr(p, "Version=\"");
  if (!v) { snprintf(err,256,"Version attribute missing"); free(m.p); return FALSE; }
  v += strlen("Version=\"");
  const char* q = strchr(v, '"');
  if (!q) { snprintf(err,256,"parse error"); free(m.p); return FALSE; }

  size_t n = (size_t)(q - v);
  if (n >= outsz) n = outsz - 1;
  memcpy(out, v, n); out[n] = '\0';
  free(m.p);
  return *out != '\0';
}

/**
 * wait_for_version
 * - poll list.cgi jusqu’à ce que la version soit disponible (après install)
 */

// Petit polling post-install (certaines caméras mettent 1–5 s à refléter la version)
static gboolean wait_for_version(const char* user, const char* pass,
                                 const char* app_id,
                                 char* out, size_t outsz, char err[256]) {
  for (int i=0; i<10; ++i) {                 // 10 tentatives max
    if (axis_app_version_xml(user, pass, app_id, out, outsz, err)) return TRUE;
    usleep(1000*1000);                       // 1 seconde
  }
  snprintf(err,256,"version not reported after install");
  return FALSE;
}


// always comment code
// 1) extraire le nom de fichier depuis l'URL .eap (il contient déjà la version)
static void make_upload_filename(const char* eap_url, char* fname, size_t sz) {
  const char* base = strrchr(eap_url, '/');
  base = base ? base + 1 : "app.eap";             // ex: web_server_rev_proxy_1_12_0_armv7hf.eap

  // 2) créer un nom unique pour éviter EPERM sur /tmp (sticky bit) côté caméra
  //    on insère _<epoch> avant .eap (Postman varie aussi naturellement via le nom choisi)
  const char* dot = strrchr(base, '.');
  if (dot && strcmp(dot, ".eap")==0) {
    // "name" + "_" + epoch + ".eap"
    size_t stem_len = (size_t)(dot - base);
    if (stem_len > sz-32) stem_len = sz-32;       // garde une marge
    memcpy(fname, base, stem_len);
    fname[stem_len] = 0;
    snprintf(fname + stem_len, sz - stem_len, "_%ld.eap", (long)time(NULL));
  } else {
    // pas d'extension reconnue -> fallback unique
    snprintf(fname, sz, "%s_%ld", base, (long)time(NULL));
  }
}
// Upload via upload.cgi, sans forcer filename, et récupère le "package" réel renvoyé par la cam
static gboolean vp_upload_get_package(const char* eap_path,
                                      const char* user, const char* pass,
                                      char* out_pkg, size_t out_pkg_sz,
                                      char err[256]) {
  CURL* c = curl_easy_init(); if (!c) { g_snprintf(err,256,"curl init"); return FALSE; }

  // multipart: champ "file" (comme Postman), pas de curl_mime_filename => la cam choisit le nom
  curl_mime* form = curl_mime_init(c);
  curl_mimepart* f = curl_mime_addpart(form);
  curl_mime_name(f, "file");
  curl_mime_filedata(f, eap_path);

  // buffer   pour le body
  struct mem { char *p; size_t n; } m = {0};
  char ebuf[CURL_ERROR_SIZE]={0};

  curl_easy_setopt(c, CURLOPT_URL, "http://127.0.0.1/axis-cgi/applications/upload.cgi");
  curl_easy_setopt(c, CURLOPT_MIMEPOST, form);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &m);
  curl_easy_setopt(c, CURLOPT_ERRORBUFFER, ebuf);
  curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
  if (user && pass) {
    curl_easy_setopt(c, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
    curl_easy_setopt(c, CURLOPT_USERNAME, user);
    curl_easy_setopt(c, CURLOPT_PASSWORD, pass);
  }

  CURLcode rc = curl_easy_perform(c);
  long http=0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http);

  syslog(LOG_INFO, "upload.cgi rc=%d http=%ld body[0..200]=%.200s",
         rc, http, m.p ? m.p : "");

  curl_mime_free(form);
  curl_easy_cleanup(c);

  if (rc != CURLE_OK || http < 200 || http >= 300) {
    g_snprintf(err,256,"upload failed rc=%d http=%ld %s", rc, http, ebuf[0]?ebuf:"");
    free(m.p);
    return FALSE;
  }

  // Extraction "package=" …      (les logs Axis montrent souvent « Uploaded ... as /tmp/upload.XYZ »)
  // On cherche d'abord "package=" ; sinon on tente " as /tmp/upload." comme fallback.
  gboolean ok = FALSE;
  if (m.p) {
    const char* p = strstr(m.p, "package=");
    if (p) {
      p += 8; const char* q = strpbrk(p, "\r\n \t\"'");
      size_t n = q ? (size_t)(q - p) : strlen(p);
      if (n && n < out_pkg_sz) { memcpy(out_pkg, p, n); out_pkg[n]=0; ok = TRUE; }
    }
    if (!ok) {
      const char* a = strstr(m.p, " as /tmp/");
      if (a) {
        a += 4;                // saute " as "
        const char* q = strpbrk(a, "\r\n \t\"'");
        size_t n = q ? (size_t)(q - a) : strlen(a);
        if (n && n < out_pkg_sz) { memcpy(out_pkg, a, n); out_pkg[n]=0; ok = TRUE; }
      }
    }
  }
  free(m.p);

  if (!ok) { g_snprintf(err,256,"upload ok but no package name in response"); return FALSE; }
  return TRUE;
}

// always comment code
gboolean download_and_install_eap(const char* eap_url,
                                  const char* cam_user,
                                  const char* cam_pass,
                                  char err[256]) {
  // 1) télécharger localement
  // Create the downloads subfolder in /tmp if it doesn't exist to save downloaded files in a subfolder of tmp
  if (mkdir("/tmp/acap_updates", 0755) != 0 && errno != EEXIST) {
      g_snprintf(err, 256, "Failed to create /tmp/acap_updates directory");
      return FALSE;
  }
  char fname[128]; make_upload_filename(eap_url, fname, sizeof fname);
  char tmp[256];   snprintf(tmp, sizeof tmp, "/tmp/acap_updates/%s", fname);
  syslog(LOG_INFO, "DOWNLOAD OF RELEASE");
  if (!http_download(eap_url, tmp, err)) return FALSE;
  syslog(LOG_INFO, "Downloaded to %s", tmp);
  syslog(LOG_INFO, "eap url used for update is set to %s", eap_url);

  // 2) upload + lire package réel renvoyé par upload.cgi
  syslog(LOG_INFO, "UPDATE OF RELEASE (upload.cgi)");
  char pkg[128]={0};
  if (!vp_upload_get_package(tmp, cam_user, cam_pass, pkg, sizeof pkg, err)) {
    return FALSE;
  }
  syslog(LOG_INFO, "upload.cgi assigned package: %s", pkg);

  // 3) installer explicitement ce package
  // if (!vp_install_by_package(pkg, cam_user, cam_pass, err)) {
  //   return FALSE;
  // }

  // 4) vérifier la version via list.cgi (XML) avec polling
  char ver[64]={0};
  if (!wait_for_version(cam_user, cam_pass, APP_ID, ver, sizeof ver, err)) return FALSE;
  syslog(LOG_INFO, "Installed app version: %s", ver);

  // (optionnel) comparer à la version attendue (extraite du nom .eap), sinon log “mismatch”
  return TRUE;
}


// ——— Bi-hebdo ———
static gboolean file_mtime_days_ago(const char* p, int* days) {
  struct stat st; if (stat(p, &st) != 0) return FALSE;
  time_t now = time(NULL);
  *days = (int)((now - st.st_mtime) / (60*60*24));
  return TRUE;
}

gboolean should_check_update_biweekly(const char* stamp_path, int days) {
  int d=0; if (!file_mtime_days_ago(stamp_path, &d)) return TRUE; // pas de fichier => check
  return d >= days;
}
gboolean touch_update_stamp(const char* stamp_path, char err[128]) {
  FILE* f = fopen(stamp_path, "ab"); if (!f) { g_snprintf(err,128,"touch fail"); return FALSE; }
  fclose(f);
  utimensat(AT_FDCWD, stamp_path, NULL, 0); // met à “maintenant”
  return TRUE;
}


// static const char* kStamp = "/var/opt/axstorage/._last_update";
// static const char* kReleaseURL = "https://github.com/<org>/<repo>/releases/latest/download/app.eap";
// Cam s’auto-auth si on proxifie localement ; sinon passer admin/pass:
// static const char* USER = NULL;
// static const char* PASS = NULL;
/*

}
*/
static int UpdateHandler(struct mg_connection* conn, void* cb) {
    (void)cb;

      syslog(LOG_INFO, "SOMEWHERE IN UPDATE HANDLER");
      
      // gboolean ok = download_and_install_eap(DEFAULT_RELEASE_URL, USER, PASS, err);
      
      /*gboolean ok = update_from_github("ChampleinMyPC", "axWebServerApp", "arm", NULL, USER, PASS, err);*/
      
      // ✅ résoudre l’asset .eap, puis installer
      char err[256]={0};
      char* eap = resolve_latest_eap_url("ChampleinMyPC","axWebServerApp",
                                        /*must_contain*/NULL, /*token*/NULL, err);
      if (!eap) { mg_send_http_error(conn, 500, "%s", err); return 500; }
      gboolean ok = download_and_install_eap(eap, USER, PASS, err);
      syslog(LOG_INFO, "Update used asset: %s", eap); // log honnête
      free(eap);
      if (!ok) { mg_send_http_error(conn, 500, "%s", err); return 500; }
      
      
      const char* body = ok ? "{\"status\":\"ok\"}" : "{\"status\":\"fail\"}";
      syslog(LOG_INFO, "download_and_install_eap a rep : %d", ok);
      mg_printf(conn,
        "HTTP/1.1 %s\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n"
        "Content-Length: %lu\r\n\r\n%s",
        ok ? "200 OK" : "500 Internal Server Error", (unsigned long)strlen(body), body);
        
    syslog(LOG_INFO, "Update triggered from fixed URL: %s", DEFAULT_RELEASE_URL);
    if (!ok)
        syslog(LOG_WARNING, "Manual update failed: %s", err);

    return ok ? 200 : 500;

}

// *******************************************************************************


static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    struct mem *m = (struct mem *)userdata;
    size_t add = size * nmemb;
    char *np = (char *)realloc(m->p, m->n + add + 1);
    if (!np) return 0;
    m->p = np;
    memcpy(m->p + m->n, ptr, add);
    m->n += add;
    m->p[m->n] = '\0';
    return add;
}

// always comment code
// Parsing léger: on cherche un asset .eap et on récupère son browser_download_url
static char* strstr_between(const char* hay, const char* start, const char* end) {
  const char* s = strstr(hay, start); if (!s) return NULL;
  s += strlen(start);
  const char* e = strstr(s, end); if (!e) return NULL;
  size_t n = (size_t)(e - s);
  char* out = (char*)malloc(n + 1);
  if (!out) return NULL;
  memcpy(out, s, n); out[n] = '\0';
  return out;
}

static char* resolve_latest_eap_url(const char* org, const char* repo,
                                    const char* must_contain,
                                    const char* oauth_token,
                                    char err[256]) {
  char api[256];
  snprintf(api, sizeof api, "https://api.github.com/repos/%s/%s/releases/latest", org, repo);

  struct mem { char* p; size_t n; } m = {0};
  CURL* c = curl_easy_init();
  if (!c) { snprintf(err,256,"curl_easy_init"); return NULL; }

  struct curl_slist* hdr = NULL;
  hdr = curl_slist_append(hdr, "Accept: application/vnd.github+json");
  hdr = curl_slist_append(hdr, "User-Agent: champlein-updater/1.0");
  if (oauth_token && *oauth_token) {
    char auth[320]; snprintf(auth, sizeof auth, "Authorization: Bearer %s", oauth_token);
    hdr = curl_slist_append(hdr, auth);
  }

  curl_easy_setopt(c, CURLOPT_URL, api);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
  curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &m);

  CURLcode rc = curl_easy_perform(c);
  long http=0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http);
  curl_slist_free_all(hdr); curl_easy_cleanup(c);
  if (rc!=CURLE_OK) { snprintf(err,256,"GitHub GET failed: %s", curl_easy_strerror(rc)); free(m.p); return NULL; }
  if (http!=200) { snprintf(err,256,"GitHub HTTP %ld", http); free(m.p); return NULL; }

  // Cherche la zone "assets":[ ... ] pour limiter les faux positifs
  const char* assets = strstr(m.p, "\"assets\"");
  if (!assets) { snprintf(err,256,"No assets[] in latest release"); free(m.p); return NULL; }
  const char* arr = strchr(assets, '['); if (!arr) { snprintf(err,256,"assets not an array"); free(m.p); return NULL; }

  // Parcours des occurrences de "name":"...eap"
  const char* cur = arr;
  while ((cur = strstr(cur, "\"name\"")) != NULL) {
    // extrait le champ name
    char* name = strstr_between(cur, "\"name\":\"", "\"");
    if (!name) { cur += 6; continue; } // avance pour éviter boucle infinie
    int is_eap = 0;
    size_t ln = strlen(name);
    if (ln >= 4 && strcmp(name + ln - 4, ".eap") == 0) {
      is_eap = (!must_contain || strstr(name, must_contain) != NULL);
    }
    if (is_eap) {
      // depuis ce bloc, chercher le browser_download_url correspondant
      char* url = strstr_between(cur, "\"browser_download_url\":\"", "\"");
      free(name);
      if (!url) { cur += 6; continue; }
      free(m.p);
      return url; // caller free()
    }
    free(name);
    cur += 6;
  }

  snprintf(err,256,"No matching .eap asset found");
  free(m.p);
  return NULL;
}


// *******************************************************************************

int main(void) {
    signal(SIGTERM, stop_application);
    signal(SIGINT, stop_application);
    syslog(LOG_INFO, "Starting web_server_rev_proxy ACAP");
    mg_init_library(0);
    // daily_check_cb(NULL); // check au démarrage
    // g_timeout_add_seconds(24*3600, daily_check_cb, NULL); // puis tous les jours
    struct mg_callbacks callbacks = {0};
    const char* options[] =
        {"listening_ports", PORT, "request_timeout_ms", "10000", "error_log_file", "error.log", 0};

    struct mg_context* context = mg_start(&callbacks, 0, options);

    if (!context) {
        panic("Something went wrong when starting the web server");
    }

    syslog(LOG_INFO, "Server has started");

    mg_set_request_handler(context, "/list", ListHandler, NULL);
    mg_set_request_handler(context, "/send", SendHandler, NULL);
    mg_set_request_handler(context, "/update", UpdateHandler, NULL);
    
    // pour les appels via /local/web_server_rev_proxy/my_web_server/...
    mg_set_request_handler(context, "/local/web_server_rev_proxy/my_web_server/list", ListHandler, NULL);
    mg_set_request_handler(context, "/local/web_server_rev_proxy/my_web_server/send", SendHandler, NULL);
    // *******************************************************************************

    // *******************************************************************************
    // Boucle principale
    while (application_running) {
        sleep(1);
    }

    mg_stop(context);
    mg_exit_library();

    return EXIT_SUCCESS;
}

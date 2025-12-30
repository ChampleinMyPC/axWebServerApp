# Web Server Reverse Proxy – ACAP Axis

## 📌 Objectif

Ce projet est une **application ACAP pour caméras Axis** qui expose un **serveur HTTP interne** (basé sur **CivetWeb**) **via le reverse proxy Axis**.

Il permet :
- d’exposer des routes HTTP accessibles depuis l’interface web Axis
- de servir une API locale (ex: `/list`, `/download`, etc.)
- d’accéder à des fichiers stockés sur la caméra (ex : carte SD)
- de rester compatible avec un accès **local ou distant** à la caméra

---

## 🧠 Principe de fonctionnement

Axis OS fournit un **serveur Apache intégré**.  
Ce projet utilise le **reverse proxy ACAP** pour rediriger les requêtes vers un serveur interne embarqué.

### Schéma logique

```
Navigateur / Client HTTP
        |
        v
http://<CAMERA_IP>/local/<appName>/<route>
        |
        v
Apache (Axis)
 Reverse Proxy
        |
        v
CivetWeb (dans l’app ACAP)
```

📌 Format imposé par Axis :
```
/local/<appName>/<apiPath>
```

📚 Documentation officielle Axis :  
https://developer.axis.com/acap/develop/web-server-via-reverse-proxy/

---

## 📂 Structure du projet

```
web-server/
├── build-acap-multiarch.sh
├── Dockerfile
├── html/
│   ├── index.html
│   └── style.css
├── src/
│   └── web_server_rev_proxy_dev.c
├── lib/
│   └── libcivetweb.a
├── dist/
│   ├── aarch64/
│   └── armv7hf/
├── debug/
├── manifest.json
├── rep.json
└── TODO.md
```

---

## 🚀 Fonctionnalités principales

- Serveur HTTP embarqué via **CivetWeb**
- Reverse proxy compatible Axis Edge
- Routes HTTP accessibles via `/local/<appName>/...`
- Accès aux fichiers stockés sur la caméra
- Génération de réponses JSON
- Support multi-architecture :
  - `armv7hf`
  - `aarch64`

---

## 🛠️ Build & génération du package ACAP

### Build multi-architecture

```bash
./build-acap-multiarch.sh
```

Les fichiers `.eap` sont générés dans :
```
dist/
├── armv7hf/
└── aarch64/
```

📚 Documentation Axis :  
https://developer.axis.com/acap/develop/build-install-and-run/

---

## 🌐 Accès HTTP

Une fois l’application installée et démarrée :

```
http://<IP_CAMERA>/local/web_server_rev_proxy_dev/
```

Exemples :
```
GET /local/web_server_rev_proxy_dev/list
GET /local/web_server_rev_proxy_dev/list?start=...&end=...
```

⚠️ Notes importantes :
- `127.0.0.1:<port>` fonctionne **uniquement depuis la caméra**
- Pour un accès distant, utiliser l’IP ou le DNS de la caméra

---

## 🔐 Sécurité & authentification

- Le reverse proxy Axis applique automatiquement les règles d’accès
- L’utilisateur doit être authentifié sur la caméra
- Les routes non exposées via `/local/<appName>` ne sont pas accessibles

📚  
https://developer.axis.com/acap/authorization/

---

## 🧩 Dépendances

- **CivetWeb** (statique)  
  https://github.com/civetweb/civetweb
- glib / gio
- libcurl
- Axis Native SDK

Toutes les dépendances sont **gratuites**.

---

## 📝 TODO

Voir `TODO.md`, notamment :
- récupération du numéro de série caméra
- amélioration des erreurs HTTP
- validation des paramètres d’entrée

---

## 🧪 Debug local

Binaire généré dans :
```
debug/web_server_rev_proxy_dev
```

⚠️ Le reverse proxy Axis ne fonctionne pas hors caméra.

---

## 📄 Licence

Basé sur les exemples officiels Axis ACAP.

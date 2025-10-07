# Serveur HTTP via Proxy Inverse

Cet exemple démontre comment configurer le serveur web de l'appareil Axis (Apache) en mode [Proxy Inverse](https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html), où les requêtes HTTP vers l'application sont routées vers un serveur web [CivetWeb](https://github.com/civetweb/civetweb) s'exécutant à l'intérieur de l'application ACAP et agissant comme CGI.

L'avantage d'un serveur web proxy est que lors du portage de code existant vers votre application ACAP, la gestion de ses requêtes peut rester largement inchangée. Cela facilite le partage de code entre plateformes. La méthode proxy inverse applique un schéma d'URL comme suit :

`http://<AXIS_DEVICE_IP>/local/<appName>/<apiPath>`

Avec `<appName>` et `<apiPath>` définis dans le manifest.

Notez que cet exemple montre le concept de proxy inverse en utilisant CivetWeb, mais vous êtes libre d'utiliser n'importe quel serveur web de votre choix.

## Approche alternative

Un autre exemple servant des requêtes HTTP est [web-server-using-fastcgi](../web-server-using-fastcgi), où le serveur web de l'appareil Axis et l'API [FastCGI](https://developer.axis.com/acap/api/native-sdk-api/#fastcgi) prise en charge par ACAP sont utilisés.

## Configuration du proxy inverse dans le serveur Apache

Une configuration de proxy inverse offre un moyen flexible pour une application ACAP d'exposer une API externe via le serveur Apache dans AXIS OS et d'acheminer en interne les requêtes vers un serveur web s'exécutant dans l'application ACAP.

Le serveur Apache est configuré en utilisant le fichier `manifest.json` dans une application ACAP. Dans `manifest.json` sous `configuration`, il est possible de spécifier un `settingPage` et un `reverseProxy` où ce dernier connecte le serveur CivetWeb au serveur Apache.

Avant la version 1.5.0 du manifest, le proxy inverse n'était pris en charge que via le script postinstall. La méthode basée sur le manifest est plus stricte sur les URLs afin d'éviter les conflits de noms pouvant survenir dans l'ancien mécanisme. Lors de la mise à niveau, vos URLs changeront vers le format présenté dans [Serveur HTTP via Proxy Inverse](#serveur-http-via-proxy-inverse).

Le serveur web s'exécutant dans l'application ACAP peut également être exposé directement au réseau en permettant l'accès externe au port dans la configuration réseau de l'appareil. Il y a des inconvénients à exposer le serveur web directement au réseau tels que des ports non standard et l'absence de réutilisation de l'authentification, du TLS et d'autres fonctionnalités fournies par le serveur Apache.

## Serveur web CivetWeb

CivetWeb est un serveur web embarquable C pour Linux. C'est une excellente solution pour exécuter un serveur web sur Linux embarqué. En plus d'être un serveur HTTP, il a une API C qui peut être étendue comme souhaité. La documentation du serveur web CivetWeb [documentation](https://github.com/civetweb/civetweb/) décrit la configuration en détail. CivetWeb est open source et contiendra différentes licences selon les fonctionnalités que vous compilez. Veuillez consulter le [dépôt de CivetWeb](https://github.com/civetweb/civetweb/) pour plus d'informations.

## Pour commencer

Ces instructions vous guideront sur la façon d'exécuter le code. Voici la structure utilisée dans l'exemple :

```sh
web-server
├── app
│   ├── LICENSE
│   └── manifest.json
├── Dockerfile
└── README.md
```

- **app/LICENSE** - Liste le code source sous licence open source dans l'application.
- **app/manifest.json** - Définit l'application et sa configuration.
- **Dockerfile** - Construit une image conteneur Axis et l'exemple spécifié.
- **README.md** - Instructions étape par étape pour exécuter l'exemple.

## Limitations

- Le proxy inverse Apache ne peut pas traduire le contenu avec des adresses absolues (c'est-à-dire /image.png) dans la page HTML. Utilisez uniquement du contenu relatif (c'est-à-dire image.png ou ../image.png). Voir [comment gérer correctement les URLs relatives avec un proxy inverse](https://serverfault.com/questions/561892/how-to-handle-relative-urls-correctly-with-a-reverse-proxy) pour plus d'informations.

### Comment exécuter le code

Voici les instructions étape par étape pour exécuter le programme. Essentiellement, commencer par la génération du fichier .eap à l'exécution sur un appareil.

#### Construire l'application

En étant dans votre répertoire de travail, exécutez les commandes suivantes :

> [!NOTE]
>
> Selon le réseau sur lequel votre machine de construction locale est connectée,
vous devrez peut-être ajouter des paramètres proxy
> pour Docker. Voir
> [Proxy lors de la construction](https://developer.axis.com/acap/develop/proxy/#proxy-in-build-time).

```sh
docker build --tag <APP_IMAGE> --build-arg ARCH=<ARCH> .
```

- `<APP_IMAGE>` est le nom pour taguer l'image, par exemple `web-server:1.0`
- `<ARCH>` est l'architecture du SDK, `armv7hf` ou `aarch64`.

Copiez le résultat de l'image conteneur vers un répertoire local `build` :

```sh
docker cp $(docker create <APP_IMAGE>):/opt/app ./build
```

Le répertoire `build` contient les artefacts de construction, où l'application ACAP se trouve avec le suffixe `.eap`, selon l'architecture du SDK choisie, l'un de ces fichiers devrait être présent :

- `web_server_rev_proxy_1_0_0_aarch64.eap`
- `web_server_rev_proxy_1_0_0_armv7hf.eap`

#### Installer et démarrer l'application

Accédez à la page des applications de l'appareil Axis :

```sh
http://<AXIS_DEVICE_IP>/index.html#apps
```

- Cliquez sur l'onglet `Apps` dans l'interface utilisateur de l'appareil
- Activez le commutateur `Allow unsigned apps`
- Cliquez sur le bouton `(+ Add app)` pour télécharger l'application
- Parcourez pour sélectionner l'application ACAP nouvellement construite, selon l'architecture :
  - `web_server_rev_proxy_1_0_0_aarch64.eap`
  - `web_server_rev_proxy_1_0_0_armv7hf.eap`
- Cliquez sur `Install`
- Démarrez l'application en activant le commutateur `Start`

#### La sortie attendue

Un utilisateur peut faire une requête HTTP à l'API de l'application en utilisant par exemple cURL

```sh
curl -u <USER>:<PASSWORD> --anyauth http://<AXIS_DEVICE_IP>/local/web_server_rev_proxy/my_web_server
```

Avec la sortie attendue

```sh
<html>
 <head><link rel="stylesheet" href="style.css"/></head>
 <title>
  Exemple de serveur web ACAP
 </title>
 <body>
  <h1>Exemple de serveur web ACAP</h1>
  Bienvenue sur l'exemple de serveur web, ce serveur est basé sur la bibliothèque C 
        <a href="https://github.com/civetweb/civetweb">CivetWeb</a>.
 </body>
</html>
```

Comme on peut le voir, c'est du code HTML, parcourez la page web
`http://<AXIS_DEVICE_IP>/local/web_server_rev_proxy/my_web_server`
pour la voir rendue.

Le journal de l'application peut être trouvé soit par

- Parcourir `http://<AXIS_DEVICE_IP>/axis-cgi/admin/systemlog.cgi?appname=web_server_rev_proxy`.
- Parcourir la page des applications et cliquer sur `App log`.

## Rôles des fichiers

- **app/manifest.json** : Fichier de configuration JSON définissant l'application ACAP, sa version, son nom, et la configuration du proxy inverse pour router les requêtes vers le serveur interne.
- **app/web_server_rev_proxy.c** : Code source principal en C du serveur web utilisant CivetWeb. Implémente les gestionnaires pour les endpoints `/list` (lister les fichiers de comptages dans une plage de dates), `/send` (envoyer les fichiers au serveur backend via HTTP POST), et support WebSocket pour la communication en temps réel.
- **app/web_server_rev_proxy_mgr.c** : Version alternative du code serveur, similaire au fichier principal mais configuré pour utiliser un socket Unix au lieu d'un port TCP, potentiellement pour une communication interne plus sécurisée.
- **app/Makefile** : Script de construction pour compiler les programmes C, liant avec les bibliothèques nécessaires comme CivetWeb, cURL, et GLib.
- **app/html/index.html** : Interface utilisateur web (UI) en HTML/CSS/JavaScript pour interagir avec l'application. Permet de sélectionner des plages de dates, lister les fichiers de comptages, et les envoyer au serveur backend.
- **Dockerfile** : Script Docker pour construire l'image conteneur Axis, incluant la compilation de CivetWeb et la construction de l'application ACAP.
- **README.md** : Ce fichier de documentation expliquant l'utilisation du projet.

Pour la documentation officielle, consultez [Axis Developer Portal](https://developer.axis.com/acap/).

## Licence

**[Licence Apache 2.0](../LICENSE)**

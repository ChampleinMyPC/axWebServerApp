#!/usr/bin/env bash
set -euo pipefail

# Petit script pour construire l'application ACAP
# pour les deux archis : armv7hf et aarch64.

# ⚙️ Paramètres communs au Dockerfile
VERSION="${VERSION:-12.6.0}"
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"

# Dossier de sortie pour les binaires
DIST_DIR="./dist"
mkdir -p "${DIST_DIR}"

# Architectures à construire
ARCHS=("armv7hf" "aarch64")

for ARCH in "${ARCHS[@]}"; do
    IMAGE_TAG="acap-app-builder:${ARCH}"

    echo "🚧 Build de l'image pour ARCH=${ARCH}..."
    docker build \
        --build-arg ARCH="${ARCH}" \
        --build-arg VERSION="${VERSION}" \
        --build-arg UBUNTU_VERSION="${UBUNTU_VERSION}" \
        -t "${IMAGE_TAG}" \
        .

    echo "📦 Recherche et extraction du package ACAP pour ${ARCH}..."

    # On crée un conteneur qui reste vivant (sleep) pour pouvoir faire des exec
    CID="$(docker create --entrypoint sh "${IMAGE_TAG}" -c 'sleep 600')"

    # On démarre le conteneur
    docker start "${CID}" >/dev/null

    # On cherche le premier fichier .eap sous /opt
    # (adaptable si besoin : / au lieu de /opt, etc.)
    EAP_PATH="$(docker exec "${CID}" sh -lc 'find /opt -maxdepth 6 -name "*.eap" 2>/dev/null | head -n 1')"

    if [ -z "${EAP_PATH}" ]; then
        echo "❌ Aucun fichier .eap trouvé dans le conteneur pour ARCH=${ARCH}."
        echo "   -> Vérifie que ton Dockerfile lance bien acap-build et génère un .eap."
        echo "   -> Tu peux inspecter l'image avec par ex. :"
        echo "      docker run --rm -it ${IMAGE_TAG} sh"
        # On nettoie le conteneur avant de passer à l'arch suivante
        docker rm -f "${CID}" >/dev/null
        continue
    fi

    OUT_DIR="${DIST_DIR}/${ARCH}"
    mkdir -p "${OUT_DIR}"

    echo "   ✅ Fichier trouvé : ${EAP_PATH}"
    echo "   📂 Copie vers ${OUT_DIR}..."

    # On copie le .eap depuis le conteneur vers le host
    docker cp "${CID}:${EAP_PATH}" "${OUT_DIR}/"

    # Nettoyage du conteneur
    docker rm -f "${CID}" >/dev/null

    echo "   ✅ Binaire ${ARCH} disponible dans ${OUT_DIR}"
done

echo "✨ Terminé. Regarde dans ${DIST_DIR}/armv7hf et ${DIST_DIR}/aarch64"

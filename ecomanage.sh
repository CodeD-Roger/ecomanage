#!/bin/bash

# Script d'installation d'Odoo 18 sur Ubuntu
# Idempotent, automatisé, sans interaction
# Exit en cas d'erreur (sauf pour certaines commandes)
set -e

# ------------------- Variables configurables -------------------
ODOO_VERSION=18
ODOO_DB_PASSWORD="123456"
ODOO_PORT=8069
ODOO_USER="odoo${ODOO_VERSION}"
ODOO_HOME="/opt/odoo${ODOO_VERSION}"
ODOO_CONF="/etc/odoo${ODOO_VERSION}.conf"
ODOO_SERVICE="odoo${ODOO_VERSION}"
LOG_DIR="/var/log/odoo${ODOO_VERSION}"
SSH_KEY_DIR="/root/.ssh"
SSH_PRIVATE_KEY="${SSH_KEY_DIR}/odoo18_key"
SSH_PUBLIC_KEY="${SSH_KEY_DIR}/odoo18_key.pub"
SSH_USER="odoo_user"

# ------------------- Fonctions utilitaires -------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "Erreur : Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

get_server_ip() {
    ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -n 1
}

check_apt_sources() {
    log "Vérification des sources APT"
    if grep -r "deb.debian.org" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        log "Attention : Dépôts Debian détectés. Cela peut causer des erreurs. Exécutez fix.sh pour nettoyer les sources APT."
    fi
}

get_ssh_service_name() {
    if systemctl list-units --full -all | grep -q "ssh.service"; then
        echo "ssh.service"
    elif systemctl list-units --full -all | grep -q "sshd.service"; then
        echo "sshd.service"
    else
        log "Erreur : Aucun service SSH (ssh.service ou sshd.service) trouvé"
        exit 1
    fi
}

# ------------------- Vérification initiale -------------------
check_root
SERVER_IP=$(get_server_ip)
log "Démarrage de l'installation d'Odoo ${ODOO_VERSION} sur ${SERVER_IP}"

# Vérification des sources APT
check_apt_sources

# ------------------- 1. Mise à jour & dépendances -------------------
log "Mise à jour du système et installation des dépendances"

# Désactiver temporairement le redémarrage automatique de SSH
SSH_SERVICE=$(get_ssh_service_name)
log "Désactivation temporaire du service SSH (${SSH_SERVICE}) pour éviter les redémarrages automatiques"
systemctl mask "${SSH_SERVICE}" || log "Erreur lors de la désactivation temporaire de ${SSH_SERVICE}, continuation..."

apt update -y || log "Erreur lors de apt update, continuation..."
log "Étape : apt update terminé"
apt upgrade -y
log "Étape : apt upgrade terminé"

apt install -y \
    python3 python3-venv python3-dev python3-pip \
    postgresql postgresql-contrib \
    nodejs npm \
    wkhtmltopdf \
    git \
    build-essential \
    libpq-dev \
    libxml2-dev libxslt1-dev \
    zlib1g-dev libjpeg-dev \
    libfreetype-dev \
    fonts-liberation \
    libldap2-dev libsasl2-dev \
    openssh-server
log "Étape : Installation des dépendances terminée"

# Réactiver le service SSH après les mises à jour
log "Réactivation du service SSH (${SSH_SERVICE})"
systemctl unmask "${SSH_SERVICE}" || log "Erreur lors de la réactivation de ${SSH_SERVICE}, continuation..."
systemctl enable "${SSH_SERVICE}"
log "Service SSH (${SSH_SERVICE}) activé pour démarrer au boot"

npm install -g rtlcss
log "Étape : Installation de rtlcss terminée"

# ------------------- 2. Installation d'Odoo 18 -------------------
log "Configuration de l'utilisateur et installation d'Odoo ${ODOO_VERSION}"

if ! id "${ODOO_USER}" >/dev/null 2>&1; then
    useradd -r -m -d "${ODOO_HOME}" -s /bin/false "${ODOO_USER}"
    log "Utilisateur ${ODOO_USER} créé"
else
    log "Utilisateur ${ODOO_USER} existe déjà"
fi

# Configuration de PostgreSQL
log "Configuration de PostgreSQL"
systemctl enable postgresql
systemctl start postgresql
log "Étape : Démarrage de PostgreSQL terminé"

# Création de l'utilisateur PostgreSQL (idempotent)
if ! su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${ODOO_USER}'\" | grep -q 1" 2>/dev/null; then
    su - postgres -c "createuser -s ${ODOO_USER}"
    log "Utilisateur PostgreSQL ${ODOO_USER} créé"
else
    log "Utilisateur PostgreSQL ${ODOO_USER} existe déjà"
fi
su - postgres -c "psql -c \"ALTER USER ${ODOO_USER} WITH ENCRYPTED PASSWORD '${ODOO_DB_PASSWORD}'\""
log "Étape : Configuration de l'utilisateur PostgreSQL terminée"

# Clonage du dépôt Odoo (idempotent)
if [ ! -d "${ODOO_HOME}/odoo" ]; then
    git clone --depth 1 --branch ${ODOO_VERSION}.0 https://github.com/odoo/odoo.git "${ODOO_HOME}/odoo"
    chown -R "${ODOO_USER}:${ODOO_USER}" "${ODOO_HOME}"
    log "Dépôt Odoo cloné dans ${ODOO_HOME}/odoo"
else
    log "Dépôt Odoo déjà présent dans ${ODOO_HOME}/odoo"
fi
log "Étape : Clonage du dépôt Odoo terminé"

# Configuration de l'environnement virtuel
log "Configuration de l'environnement virtuel Python"
if [ ! -d "${ODOO_HOME}/venv" ]; then
    python3 -m venv "${ODOO_HOME}/venv"
    source "${ODOO_HOME}/venv/bin/activate"
    pip install --upgrade pip
    pip install -r "${ODOO_HOME}/odoo/requirements.txt"
    pip install phonenumbers
    deactivate
    chown -R "${ODOO_USER}:${ODOO_USER}" "${ODOO_HOME}/venv"
    log "Environnement virtuel configuré"
else
    log "Environnement virtuel déjà configuré"
fi
log "Étape : Configuration de l'environnement virtuel terminée"

mkdir -p "${LOG_DIR}"
chown "${ODOO_USER}:${ODOO_USER}" "${LOG_DIR}"

log "Création du fichier de configuration ${ODOO_CONF}"
cat > "${ODOO_CONF}" << EOF
[options]
admin_passwd = admin
db_host = False
db_port = False
db_user = ${ODOO_USER}
db_password = ${ODOO_DB_PASSWORD}
addons_path = ${ODOO_HOME}/odoo/addons
logfile = ${LOG_DIR}/odoo.log
log_level = info
http_port = ${ODOO_PORT}
EOF
chown "${ODOO_USER}:${ODOO_USER}" "${ODOO_CONF}"
chmod 640 "${ODOO_CONF}"
log "Étape : Création du fichier de configuration Odoo terminée"

log "Création du service systemd ${ODOO_SERVICE}"
cat > "/etc/systemd/system/${ODOO_SERVICE}.service" << EOF
[Unit]
Description=Odoo ${ODOO_VERSION} Service
After=network.target postgresql.service

[Service]
Type=simple
User=${ODOO_USER}
Group=${ODOO_USER}
ExecStart=${ODOO_HOME}/venv/bin/python3 ${ODOO_HOME}/odoo/odoo-bin -c ${ODOO_CONF}
Restart=always
SyslogIdentifier=odoo${ODOO_VERSION}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${ODOO_SERVICE}"
systemctl restart "${ODOO_SERVICE}"
log "Étape : Création et démarrage du service Odoo terminée"

# ------------------- 3. Sécurisation SSH -------------------
log "Sécurisation de la configuration SSH"

if ! dpkg -l | grep -q openssh-server; then
    log "Erreur : openssh-server n'est pas installé"
    exit 1
fi

SSH_SERVICE=$(get_ssh_service_name)
log "Service SSH détecté : ${SSH_SERVICE}"

mkdir -p "${SSH_KEY_DIR}"
chmod 700 "${SSH_KEY_DIR}"

if [ ! -f "${SSH_PRIVATE_KEY}" ]; then
    ssh-keygen -t ed25519 -f "${SSH_PRIVATE_KEY}" -N "" -C "odoo18@`hostname`" >/dev/null
    log "Clé SSH ED25519 générée : ${SSH_PUBLIC_KEY}"
else
    log "Clé SSH ED25519 déjà existante : ${SSH_PUBLIC_KEY}"
fi

# Ajouter la clé publique de l'utilisateur actuel pour éviter la déconnexion
CURRENT_SSH_USER=$(whoami)
if [ -f "/home/${CURRENT_SSH_USER}/.ssh/id_rsa.pub" ]; then
    mkdir -p "/home/${SSH_USER}/.ssh"
    cat "/home/${CURRENT_SSH_USER}/.ssh/id_rsa.pub" >> "/home/${SSH_USER}/.ssh/authorized_keys"
    chown -R "${SSH_USER}:${SSH_USER}" "/home/${SSH_USER}/.ssh"
    chmod 700 "/home/${SSH_USER}/.ssh"
    chmod 600 "/home/${SSH_USER}/.ssh/authorized_keys"
    log "Clé publique de ${CURRENT_SSH_USER} ajoutée à ${AUTHORIZED_KEYS}"
else
    log "Aucune clé publique trouvée pour ${CURRENT_SSH_USER}, l'authentification par mot de passe sera conservée"
fi

if ! id "${SSH_USER}" >/dev/null 2>&1; then
    log "Saisie du mot de passe pour l'utilisateur SSH ${SSH_USER}"
    while true; do
        read -s -p "Entrez le mot de passe pour ${SSH_USER}: " password
        echo
        read -s -p "Confirmez le mot de passe: " password_confirm
        echo
        if [ "$password" = "$password_confirm" ]; then
            break
        else
            log "Les mots de passe ne correspondent pas. Veuillez réessayer."
        fi
    done
    adduser --gecos "" "${SSH_USER}"
    echo "${SSH_USER}:${password}" | chpasswd
    usermod -aG sudo "${SSH_USER}"
    mkdir -p "/home/${SSH_USER}/.ssh"
    cat "${SSH_PUBLIC_KEY}" >> "/home/${SSH_USER}/.ssh/authorized_keys"
    chown -R "${SSH_USER}:${SSH_USER}" "/home/${SSH_USER}/.ssh"
    chmod 700 "/home/${SSH_USER}/.ssh"
    chmod 600 "/home/${SSH_USER}/.ssh/authorized_keys"
    log "Utilisateur SSH ${SSH_USER} créé avec mot de passe et ajouté au groupe sudo"
else
    log "Utilisateur SSH ${SSH_USER} existe déjà"
fi

# Vérification de la présence d'une clé publique dans authorized_keys
AUTHORIZED_KEYS="/home/${SSH_USER}/.ssh/authorized_keys"
if [ ! -s "${AUTHORIZED_KEYS}" ]; then
    log "⚠️ Erreur : Aucune clé publique trouvée dans ${AUTHORIZED_KEYS}. L'authentification par mot de passe sera conservée pour éviter un verrouillage SSH."
    SSH_AUTH_METHOD="PasswordAuthentication yes"
else
    log "Clé publique détectée dans ${AUTHORIZED_KEYS}. Désactivation de l'authentification par mot de passe."
    SSH_AUTH_METHOD="PasswordAuthentication no"
fi

if [ -f "/etc/ssh/sshd_config" ]; then
    if [ ! -f "/etc/ssh/sshd_config.bak" ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        log "Sauvegarde de /etc/ssh/sshd_config effectuée"
    fi
else
    log "Aucun fichier /etc/ssh/sshd_config trouvé, création d'un nouveau fichier"
fi

# Écrire la configuration SSH dans un fichier temporaire pour éviter un rechargement automatique
log "Écriture de la configuration SSH dans un fichier temporaire"
TEMP_SSH_CONFIG="/tmp/sshd_config_temp"
cat > "${TEMP_SSH_CONFIG}" << EOF
# Configuration SSH sécurisée pour Odoo
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
${SSH_AUTH_METHOD}
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
ChallengeResponseAuthentication no
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
log "Étape : Création du fichier de configuration SSH temporaire terminée"

# ------------------- 4. Affichage final -------------------
log "Installation terminée avec succès !"

cat << EOF

✅ Installation d'Odoo ${ODOO_VERSION} terminée

🌐 URL d'accès à Odoo :
   - http://${SERVER_IP}:${ODOO_PORT}

🔑 Clés SSH générées :
   - Clé privée : ${SSH_PRIVATE_KEY}
   - Clé publique : ${SSH_PUBLIC_KEY}
   - Utilisateur SSH : ${SSH_USER}
   - Commande SSH : ssh -i <chemin_vers_clé_privée> ${SSH_USER}@${SERVER_IP}

⚙️ Statut du service Odoo :
$(systemctl is-active "${ODOO_SERVICE}" | grep -q "active" && echo "Actif" || echo "Inactif")

📝 Fichier de configuration :
   - ${ODOO_CONF}

🎉 Odoo ${ODOO_VERSION} est prêt à l'utilisation !
Connectez-vous via l'URL ci-dessus et configurez votre instance Odoo.

⚠️ Sauvegardez la clé privée SSH (${SSH_PRIVATE_KEY}) dans un endroit sûr !
$([ ! -s "${AUTHORIZED_KEYS}" ] && echo -e "\n⚠️ ATTENTION : Aucune clé publique dans ${AUTHORIZED_KEYS}. L'authentification par mot de passe est activée pour éviter un verrouillage SSH.")

EOF

# ------------------- 5. Application de la configuration SSH et délai -------------------
log "Application de la configuration SSH"
mv "${TEMP_SSH_CONFIG}" /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 644 /etc/ssh/sshd_config
log "Étape : Configuration SSH appliquée"

log "⚠️ ATTENTION : Vous avez 300 secondes (5 minutes) pour copier la clé privée SSH (${SSH_PRIVATE_KEY}) avant la demande de redémarrage du service SSH."
sleep 300
log "Veuillez taper 'RESTART' pour redémarrer le service SSH (${SSH_SERVICE}) et appliquer la configuration sécurisée :"
read -r user_input
if [ "$user_input" = "RESTART" ]; then
    log "Redémarrage du service SSH (${SSH_SERVICE}) pour appliquer la configuration sécurisée"
    systemctl restart "${SSH_SERVICE}"
else
    log "Redémarrage du service SSH annulé. Veuillez redémarrer manuellement avec 'systemctl restart ${SSH_SERVICE}' si nécessaire."
fi

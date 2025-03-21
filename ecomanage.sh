#!/bin/bash

# Script ecomanage.sh
# Automatise l'installation d'ERPNext sur Debian
# Configure SSH sécurisé et UFW

# Fonction pour afficher les messages avec des couleurs
print_message() {
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color

    case $1 in
        "info")
            echo -e "${GREEN}[INFO]${NC} $2"
            ;;
        "error")
            echo -e "${RED}[ERREUR]${NC} $2"
            ;;
        "warning")
            echo -e "${YELLOW}[ATTENTION]${NC} $2"
            ;;
    esac
}

# Vérification des privilèges sudo
if [ "$(id -u)" -ne 0 ]; then
    print_message "error" "Ce script doit être exécuté avec des privilèges sudo"
    exit 1
fi

# Création du fichier log
LOG_FILE="/var/log/ecomanage_install.log"
touch $LOG_FILE
chmod 644 $LOG_FILE

print_message "info" "Installation de Ecomanage (basé sur ERPNext) démarrée. Veuillez patienter..."
echo "$(date) - Installation démarrée" >> $LOG_FILE

# Mise à jour du système
print_message "info" "Mise à jour des paquets..."
apt update -qq && apt upgrade -y -qq >> $LOG_FILE 2>&1

# Vérification et installation des dépendances
print_message "info" "Installation des dépendances nécessaires..."
apt install -y curl git openssh-server ufw fail2ban >> $LOG_FILE 2>&1

# Déterminer l'utilisateur non-root
current_user=$(logname || echo $SUDO_USER)
if [ -z "$current_user" ]; then
    current_user="$(who | awk '{print $1}' | head -n1)"
fi

if [ -z "$current_user" ] || [ "$current_user" = "root" ]; then
    print_message "warning" "Impossible de déterminer l'utilisateur non-root. Utilisation de l'utilisateur actuel."
    current_user=$(whoami)
    
    # Si toujours root, créer un utilisateur
    if [ "$current_user" = "root" ]; then
        print_message "info" "Création d'un utilisateur non-root 'ecomanage'..."
        useradd -m -s /bin/bash ecomanage
        current_user="ecomanage"
    fi
fi

print_message "info" "Utilisation de l'utilisateur: $current_user pour les clés SSH"
USER_HOME=$(eval echo ~$current_user)

# Configuration de SSH sécurisé
print_message "info" "Configuration du serveur SSH pour une sécurité renforcée..."

# Sauvegarde du fichier de configuration SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configuration de SSH avec paramètres de sécurité renforcés
cat > /etc/ssh/sshd_config << EOF
# Configuration SSH sécurisée pour Ecomanage
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Paramètres d'authentification
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5

# Authentification par clé uniquement
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Fichier authorized_keys
AuthorizedKeysFile .ssh/authorized_keys

# Autres paramètres de sécurité
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Paramètres de sécurité supplémentaires
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
EOF

# Configuration de fail2ban pour SSH
print_message "info" "Configuration de fail2ban pour protéger SSH..."
cat > /etc/fail2ban/jail.d/ssh.conf << EOF
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

systemctl restart fail2ban >> $LOG_FILE 2>&1

# Création du répertoire .ssh s'il n'existe pas
if [ ! -d "$USER_HOME/.ssh" ]; then
    mkdir -p "$USER_HOME/.ssh"
    chmod 700 "$USER_HOME/.ssh"
    chown $current_user:$current_user "$USER_HOME/.ssh"
fi

# Génération de la clé SSH Ed25519 (plus sécurisée que RSA)
if [ ! -f "$USER_HOME/.ssh/id_ed25519" ]; then
    print_message "info" "Génération de clés SSH pour l'utilisateur $current_user..."
    # Utiliser sudo pour exécuter la commande en tant que l'utilisateur
    sudo -u $current_user ssh-keygen -t ed25519 -f "$USER_HOME/.ssh/id_ed25519" -N "" >> $LOG_FILE 2>&1
    chmod 600 "$USER_HOME/.ssh/id_ed25519"
    chmod 644 "$USER_HOME/.ssh/id_ed25519.pub"
    print_message "info" "Clé SSH Ed25519 générée pour l'utilisateur $current_user"
else
    print_message "warning" "Une clé SSH Ed25519 existe déjà pour l'utilisateur $current_user"
fi

# Configuration du fichier authorized_keys
print_message "info" "Configuration du fichier authorized_keys..."
touch "$USER_HOME/.ssh/authorized_keys"
cat "$USER_HOME/.ssh/id_ed25519.pub" > "$USER_HOME/.ssh/authorized_keys"
chmod 600 "$USER_HOME/.ssh/authorized_keys"
chown $current_user:$current_user "$USER_HOME/.ssh/authorized_keys"

# Redémarrage du service SSH
systemctl restart sshd >> $LOG_FILE 2>&1

# Test de la configuration SSH
print_message "info" "Test de la configuration SSH..."
# Attendre que le service SSH redémarre complètement
sleep 2

# Vérifier que le service SSH est actif
if ! systemctl is-active --quiet sshd; then
    print_message "error" "Le service SSH n'est pas actif. Vérifiez la configuration."
    # Restaurer la configuration précédente
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    systemctl restart sshd
    print_message "info" "Configuration SSH restaurée à l'état précédent."
else
    print_message "info" "Service SSH actif et configuré correctement."
fi

# Configuration de UFW
print_message "info" "Configuration du pare-feu UFW..."
ufw --force reset >> $LOG_FILE 2>&1
ufw default deny incoming >> $LOG_FILE 2>&1
ufw default allow outgoing >> $LOG_FILE 2>&1
ufw allow 22/tcp comment 'SSH access' >> $LOG_FILE 2>&1
ufw allow 8080/tcp comment 'ERPNext web interface' >> $LOG_FILE 2>&1
ufw --force enable >> $LOG_FILE 2>&1

# Installation de Docker et ERPNext selon les instructions fournies
print_message "info" "Installation de Docker et ERPNext..."

# Installation de curl
apt install -y curl >> $LOG_FILE 2>&1

# Téléchargement du script d'installation Docker
curl -fsSL https://get.docker.com -o install-docker.sh >> $LOG_FILE 2>&1

# Exécution d'un dry-run pour vérifier
sh install-docker.sh --dry-run >> $LOG_FILE 2>&1

# Installation de Docker
sh install-docker.sh >> $LOG_FILE 2>&1

# Après l'installation de Docker, s'assurer qu'il démarre automatiquement
print_message "info" "Configuration de Docker pour démarrer automatiquement..."
systemctl enable docker >> $LOG_FILE 2>&1

# Vérification de l'installation Docker
docker ps >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
    print_message "error" "L'installation de Docker a échoué. Veuillez vérifier le fichier log: $LOG_FILE"
    exit 1
fi

# Clone du dépôt frappe_docker
print_message "info" "Clonage du dépôt frappe_docker..."
cd /opt
if [ ! -d "frappe_docker" ]; then
    git clone https://github.com/frappe/frappe_docker >> $LOG_FILE 2>&1
else
    print_message "warning" "Le répertoire frappe_docker existe déjà. Utilisation du répertoire existant."
    cd frappe_docker
    git pull >> $LOG_FILE 2>&1
fi

# Installation d'ERPNext
cd /opt/frappe_docker
docker compose -f pwd.yml up -d >> $LOG_FILE 2>&1

if [ $? -ne 0 ]; then
    print_message "error" "L'installation d'ERPNext a échoué. Veuillez vérifier le fichier log: $LOG_FILE"
    exit 1
fi

# Créer un service systemd pour démarrer ERPNext automatiquement
print_message "info" "Configuration d'ERPNext pour démarrer automatiquement..."
cat > /etc/systemd/system/erpnext.service << EOF
[Unit]
Description=ERPNext Docker Compose
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/frappe_docker
ExecStart=/usr/bin/docker compose -f pwd.yml up -d
ExecStop=/usr/bin/docker compose -f pwd.yml down

[Install]
WantedBy=multi-user.target
EOF

# Activer et démarrer le service
systemctl daemon-reload
systemctl enable erpnext.service >> $LOG_FILE 2>&1

# Affichage des informations finales
print_message "info" "Installation d'Ecomanage terminée avec succès!"
print_message "info" "Votre clé publique SSH est:"
echo "-------------------------------------------------------------------"
cat "$USER_HOME/.ssh/id_ed25519.pub"
echo "-------------------------------------------------------------------"

# Sauvegarde de la clé publique dans un fichier accessible
cp "$USER_HOME/.ssh/id_ed25519.pub" "$USER_HOME/ecomanage_ssh_key.pub"
chown $current_user:$current_user "$USER_HOME/ecomanage_ssh_key.pub"
print_message "info" "La clé publique a été sauvegardée dans: $USER_HOME/ecomanage_ssh_key.pub"

# Sauvegarde de la clé privée pour l'utilisateur
cp "$USER_HOME/.ssh/id_ed25519" "$USER_HOME/ecomanage_ssh_key"
chmod 600 "$USER_HOME/ecomanage_ssh_key"
chown $current_user:$current_user "$USER_HOME/ecomanage_ssh_key"
print_message "info" "Une copie de la clé privée a été sauvegardée dans: $USER_HOME/ecomanage_ssh_key"
print_message "warning" "IMPORTANT: Téléchargez cette clé privée et supprimez-la du serveur pour plus de sécurité."

# Instructions finales
cat << EOF

====================================================================
           INSTALLATION ECOMANAGE TERMINÉE
====================================================================

Votre système Ecomanage (basé sur ERPNext) est maintenant installé.

INFORMATIONS IMPORTANTES:

Une copie de votre clé SSH publique se trouve dans: $USER_HOME/ecomanage_ssh_key.pub
Une copie de votre clé SSH privée se trouve dans: $USER_HOME/ecomanage_ssh_key
  ⚠️ IMPORTANT: Téléchargez cette clé privée et supprimez-la du serveur pour plus de sécurité.

Pour accéder à votre système à distance via SSH:

1. Téléchargez la clé privée sur votre machine cliente
2. Définissez les permissions correctes: chmod 600 ecomanage_ssh_key
3. Connectez-vous avec: ssh -i chemin/vers/ecomanage_ssh_key $current_user@votre_serveur

Pour accéder à l'interface web d'Ecomanage: http://$(hostname -I | awk '{print $1}'):8080

Un journal d'installation est disponible dans: $LOG_FILE

Pour toute assistance supplémentaire, contactez le support technique.
EOF

echo "$(date) - Installation terminée avec succès" >> $LOG_FILE

#!/bin/bash

# Script ecomanage.sh
# Automatise l'installation d'ERPNext sur Raspberry Pi avec Debian 12
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
apt install -y curl git openssh-server ufw >> $LOG_FILE 2>&1

# Configuration de SSH
print_message "info" "Configuration du serveur SSH pour authentification par clé uniquement..."

# Sauvegarde du fichier de configuration SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configuration de SSH pour n'autoriser que l'authentification par clé
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Redémarrage du service SSH
systemctl restart sshd >> $LOG_FILE 2>&1

# Génération des clés SSH
print_message "info" "Génération des clés SSH pour les utilisateurs..."

current_user=$(logname || echo $SUDO_USER)
if [ -z "$current_user" ]; then
    current_user="$(who | awk '{print $1}' | head -n1)"
fi

if [ -z "$current_user" ] || [ "$current_user" = "root" ]; then
    print_message "warning" "Impossible de déterminer l'utilisateur non-root. Utilisation de l'utilisateur actuel."
    current_user=$(whoami)
fi

print_message "info" "Utilisation de l'utilisateur: $current_user pour les clés SSH"
USER_HOME=$(eval echo ~$current_user)

# Création du répertoire .ssh s'il n'existe pas
if [ ! -d "$USER_HOME/.ssh" ]; then
    mkdir -p "$USER_HOME/.ssh"
    chmod 700 "$USER_HOME/.ssh"
    chown $current_user:$current_user "$USER_HOME/.ssh"
fi

# Génération de la clé SSH
if [ ! -f "$USER_HOME/.ssh/id_rsa" ]; then
    su - $current_user -c "ssh-keygen -t rsa -b 2048 -f $USER_HOME/.ssh/id_rsa -N ''" >> $LOG_FILE 2>&1
    chmod 600 "$USER_HOME/.ssh/id_rsa"
    chmod 644 "$USER_HOME/.ssh/id_rsa.pub"
    print_message "info" "Clé SSH générée pour l'utilisateur $current_user"
else
    print_message "warning" "Une clé SSH existe déjà pour l'utilisateur $current_user"
fi

# Configuration de UFW
print_message "info" "Configuration du pare-feu UFW..."
ufw --force reset >> $LOG_FILE 2>&1
ufw default deny incoming >> $LOG_FILE 2>&1
ufw default allow outgoing >> $LOG_FILE 2>&1
ufw allow 22/tcp >> $LOG_FILE 2>&1
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

# Vérification de l'installation Docker
docker ps >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
    print_message "error" "L'installation de Docker a échoué. Veuillez vérifier le fichier log: $LOG_FILE"
    exit 1
fi

# Clone du dépôt frappe_docker
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

# Affichage des informations finales
print_message "info" "Installation d'Ecomanage terminée avec succès!"
print_message "info" "Votre clé publique SSH est:"
echo "-------------------------------------------------------------------"
cat "$USER_HOME/.ssh/id_rsa.pub"
echo "-------------------------------------------------------------------"

# Sauvegarde de la clé publique dans un fichier accessible
cp "$USER_HOME/.ssh/id_rsa.pub" "/home/$current_user/ecomanage_ssh_key.pub"
chown $current_user:$current_user "/home/$current_user/ecomanage_ssh_key.pub"
print_message "info" "La clé publique a été sauvegardée dans: /home/$current_user/ecomanage_ssh_key.pub"

# Instructions finales
cat << EOF

====================================================================
               INSTALLATION ECOMANAGE TERMINÉE
====================================================================

Votre système Ecomanage (basé sur ERPNext) est maintenant installé.

INFORMATIONS IMPORTANTES:
1. Une copie de votre clé SSH publique se trouve dans:
   /home/$current_user/ecomanage_ssh_key.pub

2. Pour accéder à votre système à distance via SSH:
   - Utilisez la clé privée située dans: $USER_HOME/.ssh/id_rsa
   - Ajoutez la clé publique au fichier ~/.ssh/authorized_keys sur 
     les machines clientes

3. Pour accéder à l'interface web d'Ecomanage:
   http://$(hostname -I | awk '{print $1}'):8080

4. Un journal d'installation est disponible dans:
   $LOG_FILE

Pour toute assistance supplémentaire, contactez le support technique.
====================================================================

EOF

echo "$(date) - Installation terminée avec succès" >> $LOG_FILE

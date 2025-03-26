#!/bin/bash

# Script ecomanage.sh - Version améliorée

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
apt install -y curl git openssh-server jq >> $LOG_FILE 2>&1

# Configuration de SSH
print_message "info" "Configuration du serveur SSH pour authentification par clé uniquement..."

# Sauvegarde du fichier de configuration SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configuration de SSH pour n'autoriser que l'authentification par clé
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config

# Vérification de la configuration SSH de manière sécurisée
print_message "info" "Vérification de la configuration SSH..."
if systemctl restart sshd; then
    print_message "info" "Configuration SSH validée avec succès"
else
    print_message "error" "Erreur dans la configuration SSH"
    print_message "warning" "Restauration de la configuration SSH par défaut..."
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    systemctl restart sshd
fi

# Génération des clés SSH
print_message "info" "Configuration des clés SSH pour les utilisateurs..."

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

# Création et configuration du fichier authorized_keys
if [ ! -f "$USER_HOME/.ssh/authorized_keys" ]; then
    touch "$USER_HOME/.ssh/authorized_keys"
fi

# Copie de la clé publique dans authorized_keys
cat "$USER_HOME/.ssh/id_rsa.pub" >> "$USER_HOME/.ssh/authorized_keys"

# Correction des permissions
chmod 600 "$USER_HOME/.ssh/authorized_keys"
chown $current_user:$current_user "$USER_HOME/.ssh/authorized_keys"

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
print_message "info" "Lancement des conteneurs Docker pour ERPNext..."
docker compose -f pwd.yml up -d >> $LOG_FILE 2>&1

if [ $? -ne 0 ]; then
    print_message "error" "Le lancement des conteneurs ERPNext a échoué. Veuillez vérifier le fichier log: $LOG_FILE"
    exit 1
fi

# Vérification que les conteneurs sont bien lancés
print_message "info" "Vérification des conteneurs ERPNext..."
sleep 10  # Attendre que les conteneurs démarrent
CONTAINERS_RUNNING=$(docker ps --format '{{.Names}}' | grep -c "frappe")
if [ "$CONTAINERS_RUNNING" -lt 3 ]; then
    print_message "warning" "Certains conteneurs ERPNext ne semblent pas être en cours d'exécution. Tentative de relance..."
    docker compose -f pwd.yml down >> $LOG_FILE 2>&1
    docker compose -f pwd.yml up -d >> $LOG_FILE 2>&1
    sleep 15
    CONTAINERS_RUNNING=$(docker ps --format '{{.Names}}' | grep -c "frappe")
    if [ "$CONTAINERS_RUNNING" -lt 3 ]; then
        print_message "error" "Impossible de lancer tous les conteneurs ERPNext. Veuillez vérifier le fichier log: $LOG_FILE"
        exit 1
    fi
fi

# Définition du mot de passe MySQL
print_message "info" "Configuration du mot de passe MySQL..."
MYSQL_ROOT_PASSWORD="admin"
echo "Mot de passe MySQL root défini: $MYSQL_ROOT_PASSWORD" >> $LOG_FILE

# Attendre que le conteneur backend soit prêt
print_message "info" "Attente de l'initialisation des conteneurs..."
BACKEND_CONTAINER=$(docker ps --format '{{.Names}}' | grep "backend")
if [ -z "$BACKEND_CONTAINER" ]; then
    print_message "error" "Conteneur backend non trouvé"
    exit 1
fi

# Attendre que le système de fichiers soit prêt
RETRY_COUNT=0
MAX_RETRIES=30
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if docker exec $BACKEND_CONTAINER test -d /home/frappe/frappe-bench/sites; then
        break
    fi
    print_message "info" "En attente de l'initialisation du système de fichiers... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 10
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    print_message "error" "Délai d'attente dépassé pour l'initialisation du système de fichiers"
    exit 1
fi

# Injection du mot de passe MySQL dans common_site_config.json
print_message "info" "Injection du mot de passe MySQL dans la configuration..."
CONFIG_FILE="/home/frappe/frappe-bench/sites/common_site_config.json"

# Vérifier si le fichier existe dans le conteneur
if ! docker exec $BACKEND_CONTAINER test -f $CONFIG_FILE; then
    print_message "warning" "Fichier de configuration non trouvé, création..."
    docker exec $BACKEND_CONTAINER bash -c "echo '{}' > $CONFIG_FILE"
fi

# Injecter le mot de passe MySQL
docker exec $BACKEND_CONTAINER bash -c "cat $CONFIG_FILE | jq '. + {\"db_password\": \"$MYSQL_ROOT_PASSWORD\"}' > /tmp/config.json && mv /tmp/config.json $CONFIG_FILE" >> $LOG_FILE 2>&1

if [ $? -ne 0 ]; then
    print_message "error" "Échec de l'injection du mot de passe MySQL. Veuillez vérifier le fichier log: $LOG_FILE"
    exit 1
fi

print_message "info" "Mot de passe MySQL injecté avec succès"

# Création automatique du site ERPNext
print_message "info" "Création du site ERPNext..."
SITE_NAME="site1.local"

# Exécution de la commande bench new-site
print_message "info" "Création du site $SITE_NAME..."
docker exec $BACKEND_CONTAINER bash -c "cd /home/frappe/frappe-bench && bench new-site $SITE_NAME --admin-password admin --mariadb-root-password $MYSQL_ROOT_PASSWORD --install-app erpnext" >> $LOG_FILE 2>&1

if [ $? -ne 0 ]; then
    print_message "error" "Échec de la création du site ERPNext. Veuillez vérifier le fichier log: $LOG_FILE"
    # Tentative de résolution des problèmes courants
    print_message "warning" "Tentative de résolution des problèmes..."
    
    # Vérifier si le site existe déjà
    if docker exec $BACKEND_CONTAINER bash -c "cd /home/frappe/frappe-bench && bench --site $SITE_NAME list-apps" >> $LOG_FILE 2>&1; then
        print_message "warning" "Le site semble déjà exister. Tentative d'installation de l'application erpnext..."
        docker exec $BACKEND_CONTAINER bash -c "cd /home/frappe/frappe-bench && bench --site $SITE_NAME install-app erpnext" >> $LOG_FILE 2>&1
    else
        print_message "error" "Impossible de créer ou de configurer le site ERPNext"
        exit 1
    fi
fi

# Configuration du site par défaut
print_message "info" "Configuration du site par défaut..."
docker exec $BACKEND_CONTAINER bash -c "echo \"$SITE_NAME\" > /home/frappe/frappe-bench/sites/currentsite.txt" >> $LOG_FILE 2>&1

if [ $? -ne 0 ]; then
    print_message "error" "Échec de la configuration du site par défaut. Veuillez vérifier le fichier log: $LOG_FILE"
    exit 1
fi

# Redémarrage des services Docker
print_message "info" "Redémarrage des services Docker..."
cd /opt/frappe_docker
docker compose -f pwd.yml restart >> $LOG_FILE 2>&1

if [ $? -ne 0 ]; then
    print_message "error" "Échec du redémarrage des services Docker. Veuillez vérifier le fichier log: $LOG_FILE"
    exit 1
fi

# Sauvegarde de la clé publique dans un fichier accessible
cp "$USER_HOME/.ssh/id_rsa.pub" "/home/$current_user/ecomanage_ssh_key.pub"
chown $current_user:$current_user "/home/$current_user/ecomanage_ssh_key.pub"

# Sauvegarde de la clé privée dans un fichier accessible
cp "$USER_HOME/.ssh/id_rsa" "/home/$current_user/ecomanage_ssh_key"
chmod 600 "/home/$current_user/ecomanage_ssh_key"
chown $current_user:$current_user "/home/$current_user/ecomanage_ssh_key"

# Création d'un script pour faciliter l'ajout de clés SSH externes
cat > "/home/$current_user/add_ssh_key.sh" << 'EOF'
#!/bin/bash
# Script pour ajouter une clé SSH externe au fichier authorized_keys

if [ -z "$1" ]; then
    echo "Usage: $0 \"votre_cle_ssh_publique\""
    echo "Exemple: $0 \"ssh-rsa AAAAB3NzaC1yc2E... user@example.com\""
    exit 1
fi

SSH_DIR="$HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

# Vérification du répertoire .ssh
if [ ! -d "$SSH_DIR" ]; then
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
fi

# Vérification du fichier authorized_keys
if [ ! -f "$AUTH_KEYS" ]; then
    touch "$AUTH_KEYS"
fi

# Ajout de la clé
echo "$1" >> "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

echo "Clé SSH ajoutée avec succès!"
echo "Vérification des permissions..."
ls -la "$SSH_DIR"
echo "Contenu du fichier authorized_keys:"
cat "$AUTH_KEYS"
EOF

chmod +x "/home/$current_user/add_ssh_key.sh"
chown $current_user:$current_user "/home/$current_user/add_ssh_key.sh"

# Attendre que le site soit complètement prêt
print_message "info" "Attente de la finalisation du site ERPNext..."
sleep 20

# Vérification finale
SERVER_IP=$(hostname -I | awk '{print $1}')
print_message "info" "Vérification de l'accès au site ERPNext..."
curl -s -o /dev/null -w "%{http_code}" http://$SERVER_IP:8080 > /tmp/http_status
HTTP_STATUS=$(cat /tmp/http_status)

if [[ "$HTTP_STATUS" == "200" || "$HTTP_STATUS" == "302" || "$HTTP_STATUS" == "301" ]]; then
    print_message "info" "Site ERPNext accessible avec succès!"
else
    print_message "warning" "Le site ERPNext n'est pas encore accessible (HTTP status: $HTTP_STATUS). Il pourrait nécessiter plus de temps pour s'initialiser."
fi

# Affichage des informations finales
print_message "info" "Installation d'Ecomanage terminée avec succès!"
print_message "info" "Votre clé publique SSH est:"
echo "-------------------------------------------------------------------"
cat "$USER_HOME/.ssh/id_rsa.pub"
echo "-------------------------------------------------------------------"
print_message "info" "La clé publique a été sauvegardée dans: /home/$current_user/ecomanage_ssh_key.pub"
print_message "info" "La clé privée a été sauvegardée dans: /home/$current_user/ecomanage_ssh_key"

# Instructions finales
cat << EOF

====================================================================
               INSTALLATION ECOMANAGE TERMINÉE
====================================================================

Votre système Ecomanage (basé sur ERPNext) est maintenant installé.

INFORMATIONS IMPORTANTES:
1. Une copie de votre clé SSH publique se trouve dans:
   /home/$current_user/ecomanage_ssh_key.pub

2. Une copie de votre clé SSH privée se trouve dans:
   /home/$current_user/ecomanage_ssh_key
   
3. Pour ajouter une clé SSH externe, utilisez le script:
   /home/$current_user/add_ssh_key.sh "votre_cle_ssh_publique"

4. Pour accéder à votre système à distance via SSH:
   - Utilisez la clé privée située dans: $USER_HOME/.ssh/id_rsa
   - Commande: ssh -i chemin/vers/cle_privee $current_user@$SERVER_IP

5. Pour accéder à l'interface web d'Ecomanage:
   http://$SERVER_IP:8080
   
   Identifiants par défaut:
   - Utilisateur: Administrator
   - Mot de passe: admin

6. Un journal d'installation est disponible dans:
   $LOG_FILE

Pour toute assistance supplémentaire, contactez le support technique.
====================================================================

EOF

echo "$(date) - Installation terminée avec succès" >> $LOG_FILE

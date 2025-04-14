#!/bin/bash

# Script: enix-core.sh
# Description: Automatisation de l'installation d'ERPNext via Docker avec configuration SSH sécurisée et Cockpit
# Version: 1.2
# Date: 14 April 2025

# Configuration
LOG_FILE="/var/log/enix-core-install.log"
SSH_KEY_DIR="/etc/ssh/enix_keys"
SSH_PRIVATE_KEY="${SSH_KEY_DIR}/enix_key"
SSH_PUBLIC_KEY="${SSH_KEY_DIR}/enix_key.pub"
REPO_URL="https://github.com/frappe/frappe_docker.git"
COMPOSE_FILE="pwd.yml"
COCKPIT_PORT="9090"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Initialize logging
init_logging() {
    touch "$LOG_FILE" || {
        echo -e "${RED}Erreur: Impossible de créer le fichier de log $LOG_FILE${NC}"
        exit 1
    }
    echo "===== Début de l'installation - $(date) =====" >> "$LOG_FILE"
}

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo -e "$1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "${RED}Erreur: Ce script doit être exécuté en tant que root${NC}"
        exit 1
    fi
    log "${GREEN}Vérification root: OK${NC}"
}

# Check if a port is in use
check_port() {
    local port="$1"
    if ss -tuln | grep -q ":$port"; then
        log "${RED}Erreur: Le port $port est déjà utilisé${NC}"
        exit 1
    fi
}

# Install required packages
install_packages() {
    log "${YELLOW}Mise à jour des paquets et installation des dépendances...${NC}"
    apt-get update >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de la mise à jour des paquets${NC}"
        exit 1
    }
    apt-get install -y curl git openssh-server >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de l'installation des paquets${NC}"
        exit 1
    }
    systemctl enable ssh >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de l'activation de SSH${NC}"
        exit 1
    }
    systemctl start ssh >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec du démarrage de SSH${NC}"
        exit 1
    }
    log "${GREEN}Paquets installés: curl, git, openssh-server${NC}"
}

# Install Docker using provided commands
install_docker() {
    log "${YELLOW}Installation de Docker via le script officiel...${NC}"
    curl -fsSL https://get.docker.com/ -o install-docker.sh >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec du téléchargement du script Docker${NC}"
        exit 1
    }
    sh install-docker.sh --dry-run >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec du test du script Docker${NC}"
        exit 1
    }
    sh install-docker.sh >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de l'installation de Docker${NC}"
        exit 1
    }
    rm install-docker.sh
    systemctl enable docker >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de l'activation du service Docker${NC}"
        exit 1
    }
    systemctl start docker >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec du démarrage du service Docker${NC}"
        exit 1
    }
    log "${GREEN}Docker installé et démarré avec succès${NC}"
}

# Install Cockpit
install_cockpit() {
    log "${YELLOW}Installation de Cockpit...${NC}"
    check_port "$COCKPIT_PORT"
    apt-get install -y cockpit >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de l'installation de Cockpit${NC}"
        exit 1
    }
    systemctl enable cockpit.socket >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de l'activation de Cockpit${NC}"
        exit 1
    }
    systemctl start cockpit.socket >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec du démarrage de Cockpit${NC}"
        exit 1
    }
    log "${GREEN}Cockpit installé et démarré sur le port $COCKPIT_PORT${NC}"
}

# Clone ERPNext Docker repository
clone_repo() {
    log "${YELLOW}Clonage du dépôt ERPNext Docker...${NC}"
    git clone "$REPO_URL" >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec du clonage du dépôt${NC}"
        exit 1
    }
    log "${GREEN}Dépôt ERPNext cloné avec succès${NC}"
}

# Start ERPNext Docker services
start_erpnext() {
    log "${YELLOW}Démarrage des services ERPNext...${NC}"
    cd frappe_docker || {
        log "${RED}Erreur: Dossier frappe_docker introuvable${NC}"
        exit 1
    }
    docker compose -f "$COMPOSE_FILE" up -d >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec du démarrage des services ERPNext${NC}"
        exit 1
    }
    log "${GREEN}Services ERPNext démarrés avec succès${NC}"
}

# Generate SSH keys
generate_ssh_keys() {
    log "${YELLOW}Génération des clés SSH Ed25519...${NC}"
    mkdir -p "$SSH_KEY_DIR" || {
        log "${RED}Erreur: Impossible de créer le dossier $SSH_KEY_DIR${NC}"
        exit 1
    }
    chmod 700 "$SSH_KEY_DIR"
    ssh-keygen -t ed25519 -f "$SSH_PRIVATE_KEY" -N "" >> "$LOG_FILE" 2>&1 || {
        log "${RED}Erreur: Échec de la génération des clés SSH${NC}"
        exit 1
    }
    chmod 600 "$SSH_PRIVATE_KEY"
    chmod 644 "$SSH_PUBLIC_KEY"
    log "${GREEN}Clés SSH générées avec succès${NC}"

    # Optional: Add public key to authorized_keys
    read -p "Voulez-vous ajouter la clé publique à ~/.ssh/authorized_keys ? (y/n): " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        cat "$SSH_PUBLIC_KEY" >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        log "${GREEN}Clé publique ajoutée à ~/.ssh/authorized_keys${NC}"
    fi
}

# Display final summary
display_summary() {
    SERVER_IP=$(curl -s ifconfig.me)
    cat << EOF
====================================================================
               INSTALLATION ECOMANAGE TERMINÉE
====================================================================

Votre système Ecomanage (basé sur ERPNext) est maintenant installé.

INFORMATIONS IMPORTANTES:
1. Une copie de votre clé SSH publique se trouve dans:
$SSH_PUBLIC_KEY

2. Une copie de votre clé SSH privée se trouve dans:
$SSH_PRIVATE_KEY

3. Pour accéder à votre système à distance via SSH:
- Utilisez la clé privée située dans: $SSH_PRIVATE_KEY
- Commande: ssh -i $SSH_PRIVATE_KEY root@$SERVER_IP

4. Pour accéder à l’interface web d’Ecomanage:
http://$SERVER_IP:8080

   Identifiants par défaut:
   - Utilisateur: Administrator
   - Mot de passe: admin

5. Pour accéder à l’interface de monitoring système Cockpit:
https://$SERVER_IP:9090
   Connectez-vous avec vos identifiants Linux habituels.

6. Un journal d’installation est disponible dans:
$LOG_FILE

7. TOUS LES MODULES NÉCESSAIRES ONT ÉTÉ ACTIVÉS POUR LA CONFIGURATION AUTOMATIQUE

Pour toute assistance supplémentaire, contactez le support technique.
====================================================================
EOF
    echo "$(date) - Installation terminée avec succès" >> "$LOG_FILE"
}

# Main function
main() {
    init_logging
    check_root
    install_packages
    install_docker
    install_cockpit
    clone_repo
    start_erpnext
    generate_ssh_keys
    display_summary
}

# Trap errors
trap 'log "${RED}Erreur inattendue détectée, arrêt du script${NC}"; exit 1' ERR

# Execute main
main

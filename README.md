# Ecomanage
---
Le script **ecomanage.sh** prépare l’environnement nécessaire.

Il effectue les actions suivantes :

- **📦 Installation d'un ERP.**
- **🔒 Configuration de SSH pour l'authentification par clé.**
- **🔑 Génération d’une clé SSH pour un accès sécurisé.**

---

## 🎯 Fonctionnalités principales

- **📦 Installation automatique d'un ERP.**
- **🔐 Sécurisation du serveur SSH avec clé  Ed25519.**
- **🔑 Génération et sauvegarde de la clé SSH pour un accès distant sécurisé.**

---

## 🚀 Installation et utilisation

### 1️⃣ Cloner le dépôt
```bash
git clone https://github.com/CodeD-Roger/ecomanage.git
cd ecomanage
sudo chmod +x ecomanage.sh
sudo ./ecomanage.sh
```

## 🚀 Configuration du DNS local, HTTPS, pare-feu, Webmin 

### 1️⃣ Cloner le dépôt
```bash
sudo chmod +x network-setup.sh
sudo ./network-setup.sh
```

## 🚀 Installe et configure un serveur VPN WireGuard

### 1️⃣ Cloner le dépôt
```bash
sudo chmod +x vpn.sh
sudo ./vpn.sh

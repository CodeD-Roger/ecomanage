# Ecomanage
---
Le script **ecomanage.sh** prépare l’environnement nécessaire.

Il effectue les actions suivantes :

- **📦 Installation d'ERPNext via Docker.**
- **🔒 Configuration de SSH pour l'authentification par clé.**
- **🛡 Sécurisation du serveur avec UFW et ouverture du port 22.**
- **🔑 Génération d’une clé SSH pour un accès sécurisé.**

---

## 🎯 Fonctionnalités principales

- **📦 Installation automatique d'ERPNext (via Docker).**
- **🔐 Sécurisation du serveur SSH avec clé RSA.**
- **🛡 Configuration d'un pare-feu (UFW) pour sécuriser l'accès SSH.**
- **🔑 Génération et sauvegarde de la clé SSH pour un accès distant sécurisé.**

---

## 🚀 Installation et utilisation

### 1️⃣ Cloner le dépôt
```bash
git clone https://github.com/CodeD-Roger/ecomanage.git
cd ecomanage
sudo ./ecomanage.sh


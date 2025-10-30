# 🚀 AlternateDataStreamScanner - Scanner de Flux de Données Alternatifs NTFS

![C++](https://img.shields.io/badge/language-C++-blue?style=flat-square) ![License](https://img.shields.io/badge/license-MIT-green?style=flat-square) ![Maintained](https://img.shields.io/badge/Maintained%3F-yes-brightgreen?style=flat-square) ![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)

## 📑 Table des Matières

- [📋 Description](#-description)
- [Qu'est-ce qu'un ADS ?](#quest-ce-quun-ads-)
- [✨ Fonctionnalités principales](#-fonctionnalités-principales)
- [Interface utilisateur](#interface-utilisateur)
- [Compilation](#compilation)
- [🚀 Utilisation](#-utilisation)
- [🚀 Exemples d'utilisation forensique](#-exemples-dutilisation-forensique)
- [Architecture technique](#architecture-technique)
- [Techniques d'attaque utilisant les ADS](#techniques-dattaque-utilisant-les-ads)
- [🚀 Cas d'usage forensiques](#-cas-dusage-forensiques)
- [Limitations connues](#limitations-connues)
- [Améliorations futures](#améliorations-futures)
- [Outils complémentaires](#outils-complémentaires)
- [Références techniques](#références-techniques)
- [🔧 Dépannage](#-dépannage)
- [🔒 Sécurité et éthique](#-sécurité-et-éthique)
- [📄 Licence MIT](#-licence-mit)
- [Support](#support)




**Auteur** : Ayi NEDJIMI
**Licence** : MIT
**Plateforme** : Windows (Win32 GUI)

## 📋 Description

AlternateDataStreamScanner est un outil forensique spécialisé dans la détection et l'analyse des **ADS (Alternate Data Streams)** - des flux de données alternatifs cachés dans le système de fichiers NTFS. Ces flux peuvent être utilisés par des malwares pour dissimuler du code malveillant, stocker des configurations ou exfiltrer des données sans être visibles dans l'Explorateur Windows standard.


# 🚀 Créer un fichier normal

# 🚀 Créer un ADS caché

# 🚀 Créer un ADS exécutable (suspect)

# 🚀 Lister les ADS (méthode PowerShell)

## Qu'est-ce qu'un ADS ?

Les Alternate Data Streams sont une fonctionnalité NTFS qui permet de stocker plusieurs flux de données dans un seul fichier. Par exemple :

```
fichier.txt              <- Flux principal (visible)
fichier.txt:hidden.exe   <- ADS caché (invisible)
fichier.txt:config.ini   <- ADS caché (invisible)
```

Ces flux sont totalement invisibles pour l'utilisateur normal et ne sont pas comptabilisés dans la taille du fichier affichée par Windows.


## ✨ Fonctionnalités principales

### Énumération ADS
- **Scan récursif** : Parcours de dossiers complets et sous-dossiers
- **API native** : Utilisation de FindFirstStreamW/FindNextStreamW
- **Détection exhaustive** : Trouve tous les streams alternatifs
- **Support de fichiers individuels** : Scan d'un fichier unique possible

### Détection de malware
- **Header MZ** : Détection d'exécutables cachés dans les ADS
- **Analyse de taille** : Signalement des ADS > 10 KB
- **Patterns suspects** : Détection d'extensions exécutables (.exe, .dll, .ps1, etc.)
- **Score de suspicion** : Classification automatique

### Extraction et analyse
- **Export de streams** : Extraction du contenu des ADS vers des fichiers
- **Calcul de hash** : SHA-256 pour identification (à implémenter complètement)
- **Lecture de contenu** : Accès direct au contenu via CreateFile
- **Suppression sécurisée** : Suppression d'ADS avec confirmation

### Reporting
- **Export CSV** : Export complet des résultats au format UTF-8
- **Statistiques** : Compteurs d'ADS trouvés et suspects
- **Logging détaillé** : Journal des opérations


## Interface utilisateur

### Contrôles principaux
1. **Zone de chemin** : Spécification du dossier ou fichier à scanner
2. **Bouton "Parcourir"** : Sélection visuelle du dossier
3. **Bouton "Scanner"** : Lance/arrête le scan
4. **Barre de progression** : Indicateur visuel du scan
5. **ListView** : Résultats avec colonnes :
   - Chemin Fichier (chemin complet du fichier hôte)
   - Nom Stream (nom du flux alternatif)
   - Taille (taille du stream)
   - Hash (SHA-256, à implémenter)
   - Suspect (OUI/Non)
   - Notes (raisons de suspicion)
6. **Bouton "Extraire Stream"** : Exporte l'ADS sélectionné
7. **Bouton "Supprimer ADS"** : Supprime l'ADS avec confirmation
8. **Bouton "Exporter Résultats"** : Sauvegarde en CSV
9. **Journal de log** : Messages et erreurs


## Compilation

### Prérequis
- Visual Studio 2019/2022 avec outils C++
- Windows SDK (10.0 ou supérieur)
- Support Unicode

### Compilation automatique
```batch
go.bat
```

### Compilation manuelle
```batch
cl.exe /nologo /W4 /EHsc /O2 /D_UNICODE /DUNICODE /FeAlternateDataStreamScanner.exe AlternateDataStreamScanner.cpp ^
    kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib shlwapi.lib shell32.lib ole32.lib
```


## 🚀 Utilisation

### Scan basique
1. Lancez l'application
2. Cliquez sur "Parcourir" pour sélectionner un dossier
3. Cliquez sur "Scanner"
4. Consultez les résultats dans la liste
5. Examinez les entrées marquées comme "Suspect"

### Extraction d'un ADS suspect
1. Sélectionnez l'entrée dans la liste
2. Cliquez sur "Extraire Stream"
3. Choisissez l'emplacement et le nom du fichier
4. Analysez le fichier extrait avec un antivirus

### Suppression d'un ADS
1. Sélectionnez l'entrée à supprimer
2. Cliquez sur "Supprimer ADS"
3. Confirmez la suppression (irréversible)

### Export des résultats
1. Cliquez sur "Exporter Résultats"
2. Choisissez l'emplacement du fichier CSV
3. Ouvrez avec Excel ou LibreOffice pour analyse


## 🚀 Exemples d'utilisation forensique

### Création d'un ADS pour test (PowerShell)
```powershell
echo "Fichier visible" > test.txt

echo "Données cachées" > test.txt:hidden.txt

copy C:\Windows\notepad.exe test.txt:malware.exe

Get-Item test.txt -Stream *
```

### Workflow d'investigation
```
1. Incident de sécurité détecté
2. Scanner le dossier Downloads de l'utilisateur
3. Scanner le dossier Temp
4. Scanner C:\Windows\System32 (si compromission système)
5. Identifier les ADS suspects (header MZ, taille importante)
6. Extraire les ADS suspects
7. Analyser avec antivirus ou sandbox
8. Documenter dans le rapport forensique
9. Supprimer les ADS malveillants
```

### Exemple de rapport
```csv
CheminFichier,NomStream,Taille,Hash,Suspect,Notes
"C:\Users\John\Downloads\invoice.pdf","::$DATA",245760,N/A,Non,""
"C:\Users\John\Downloads\invoice.pdf",":hidden.exe:$DATA",73728,N/A,OUI,"Contient un header MZ (exécutable)"
"C:\Temp\readme.txt",":config.ini:$DATA",156,N/A,Non,""
```


## Architecture technique

### APIs Windows utilisées
- **FindFirstStreamW** : Début de l'énumération des streams
- **FindNextStreamW** : Énumération suivante
- **CreateFile** : Ouverture des streams avec syntaxe `file.txt:stream:$DATA`
- **ReadFile** : Lecture du contenu des streams
- **DeleteFile** : Suppression de streams
- **CopyFile** : Extraction de streams

### Format des noms de streams
```
fichier.txt:stream_name:$DATA
│           │           └─ Type de stream (toujours $DATA)
│           └─ Nom du stream alternatif
└─ Fichier hôte
```

### Structure WIN32_FIND_STREAM_DATA
```cpp
typedef struct _WIN32_FIND_STREAM_DATA {
    LARGE_INTEGER StreamSize;      // Taille du stream
    WCHAR cStreamName[MAX_PATH + 36]; // Nom du stream
} WIN32_FIND_STREAM_DATA;
```

### Détection de malware

#### Vérification du header MZ
```cpp
bool CheckMZHeader(const std::wstring& fullPath) {
    // Ouvre le stream
    HANDLE hFile = CreateFile(fullPath.c_str(), ...);

    // Lit les 2 premiers octets
    BYTE buffer[2];
    ReadFile(hFile, buffer, 2, ...);

    // Vérifie la signature PE (MZ = 0x4D 0x5A)
    return (buffer[0] == 'M' && buffer[1] == 'Z');
}
```

#### Critères de suspicion
1. **Header MZ détecté** : Exécutable caché
2. **Taille > 10 KB** : Contenu volumineux inhabituel
3. **Extensions suspectes** : .exe, .dll, .scr, .bat, .cmd, .ps1 dans le nom
4. **Combinaison de critères** : Score de risque élevé

### Gestion mémoire
- **RAII** : HandleGuard pour gestion automatique des handles
- **Vecteurs STL** : Stockage dynamique des résultats
- **Smart pointers** : std::unique_ptr pour les buffers

### Threading
- **Thread de scan** : Scan en arrière-plan pour UI responsive
- **Flag d'arrêt** : g_scanning pour interruption propre
- **Mise à jour UI** : UpdateListView après scan complet


## Techniques d'attaque utilisant les ADS

### 1. Dissimulation de malware
```batch
REM Attaquant cache un payload dans un ADS
type malware.exe > document.docx:payload.exe

REM Exécution depuis l'ADS
wmic process call create "C:\path\document.docx:payload.exe"
```

### 2. Exfiltration de données
```batch
REM Vol de données cachées dans un fichier légitime
type passwords.txt > image.jpg:stolen.txt
```

### 3. Persistence
```batch
REM Configuration de backdoor cachée
echo "C:\backdoor.exe" > system.dll:autorun:$DATA
```

### 4. Zone.Identifier
Windows utilise l'ADS `:Zone.Identifier` pour marquer les fichiers téléchargés :
```
[ZoneTransfer]
ZoneId=3
```


## 🚀 Cas d'usage forensiques

### 1. Investigation de malware
- Recherche d'exécutables cachés dans des documents
- Détection de droppers utilisant les ADS
- Identification de RATs (Remote Access Trojans)

### 2. Analyse post-incident
- Découverte de fichiers de configuration malveillants
- Identification de scripts PowerShell cachés
- Détection de fichiers de données exfiltrées

### 3. Audit de sécurité
- Scan préventif des dossiers critiques
- Vérification de l'intégrité du système
- Détection d'activités anormales

### 4. Conformité
- Vérification de l'absence de données cachées
- Audit avant transfert de fichiers
- Contrôle des supports amovibles


## Limitations connues

### Limitations NTFS
- **Systèmes de fichiers** : Fonctionne uniquement sur NTFS (pas FAT32, exFAT)
- **Compatibilité** : Certains outils ne préservent pas les ADS lors de copies
- **Visibilité** : Les ADS ne sont pas visibles dans l'Explorateur standard

### Limitations de l'outil
- **Hash SHA-256** : Non complètement implémenté (retourne "N/A")
- **Performance** : Peut être lent sur de très gros volumes
- **Limite de scan** : Pas de limite de temps ou de nombre de fichiers
- **Analyse de contenu** : Pas d'analyse heuristique avancée


## Améliorations futures

### Court terme
- **Implémentation complète du hashing** : SHA-256 avec CryptoAPI
- **Filtres avancés** : Par taille, date, type
- **Recherche en temps réel** : Dans les résultats affichés
- **Statistiques détaillées** : Graphiques et diagrammes

### Moyen terme
- **Analyse heuristique** : Détection de patterns malveillants
- **Base de signatures** : Hash connus de malware
- **Intégration VirusTotal** : Scan en ligne des ADS suspects
- **Mode batch** : Ligne de commande pour scripts

### Long terme
- **Analyse de contenu approfondie** : Strings, désassemblage
- **Corrélation avec d'autres artefacts** : Timeline globale
- **Machine learning** : Détection automatique de malware
- **Interface web** : Dashboard centralisé


## Outils complémentaires

### Outils système
```batch
REM Lister les ADS avec dir (affiche taille uniquement)
dir /R C:\path\to\file.txt

REM Lister avec PowerShell
Get-Item file.txt -Stream *

REM Supprimer un ADS avec PowerShell
Remove-Item file.txt -Stream hidden.exe

REM Lire un ADS
more < file.txt:stream.txt
```

### Outils forensiques
- **Streams.exe (Sysinternals)** : Utilitaire en ligne de commande
- **FTK Imager** : Support des ADS dans les images forensiques
- **X-Ways Forensics** : Analyse complète incluant ADS
- **Autopsy** : Module d'analyse des ADS


## Références techniques

### Documentation Microsoft
- [File Streams](https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [FindFirstStreamW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw)
- [Alternate Data Streams](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8)

### Articles de sécurité
- SANS DFIR : "Hunting Alternate Data Streams"
- Malwarebytes Labs : "ADS and Malware Hiding"
- Bleeping Computer : "NTFS ADS Forensics"

### Conférences
- Black Hat : "Advanced NTFS Forensics"
- DEF CON : "Hiding in Plain Sight with ADS"


## 🔧 Dépannage

### Aucun ADS trouvé
**Cause** : Dossier sans ADS ou système de fichiers non-NTFS
**Solution** : Testez sur un volume NTFS ou créez des ADS de test

### Erreur d'accès lors de l'extraction
**Cause** : Permissions insuffisantes
**Solution** : Exécutez en tant qu'administrateur

### Scan très lent
**Cause** : Nombreux fichiers ou disque lent
**Solution** : Utilisez le bouton "Arrêter" ou scannez un sous-dossier

### Faux positifs
**Cause** : Windows utilise légitimement certains ADS
**Solution** : Ignorez les `:Zone.Identifier` et `:$DATA` principaux


## 🔒 Sécurité et éthique

### Usage légal uniquement
- Utilisez uniquement sur des systèmes dont vous avez l'autorisation
- Respectez les lois sur la vie privée et la protection des données
- Documentez toute investigation forensique
- Ne distribuez pas de malware découvert

### Protection des preuves
- Ne modifiez pas les timestamps lors de l'extraction
- Calculez les hashs avant toute manipulation
- Conservez les logs d'investigation
- Utilisez des supports en écriture seule quand possible


## 📄 Licence MIT

```
Copyright (c) 2025 Ayi NEDJIMI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[Texte complet de la licence MIT]
```


## Support

### Ressources
- Documentation complète (ce README)
- Code source commenté
- Exemples d'utilisation

### Contact
**Auteur** : Ayi NEDJIMI
**Projet** : WinToolsSuite

- --

**AlternateDataStreamScanner** - Outil forensique pour la détection et l'analyse des flux de données alternatifs NTFS
Développé par **Ayi NEDJIMI** - 2025


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>
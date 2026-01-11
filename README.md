# Syscall Logger

## Objectif

Ce projet implémente un enregistreur d'appels système (syscalls) utilisant **eBPF** (*extended Berkeley Packet Filter*) pour tracer et enregistrer les appels système effectués sur un système Linux. Il offre une solution efficace et à faible surcharge pour surveiller l'activité du système, ce qui est idéal pour l'audit de sécurité, l'analyse de performance et le débogage.

## Technologies Utilisées

* **eBPF (extended Berkeley Packet Filter) :** Pour le traçage de bas niveau des appels système directement au sein du noyau (kernel).
* **Go :** Pour l'application en espace utilisateur (user-space) qui charge, gère et interagit avec les programmes eBPF.
* **bpf2go :** Un outil qui compile et intègre le code C eBPF dans des programmes Go, simplifiant ainsi le chargement et l'interaction.
* **bpftool :** Un outil puissant pour inspecter et manipuler les programmes et les "maps" eBPF.

---

## Installation

Pour compiler et exécuter ce projet, vous devez configurer votre environnement avec les outils eBPF nécessaires et les dépendances Go.

### Prérequis

* **Go** (version 1.18 ou plus récente recommandée)
* **Clang** (pour compiler les programmes eBPF)
* **Kernel headers** (en-têtes) correspondant à votre noyau Linux actuel

### Étapes

1.  **Installer `bpftool`**

    `bpftool` est essentiel pour interagir avec les programmes eBPF et générer le fichier `vmlinux.h`. L'installation varie selon votre distribution :

    * **Ubuntu/Debian :**
        ```bash
        sudo apt update
        sudo apt install linux-tools-$(uname -r) linux-headers-$(uname -r) bpftool
        ```
    * **Fedora :**
        ```bash
        sudo dnf install bpftool kernel-devel
        ```
    * **Arch Linux :**
        ```bash
        sudo pacman -S bpftool linux-headers
        ```

2.  **Installer `bpf2go`**

    `bpf2go` est un outil Go qui facilite l'intégration des programmes eBPF. Installez-le avec la commande suivante :

    ```bash
    go get -tool [github.com/cilium/ebpf/cmd/bpf2go@latest](https://github.com/cilium/ebpf/cmd/bpf2go@latest)
    ```

3.  **Générer `vmlinux.h`**

    Le fichier `vmlinux.h` contient les définitions de types du noyau nécessaires à la compilation. Générez-le via `bpftool` :

    ```bash
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    # Déplacez vmlinux.h vers le répertoire de votre code eBPF
    mv vmlinux.h internal/ebpf/
    ```

    > **Note :** Assurez-vous que votre noyau possède le BTF (*BPF Type Format*) activé. C'est le cas par défaut sur la plupart des distributions modernes.

4.  **Compiler le projet**

    Une fois les dépendances installées, utilisez le `Makefile` pour générer le code eBPF et compiler l'application Go :

    ```bash
    make build
    ```

5.  **Exécuter l'application**

    ```bash
    sudo make run
    ```

    > **Note :** L'exécution de programmes eBPF nécessite les privilèges **root** (sudo) pour interagir avec les fonctionnalités du noyau.

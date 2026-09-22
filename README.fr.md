# Krymux

Accès sécurisé aux services via des tunnels inversés.

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [Deutsch](README.de.md) | **Français** | [Español](README.es.md)
> Le SDK est multilingue dans un même dépôt : implémentation de référence Rust (crates/krymux) + TypeScript / Go / Python (sdks/) — tous compatibles sur le câble et couverts par des tests d'interop contre les binaires Rust.
> Tests et CI : trois jobs parallèles par commit — couverture (seil Rust 55 %, Go/Python/TS agrégés), intégration Linux (matrice de bord paramétrée 54 combinaisons + interop par langue + matrice inter-langages), E2E complète Windows. Détails dans la section Testing & CI de la version anglaise.

`krymux` expose des services locaux sur Internet à travers un relais TCP en clair tel que frp — des relais qui n'offrent ni chiffrement de bout en bout ni contrôle d'accès par client. Il exécute un reverse proxy sur la machine de service et établit vers le client un **tunnel chiffré TLS 1.3 à authentification mutuelle** (frp ne voit jamais rien d'autre que du texte chiffré). À l'intérieur du tunnel circule un **ensemble multiplexé de streams logiques** avec **compression par stream**, **contrôle de flux à crédits**, **half-close** et **keepalive**. Le modèle de confiance est calqué sur celui de WireGuard/SSH : le serveur détient une liste blanche d'**empreintes de clés publiques Ed25519** des clients (`sha256(SPKI)`), et le client **épingle l'empreinte du serveur** pour se prémunir des attaques de l'homme du milieu.

Ce dépôt est l'**implémentation Rust** : un unique binaire statique d'environ 5,3 Mo contenant toutes les applications (synchronisation de fichiers, accès navigateur WebSocket, frontaux SOCKS5/HTTP). Elle est **compatible au niveau du protocole filaire avec l'implémentation de référence Node** ([`../ectun`](../ectun)) — même système d'identité par empreintes Ed25519, même schéma de configuration JSON, les deux extrémités librement interchangeables et cross-benchmarkées.

```
User program ── local SOCKS5/HTTP proxy or SDK ──> krymux client
     ═══ TLS 1.3 (mutual Ed25519 auth) + multiplexing + compression ═══   ← frp sees only ciphertext
              via frps (public) → frpc relay → machine-local preset port
                                          └──> krymux server (reverse proxy)
                                               ├─ host a.test  → 127.0.0.1:3000
                                               ├─ host *.test  → 127.0.0.1:8080
                                               └─ any port / Unix socket / client-chosen target (optional)

Browser (no client process needed)
     ═══ wss:// → TLS → WebSocket → P-256 signature auth + CMPX multiplexing ═══
              same port (HTTP GET detection branch), likewise relayed through frp
                                          └──> same krymux server
```

## Fonctionnalités

- **Chiffrement de bout en bout** — TLS 1.3 uniquement (ALPN `krymux`), certificats Ed25519, AES-GCM/ChaCha20-Poly1305 ; le lien frp ne transporte rien d'autre que du texte chiffré.
- **Liste blanche à clés publiques** — l'empreinte `sha256(SPKI)` *est* l'identité ; admission fail-closed après la poignée de main. Le client épingle l'empreinte du serveur.
- **Multiplexage** — des centaines de streams logiques full-duplex sur une seule connexion TLS (un navigateur ouvrant 50 connexions = 1 poignée de main).
- **Compression par stream** — `deflate` / `brotli` / `zstd` avec contextes continus et flush en streaming ; `none` en pass-through ; négociation `auto`. Préréglages de niveau comme `"zstd:9"`, `"brotli:11"`, `"deflate:9"`.
- **Contournement par octets magiques** — le reniflage du premier bloc détecte le contenu déjà compressé (gzip/zstd/zip/png/jpeg/7z/rar/pdf/bzip2/mp4) et bascule automatiquement ce stream sur `none` (économise du CPU, évite l'expansion).
- **Contrôle de flux à crédits** — fenêtres par stream comptabilisées sur les octets *décompressés* ; les consommateurs lents ne peuvent ni épuiser la mémoire ni affamer les autres streams. L'auto-croissance dynamique de fenêtre double le crédit toutes les 100 ms tant qu'un stream se vide : 4 → 32,4 Mo/s sur un seul stream à 50 ms de RTT (de l'ancienne fenêtre fixe de 256 Ko jusqu'au plafond de 4 Mo).
- **Transparence protocolaire** — sémantique de flux d'octets TCP avec half-close préservé ; HTTP/WebSocket/SSH/protocoles de bases de données passent à l'identique.
- **Routage vhost** — le client désigne un nom d'hôte ; le serveur route selon host / port / fallback / cible choisie par le client vers différents upstreams.
- **Accès navigateur (WebSocket)** — `wss://` avec authentification par signature P-256 en couche application partageant la même liste blanche d'empreintes ; page de lancement intégrée ; SDK navigateur sans aucune dépendance.
- **Synchronisation de fichiers bidirectionnelle** — diff par hachage SHA-1, alignement du décalage d'horloge mtime, écritures atomiques, détection de verrous, daemon watch avec hints de changement poussés par le serveur.
- **Build post-quantique** — `--features pq` (backend aws-lc-rs) négocie le KEM hybride X25519MLKEM768.
- **Binaire unique, aucune dépendance d'exécution** — chaîne de dépendances purement Rust dans le build de base.

## Positionnement de l'architecture
> Organisation du dépôt : Krymux est un SDK (`crates/krymux`, bibliothèque pure) ; les applications se construisent au-dessus — `krymux-tunnel` (CLI d'exploitation du tunnel), `krymux-sync` (synchronisation de fichiers), `browser/` (SDK JS navigateur).

**Le SDK de protocole reste multi-langage ; les applications sont exclusivement en Rust.**

- Le SDK de protocole (trames / multiplexage / TLS / compression) conserve deux implémentations — Node (référence) et Rust — comme bases de régression mutuelles ; Go et Python sont prévus.
- Les applications de plus haut niveau (synchronisation de fichiers, extensions du frontal WS, …) sont implémentées **uniquement en Rust** afin de garder une surface de maintenance réduite.
- Le paquet Node est positionné comme une **référence de protocole pure** (sans applications) ; le déploiement en production utilise ce binaire Rust.

### Notes d'implémentation (Rust)

- **TLS** : rustls (backend ring), TLS 1.3 uniquement, ALPN `krymux`. Le serveur exige un certificat client émanant de n'importe quel émetteur, puis admet la connexion au regard de la liste blanche `sha256(SPKI)` (fail-closed). Le client épingle l'empreinte du serveur. Les certificats sont générés par rcgen (Ed25519).
- **Multiplexage** : le même format de trames que la version Node (voir [`../ectun/docs/PROTOCOL.md`](../ectun/docs/PROTOCOL.md)) — contrôle de flux à crédits par stream (comptabilisé sur les octets décompressés), contextes de compression continus, propagation du half-close.
- **Modèle de tâches** : deux tâches par connexion (lecteur/écrivain) + pompes entrante/sortante par stream + ticker de crédits + keepalive ; les données atteignent l'application via des duplex tokio. Les sockets du tunnel activent `TCP_NODELAY`.
- **Compression** : `deflate` (flate2), `brotli` (crate brotli, API push de bas niveau), `zstd` (fonctionnalité optionnelle). La décompression Brotli emprunte l'API de bas niveau `BrotliDecompressStream` — `DecompressorWriter` parque la sortie dans un tampon interne et son flush ne pilote pas le décodage, ce qui fait perdre les octets de fin sur les gros transferts inter-implémentations ; le chemin de bas niveau évite cela.
- **Corrigé (post-mortem archivé)** : un bug d'octets de fin manquants au EOF, causé par un auto-interblocage par double verrouillage dans `Drop` (un `Mutex` std non réentrant, reverrouillé au sein d'un prédicat `if let` — blocage permanent, le `JoinHandle` ne revient jamais). Également corrigé : la moitié écriture du split tokio n'envoyait pas le EOF à la destruction (`poll_shutdown` explicite + `stream.shutdown()` côté serveur) ; et il est documenté que « tout écrire, puis lire » se bloque en backpressure à l'identique sur du TCP brut — le schéma correct consiste à écrire tout en lisant, ce que font naturellement navigateurs/curl.

## Compilation

```bash
cargo build --release                                # workspace: SDK + both apps, pure-Rust dependency chain
cargo build --release --features krymux/zstd         # + zstd (C compilation verified under MSVC/gcc) — recommended
cargo build --release --features krymux/pq           # + aws-lc-rs post-quantum KEM (~5.7 MB binaries)
cargo build --release --features "krymux/pq krymux/zstd"  # everything
# artifacts: target/release/krymux-tunnel and target/release/krymux-sync — no runtime dependencies
```

Compilation croisée pour Linux (déploiement vers un serveur ou LXD) :

```bash
rustup target add x86_64-unknown-linux-gnu
# with a Linux-side linker: cargo build --release --target x86_64-unknown-linux-gnu
# or use cross / cargo-zigbuild
```

Note : le build de base annonce `none`/`deflate`/`brotli` dans la négociation HELLO ; `zstd` nécessite la fonctionnalité `zstd`.

## Démarrage rapide

Surface CLI (même forme que la version Node) :

| Commande | Objectif |
|---|---|
| `krymux-tunnel keygen --out <dir> --role server\|client [--name x] [--cn cn]` | Générer une identité Ed25519 (clé + certificat auto-signé + empreinte) |
| `krymux-tunnel fingerprint <key-or-cert.pem>` | Afficher l'empreinte d'un fichier PEM |
| `krymux-tunnel probe <host:port>` | Afficher l'empreinte de clé d'un serveur (assistant TOFU) |
| `krymux-tunnel server --config server.json` | Exécuter le serveur reverse proxy |
| `krymux-tunnel client --config client.json [--socks5 h:p] [--http-proxy h:p]` | Exécuter le client (éventuellement avec des frontaux proxy locaux) |
| `krymux-sync sync-server --path <dir> [--port 17890] [--mode bidir\|readonly]` | Exécuter un serveur de synchronisation de fichiers derrière krymux |
| `krymux-sync sync-client --path <dir> --config client.json [--mode …] [--watch] [--interval 30]` | Exécuter un client de synchronisation de fichiers à travers le tunnel |

### 1. Générer les identités des deux côtés

```bash
./target/release/krymux-tunnel keygen --out ./keys --role server
./target/release/krymux-tunnel keygen --out ./keys --role client --name alice
```

Chaque commande affiche l'empreinte `sha256:` de l'identité.

### 2. (TOFU) Vérifier l'empreinte du serveur

Si vous ne connaissez pas encore l'empreinte du serveur, vérifiez-la une fois hors bande et inscrivez-la dans la configuration :

```bash
./target/release/krymux-tunnel probe frp.example.com:7000
```

### 3. Configuration du serveur (sur la machine de service — c'est le port vers lequel frpc transfère)

```jsonc
// server.json
{
  "listen": "127.0.0.1:7443",                       // ← frpc's localPort points here
  "identity": { "key": "keys/server.key.pem", "cert": "keys/server.crt.pem" },
  "auth": {
    "mode": "whitelist",
    "fingerprints": [ "sha256:<alice fingerprint, printed by keygen>" ]
  },
  "routes": [
    { "host": ["nas.example"], "upstream": ["127.0.0.1", 5000] },
    { "host": ["*.example"],   "upstream": ["127.0.0.1", 80] },
    { "host": ["db"], "port": 5432, "upstream": ["127.0.0.1", 5432] }
  ],
  "fallbackUpstream": ["127.0.0.1", 80],            // route for unmatched hosts
  "clientTargets": { "enabled": false }             // true = allow clients to pick arbitrary host:port
}
```

```bash
./target/release/krymux-tunnel server --config server.json
```

### 4. Configuration du client (n'importe où)

```jsonc
// client.json
{
  "endpoint": "frp.example.com:7000",               // ← the public port frps exposes
  "identity": { "key": "keys/alice.key.pem", "cert": "keys/alice.crt.pem" },
  "serverFingerprint": "sha256:<server fingerprint from probe>",
  "compression": "auto"
}
```

```bash
./target/release/krymux-tunnel client --config client.json --socks5 127.0.0.1:1080
```

### 5. Utilisation

Pointez un navigateur ou curl vers le proxy SOCKS5 local — **le nom d'hôte devient la clé de routage vhost** :

```bash
curl --socks5-hostname 127.0.0.1:1080 http://nas.example/
```

`--http-proxy 127.0.0.1:8080` fournit à la place un frontal proxy HTTP/1.1 (CONNECT + forme absolue). Les champs de configuration sont identiques à la version Node ; voir [`../ectun/examples/`](../ectun/examples/) pour des scénarios complets.

## Synchronisation de fichiers

```bash
# Host A (server side, behind krymux)
krymux-sync sync-server --path /data --port 17890 [--mode bidir|readonly]
# krymux server config: { "host": ["sync"], "upstream": ["127.0.0.1", 17890] }

# Host B (client side, through the tunnel)
krymux-sync sync-client --path /data --config client.json [--mode bidir|readonly]

# Daemon mode: keep running, push local changes immediately, pull remote changes,
# auto-reconnect on failure
krymux-sync sync-client --path /data --config client.json --watch --interval 30
```

### Moteur de synchronisation

- **Bidirectionnelle** : téléchargement serveur → client et téléversement client → serveur, pilotés par **comparaison de hachages SHA-1**, **alignement du décalage d'horloge mtime** entre les deux machines, **écritures atomiques** (fichier tmp → renommage) et **détection de verrous**.
- **Le mode lecture seule est négocié** via `hello_ack` : quand le serveur est en lecture seule, le client supprime automatiquement les téléversements, et le serveur rejette de toute façon `put`.
- **Signalement des conflits** pour les modifications concurrentes (voir la sémantique multi-clients ci-dessous).
- **Protection contre le path traversal** : les segments `..`, les chemins absolus et les lettres de lecteur sont toujours rejetés.

### Daemon watch (`--watch`, `apps/krymux-sync/src/sync/daemon.rs`)

- **Modifications locales** → événements notify avec une **période de silence de 700 ms (debounce)**, en ignorant `*.sync-tmp` et les événements de lecture (inotify rapporte comme changements les lectures de hachage de notre propre scan ; sans filtrage, le phénomène s'auto-entretient en boucle sous Linux).
- **Modifications distantes** → poussées proactivement par le serveur (`rescan_hint`) : sync-server surveille son propre arbre (`apps/krymux-sync/src/sync/notify.rs`) et avertit immédiatement les daemons connectés dès qu'un changement survient — l'arrivée d'un hint est de l'ordre de la seconde. Les hints sont **supprimés tant qu'une session de synchronisation est active** (le serveur ne renvoie ainsi pas en écho les téléversements qu'il est en train de recevoir) ; un hint fusionné unique est émis à la fin de la session, et c'est aussi ce qui propage les changements aux autres clients. Les anciens serveurs sans prise en charge des hints se dégradent silencieusement et l'intervalle prend le relais.
- **`--interval`** (par défaut 30 s) : la réconciliation périodique est désormais un **filet de sécurité** (hints perdus / anciens serveurs) plutôt que le mécanisme principal.
- **Reconnexion** : en cas de perte du tunnel, la passe suivante échoue et reconstruit le tunnel avec un backoff exponentiel débutant à 1 s, plafonné à 60 s.
- **Sûr face à un kill à tout instant** : toutes les écritures passent par tmp+rename et les scans ignorent les débris.

### Sémantique multi-clients

N clients peuvent synchroniser simultanément la même racine serveur. Les modifications d'un client sont diffusées aux autres en quelques secondes via le hint de fin de session (sans attendre l'intervalle). Les modifications concurrentes du même fichier convergent en **last-writer-wins par mtime** — chaque extrémité finit par être d'accord, sans contenu mélangé.

### Verrous et conflits au démarrage (vérifiés par les 8 phases de `edge-e2e.sh`)

- **Exclusion mutuelle sur la racine** : sync-server/sync-client prennent au démarrage un verrou de fichier OS exclusif sur `<root>/.sync.lock` (API native std 1.89 : `LockFileEx` sous Windows, `flock` sous Unix). Un second processus sur la même racine est refusé d'emblée ; un processus planté libère le verrou automatiquement — aucune récupération de verrou périmé n'est nécessaire.
- **Vérification des verrous au démarrage** : si un fichier quelconque de la racine est détenu en exclusif par un autre processus, le démarrage est refusé et les fichiers en cause sont listés.
- **Verrous à l'exécution** : les fichiers verrouillés côté client sont ignorés pour la passe (laissés intacts). Les fichiers verrouillés ou illisibles côté serveur (y compris les échecs de lecture au moment du scan = hachage `None`) sont traités comme *indéterminables → ignorer cette passe*, jamais classés à tort comme conflits.
- **Débris de plantage** : un `kill -9` à tout instant est sans danger (atomicité tmp+rename ; testé en E2E avec 500 Mo, aucun tearing). Les fichiers `*.sync-tmp` périmés de plus de 1 h sont nettoyés au démarrage.
- **Isolation des défaillances ponctuelles** : un fichier impossible à poser (p. ex. un placeholder de répertoire) est ignoré sans affamer le reste de la passe ; un échec de vérification de téléchargement (taille/hachage) est réessayé une fois au sein de la passe.
- **Frontière de vérification** : le chemin de bout en bout des verrous de fichiers est vérifié sous Windows (véritables violations de partage) ; les conteneurs Linux non privilégiés ne peuvent pas simuler des fichiers non inscriptibles (root ignore chmod ; chattr exige `CAP_LINUX_IMMUTABLE`), le côté Linux est donc vérifié par l'exclusion `flock` entre deux processus, complétée d'un cycle kill-relance.

### Compatibilité inter-OS (Windows ↔ Linux, testée à travers un relais simulé par proxy LXD)

- **Couche de connexion** : résolution multi-adresses avec tentatives séquentielles et **délai d'expiration indépendant de 5 s par adresse** — les noms mDNS/DNS comptant plusieurs enregistrements A/AAAA n'épuisent plus le budget de connexion quand l'IPv6 est blackholé (observé avec `myhost.local` renvoyant 3×IPv6 + 2×IPv4, où l'IPv6 blackholé provoquait des timeouts garantis).
- **Noms de fichiers** : UTF-8 (noms de fichiers chinois + contenu) sans perte dans les deux sens ; les **noms illégaux sous Windows** (`<>:"|?*`, noms réservés comme `CON`/`COM1`, points/espaces de fin) sont ignorés avec un avertissement ; les **collisions de casse** (Linux `Foo.txt` + `foo.txt`) produisent un avertissement sur toutes les plateformes, et les plateformes insensibles à la casse ne synchronisent que le premier nom rencontré (évitant le basculement perpétuel téléchargement/écrasement) ; les chemins longs fonctionnent (préfixe `\\?\` sous Windows, testé à 212 caractères).
- **Liens symboliques** : ignorés selon la sémantique `lstat` (non suivis, non propagés, aucun risque de cycle).
- **mtime entre systèmes de fichiers** : les allers-retours NTFS↔ext4 restent stables grâce au court-circuit par hachage (contenu identique = no-op).
- **Limite** : macOS (observateur FSEvents) n'a jamais été compilé ni exécuté — non vérifié.

### Propagation des suppressions (tombstones)

Les suppressions se propagent à tous les clients (`.sync-tombstones.json`, expiration 30 jours, protection last-writer par mtime corrigée de l'offset horloge, suppression readonly bloquée des deux côtés) ; un fichier modifié ailleurs après suppression l'emporte avec le contenu le plus récent. `deletion-semantics-probe.sh` vérifie les deux sens sans résurrection. Note : les chiffres de performance font foi dans la version anglaise et `bench/BASELINE.md`.

## Accès navigateur (WebSocket)

Le serveur dessert trois types de connexion sur le **même port TLS**, en mode dual par détection : clients mTLS natifs (certificat Ed25519 + ALPN `krymux`) face à tout le reste sans certificat client, où un `GET` HTTP bascule vers le chemin WebSocket/statique. frp continue simplement de transférer le texte chiffré TCP — aucune configuration supplémentaire.

1. Démarrez le serveur. Il génère automatiquement une identité navigateur (`ws-p256.key.pem`, P-256) et journalise son `wsFingerprint`.
2. Ouvrez `https://<frps-public-port>/` dans un navigateur (acceptez une seule fois l'exception pour le certificat auto-signé) — la page de lancement intégrée se charge.
3. Ajoutez l'empreinte d'identité affichée sur la page aux `auth.fingerprints` du serveur — la **même liste blanche** que celle qu'utilisent les clients natifs.
4. Rafraîchissez, saisissez un `host:port` cible, connectez-vous — tout service routé est accessible depuis l'onglet du navigateur.

L'authentification est équivalente en force à mTLS : une seule liste blanche `sha256(SPKI)` mélange des entrées Ed25519 (natives) et P-256 (navigateur) ; la signature de couche application du client prouve l'identité inscrite en liste blanche, la signature du serveur prouve l'identité épinglée (à l'intérieur de TLS). Le serveur Rust applique un délai d'authentification de 10 s et un plafond de 256 connexions WS simultanées. Le SDK est un ESM monofichier sans dépendance (`ectun-browser.mjs`, intégré à ce dépôt en `browser/ectun-browser.mjs` — servez-le ou importez-le ; le protocole filaire est identique) :

```js
import { getIdentity, connect } from '/sdk/ectun-browser.mjs';
const id = await getIdentity();          // P-256 identity, persisted in IndexedDB
// id.fingerprint → add to the server whitelist
const c = await connect({
  endpoint: 'wss://frps.example:7000',
  serverFingerprint: 'sha256:…',         // pin the server's WS identity
  identity: id,
});
const s = await c.openStream({ host: 'a.test', port: 80 });
await s.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: a.test\r\n…'));
await s.end();
s.onData((chunk) => …); s.onEnd(() => …);
```

Le SDK v1 annonce la compression `none` (la négociation CMPX est prête pour des évolutions futures). Détails du protocole : [`../ectun/docs/PROTOCOL.md` §6A](../ectun/docs/PROTOCOL.md).

## Vérification

```bash
bash e2e-sync-test.sh   # file sync: 9-phase main flow
bash edge-e2e.sh        # file sync: 8 edge phases (locks / crash / conflicts)
```

- **Interop 11/11** face à la référence Node (`interop/test-interop.mjs`) :
  - Client Node → serveur Rust : écho none/deflate/brotli 1 Mo identique à l'octet près, routage double vhost, cible non routée rejetée, clé hors liste blanche rejetée ;
  - Client Rust → serveur Rust : SOCKS5 + vhost (exercés avec curl) ;
  - Client Rust → serveur Node : écho none/deflate/brotli 1 Mo identique à l'octet près.
- **Interopérabilité des empreintes** : la commande `fingerprint` de Node calcule la même valeur pour les certificats issus du keygen Rust, et réciproquement.
- **Modèle de déploiement LXC** : installation à deux conteneurs dans [`deploy/lxc/`](deploy/lxc/) — `server.json` / `client.json` / unités systemd pour le serveur, le sync-server et le(s) sync-client(s). Résultats sur machine réelle : 100 Mo transférés md5-identiques, propagation inter-clients en ~2 s, livraison des hints de rescan en ~1 s.

## Performances

Benchmarks en loopback (chiffres Node issus de la référence Node, Node 24.15, voir [`../ectun/docs/BENCHMARKS.md`](../ectun/docs/BENCHMARKS.md) ; chiffres Rust issus d'`examples/bench`, écho 16 Mo) :

| Configuration | Débit |
|---|---|
| Rust, écho 16 Mo, sans compression | ~405 Mo/s |
| Rust, écho 16 Mo, zstd (texte compressible) | ~739 Mo/s |
| Référence Node, sans compression (×1/×4 streams) | ~80 Mo/s (plafond JS monocœur) |
| Référence Node, zstd ×4 streams (texte) | ~319 Mo/s |
| Référence Node, brotli ×4 streams (texte) | ~285 Mo/s |
| **Auto-croissance de fenêtre, stream unique @ 50 ms RTT** | **4,0 → 32,4 Mo/s** (256 Ko fixes → auto jusqu'à 4 Mo) |
| À travers un relais TCP (frp simulé) | aucune pénalité mesurable |
| Latence d'ouverture de stream | p50 0,28 ms (au sein d'une connexion établie) |
| Poignée de main TLS complète | ~6 ms (loopback) |

La compression *augmente* souvent le débit (moins d'octets sur le fil) ; le goulot d'étranglement de fenêtre sur les vrais liens frp est éliminé par l'auto-croissance, ne laissant comme limites que la bande passante publique et le CPU de compression.

## Référence de configuration

JSON à clés camelCase, schéma identique dans les deux implémentations.

### server.json

| Champ | Type | Valeur par défaut | Description |
|---|---|---|---|
| `listen` | string | *requis* | `host:port` à écouter ; le `localPort` de frpc pointe ici |
| `identity.key`, `identity.cert` | string | *requis* | chemins PEM Ed25519 issus de `keygen` |
| `auth.mode` | string | `"whitelist"` | mode d'admission |
| `auth.fingerprints` | string[] | `[]` | liste blanche de clients `sha256(SPKI)` (les entrées d'`auth.clients` sont fusionnées) |
| `routes[].host` (alias `hosts`) | string ou string[] | — | clés de correspondance vhost ; jokers comme `*.example` |
| `routes[].port` (alias `ports`) | number, `"n"`, `"a-b"`, `"*"` ou tableau | — | motif de port optionnel pour la route |
| `routes[].upstream` | `[host, port]`, `"host:port"`, `"unix:/path"`, ou `{host, port}` / `{unix}` | — | destination où le trafic correspondant est remis |
| `fallbackUpstream` (alias `defaultUpstream`) | upstream | — | route pour les hôtes ne correspondant à aucune route |
| `clientTargets.enabled` | bool | `false` | autoriser les clients à spécifier des cibles `host:port` arbitraires |
| `clientTargets.allowHosts` | string[] | `["*"]` | motifs d'hôtes qu'un client peut choisir |
| `clientTargets.allowPorts` | pattern[] | — | motifs de ports qu'un client peut choisir |
| `keepaliveSec` | integer | `30` | intervalle de keepalive |
| `maxStreams` | integer | `1024` | nombre maximal de streams logiques par connexion |
| `rxWindow` | integer | `262144` (256 Ko) | fenêtre de réception initiale par stream |
| `rxWindowMax` | integer | `4194304` (4 Mo) | plafond d'auto-croissance ; régler égal à `rxWindow` pour désactiver la croissance |
| `log.level` | string | `"info"` | niveau de journalisation |
| `statsIntervalMs` | integer | — | affichage périodique des statistiques |

### client.json

| Champ | Type | Valeur par défaut | Description |
|---|---|---|---|
| `endpoint` | string | *requis* | `host:port` public exposé par frps |
| `identity.key`, `identity.cert` | string | *requis* | chemins PEM Ed25519 du client |
| `serverFingerprint` | string | *requis* | empreinte `sha256:…` épinglée du serveur |
| `compression` | string | `"auto"` | `none` / `auto` / `deflate` / `brotli` / `zstd` (build zstd), ou préréglages de niveau comme `"zstd:9"`, `"brotli:11"`, `"deflate:9"` (s'applique au côté émetteur) |
| `keepaliveSec` | integer | `30` | intervalle de keepalive |
| `rxWindow` | integer | `262144` (256 Ko) | fenêtre de réception initiale par stream (réglable des deux côtés) |
| `rxWindowMax` | integer | `4194304` (4 Mo) | plafond d'auto-croissance |
| `socks5` | string | — | adresse du frontal SOCKS5 local, p. ex. `127.0.0.1:1080` |
| `httpProxy` | string | — | frontal proxy HTTP/1.1 local (CONNECT + forme absolue) |
| `log.level` | string | `"info"` | niveau de journalisation |

Auto-croissance de fenêtre : quand un stream a consommé plus de la moitié de sa fenêtre et l'a vidée, le crédit double toutes les 100 ms ; les streams sous backpressure ne grandissent pas. Les deux extrémités peuvent configurer `rxWindow`/`rxWindowMax` ; `rxWindowMax = rxWindow` désactive la croissance.

## Dépannage

- `KRYMUX_LOG=debug` pour la journalisation de debug.
- `KRYMUX_MUX_TRACE=1` pour un traçage au niveau des trames sur stderr (flags compris).

## Feuille de route

- **Propagation des suppressions** (tombstones : un répertoire `.sync-tombstones` avec nettoyage par expiration).
- **Dictionnaires zstd (`zstdd`)** — conception finalisée : `zstd --train` hors ligne, les deux côtés référençant le même dictionnaire, négociation HELLO de `zstdd` avec vérification par suffixe d'empreinte de dictionnaire ; premiers paquets attendus 2 à 4× plus petits sur les streams courts (HTTP/API). Le côté Node nécessite un binding natif ou un repli négocié vers le zstd simple.
- **Regroupement par paliers des longueurs de trames PAD** avec un trafic de couverture à débit fixe (réservé dans le protocole v1.1).
- Débit en **cluster / multicœur**.
- Prise en charge d'**UDP**.
- **SDK Go / Python**.
- **Dérivation de clés de style Noise** pour l'authentification WS.
- **Build et vérification macOS** (observateur FSEvents).

## Licence

MIT

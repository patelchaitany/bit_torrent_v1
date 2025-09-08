# Simple BitTorrent Client (fast-peer)

A compact BitTorrent client focused on fast peer acquisition and reliable downloads. Designed for experimentation, research, and lightweight seeding — not a production-grade client.

---

## Overview

This project implements a simple BitTorrent client with an emphasis on:

* **Immediate piece requests after handshake** (no startup delay) to reduce idle time.
* **DHT support (BEP 5)** for trackerless peer discovery.
* **DHT port advertisement/consumption** via message type `9` (metadata/magnet support).
* **Auto-replenish peers** through DHT lookups when connections drop.
* **Optional magnet metadata downloader** and a minimal seeder implementation.

Ideal for: testing swarm behavior, research on peer discovery strategies, and small-scale seeding.

---

## Features

* Tracker discovery (HTTP/UDP) using standard announce requests.
* DHT node with `get_peers` / `find_node` support (BEP 5).
* PEX support where available (`ut_pex`).
* Parallel block requests per piece (configurable concurrency) for higher throughput.
* Auto-reconnect and peer replenishment from DHT when peers disconnect.
* Optional `app/seeder.py` to seed a .torrent (requires `libtorrent`).

---

## Requirements

* **Python 3.10+** (tested on Linux)
* `requests` (used for HTTP trackers):

```bash
pip install requests
```

* Optional: `libtorrent` (only required if you want to run `app/seeder.py`)

---
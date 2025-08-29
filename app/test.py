import libtorrent as lt
import time
import os

def run_localhost_peer(torrent_file, download_dir, port):
    ses = lt.session()
    ses.listen_on(port+20, port + 10)

    # Enable LSD for local peer discovery (works on localhost too)
    ses.start_lsd()
    ses.stop_dht()   # disable internet
    ses.stop_upnp()

    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    info = lt.torrent_info(torrent_file)
    params = {"ti": info, "save_path": download_dir}
    handle = ses.add_torrent(params)

    print(f"Peer running on 127.0.0.1:{port}")

    while True:
        s = handle.status()
        print(
            f"[{port}] Progress: {s.progress * 100:.2f}% "
            f"Peers: {s.num_peers} "
            f"Down: {s.download_rate / 1000:.1f} kB/s "
            f"Up: {s.upload_rate / 1000:.1f} kB/s"
        )

        for peer in handle.get_peer_info():
            incoming = " (incoming)" if peer.flags & lt.peer_info.local_connection else ""
            print(f"[{port}] Peer {peer.ip[0]}:{peer.ip[1]}{incoming}")

        time.sleep(1)


if __name__ == "__main__":
    # Example: start one as seeder and another as leecher
    # Seeder: place full file in ./seed_dir and run with same torrent
    # Leecher: empty ./download_dir, run on another port
    torrent_file = "testfile.torrent"

    # Example seeder
    # run_localhost_peer(torrent_file, "./seed_dir", 6881)

    # Example leecher
    run_localhost_peer(torrent_file, "./download_dir", 6891)


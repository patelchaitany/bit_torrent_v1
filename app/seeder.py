import libtorrent as lt
import time
import os

def run_seeder(torrent_file, seed_dir, port=6881):
    ses = lt.session()
    ses.listen_on(port, port + 10)

    # No internet, only localhost
    ses.stop_dht()
    ses.stop_upnp()
    ses.start_lsd()   # Local discovery works on 127.0.0.1

    if not os.path.exists(seed_dir):
        raise FileNotFoundError(f"Seed directory {seed_dir} does not exist")

    info = lt.torrent_info(torrent_file)
    params = {"ti": info, "save_path": seed_dir}
    handle = ses.add_torrent(params)

    print(f"Seeder running on 127.0.0.1:{port} for {torrent_file}")

    # Ensure files are checked
    handle.force_recheck()

    while True:
        s = handle.status()
        state_str = [
            'queued', 'checking', 'downloading metadata',
            'downloading', 'finished', 'seeding', 'allocating'
        ]
        print(
            f"State: {s.state} | "
            f"Progress: {s.progress * 100:.2f}% | "
            f"Peers: {s.num_peers} | "
            f"Upload: {s.upload_rate / 1000:.1f} kB/s"
        )
        for peer in handle.get_peer_info():
            incoming = "incoming" if peer.flags & lt.peer_info.local_connection else "outgoing"
            print(
                f"➡ Peer {peer.ip[0]}:{peer.ip[1]} | "
                f"Client: {peer.client} | "
                f"Direction: {incoming} | "
                f"Down: {peer.down_speed/1000:.1f} kB/s | "
                f"Up: {peer.up_speed/1000:.1f} kB/s"
            )

        time.sleep(1)


if __name__ == "__main__":
    run_seeder("testfile.torrent", "./seed_dir", port=5000)

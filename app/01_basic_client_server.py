import socket

HOST = "127.0.0.1"   # localhost
PORT = 5001          # port number

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #  Allow quick reuse of the port if the server restarts
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s.bind((HOST, PORT))
        s.listen()
        print(f"[server] Listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"[server] Connected by {addr}")
            data = conn.recv(1024)
            print("[server] Received:", data.decode())
            conn.sendall(b"Hello Client!")

def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b"Hello Server!")
        data = s.recv(1024)
        print("[client] Received:", data.decode())

if __name__ == "__main__":
    choice = input("Run as (s)erver or (c)lient? ")
    if choice.lower().startswith("s"):
        server()
    else:
        client()

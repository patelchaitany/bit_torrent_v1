import socket, threading, sys,time

HOST, PORT = "0.0.0.0", 5001
clients = []
clients_lock = threading.Lock()
client_name = {}
client_addr = {}
reverse_lookup = {}
def handle_client(conn, addr):
    last_active = time.time()
    ping_time = None
    with clients_lock:
        clients.append(conn)
        client_name[addr] = None
        client_addr[addr] = conn
    print(f"[server] client joined: {addr}")
    try:
        while True:
            msg = conn.recv(1024) 
            if not msg:
                print(f"continue")
                break
            split_msg = msg.decode().split(" ")
            # print(f"split_msg {split_msg}")
            if client_name[addr] is None:
                if msg.decode().strip().startswith("name:"):
                    client_name[addr] = msg.decode().strip().split(":",1)[1].strip()
                    conn.sendall(f"Welcome {client_name[addr]}!".encode())
                    reverse_lookup[client_name[addr]] = addr
                else:
                    conn.sendall("Please set your name using 'name:<your_name>' format.".encode())
                    continue
            if msg.decode().strip() == "PONG":
                last_active = time.time()
                ping_time = None
                print(f"PONG received from {client_name[addr]}")
                continue
            if ping_time and time.time() - ping_time > 2:
                print(f"[server] {client_name[addr]} timed out, disconnecting...")
                break
            if split_msg[0] == "/msg":
                name = split_msg[1]
                private_message = " ".join(split_msg[2:])
                # print(f"private_message {private_message}")
                with clients_lock:
                    if name in reverse_lookup:
                        target_addr = reverse_lookup[name]
                        client_addr[target_addr].sendall(f"[Private] {client_name[addr]}: {private_message}".encode())
                        continue

            message = msg.decode().strip()
            if message.lower() == "bye":
                print(f"[server] {client_name[addr]} said bye, disconnecting...")
                break
            
            with clients_lock:
                for c in clients:
                    if c is not conn:
                        if message.startswith("/msg"):
                            continue
                        if message.startswith("name:"):
                            c.sendall(f"{addr} is now known as {client_name[addr]}".encode())
                        else:
                            c.sendall(f"Client {client_name[addr]}: {message}".encode())
                
            if last_active + 2 < time.time():
                client_addr[addr].sendall("PING".encode())
                ping_time = time.time()
                continue
            
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()
        print(f"[server] client left: {addr}")

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[server] chat on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def client():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    name = "You"
    def recv_loop():
        while True:
            data = s.recv(1024)
            if data.decode().strip() == "PING":
                s.sendall("PONG".encode())
                print("PING")
                continue
            if not data:
                break
            print("\n" + data.decode() + "\nYou: ", end="")
    threading.Thread(target=recv_loop, daemon=True).start()

    print("Connected to chat. Type 'bye' to quit.")
    try:
        while True:
            line = input(f"{name}: ")
            # print(f"line {line}")
            if line.startswith("name:"):
                name = line.split(":",1)[1].strip()
            s.sendall(line.encode())
            if line.lower() == "bye":
                print("You left the chat.")
                break
    finally:
        s.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "client":
        client()
    else:
        server()

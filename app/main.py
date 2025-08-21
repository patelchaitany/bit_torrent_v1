import json
import sys
from types import resolve_bases
from typing import Dict, List, _type_repr
import hashlib
# import bencodepy #- available if you need it!
import requests  # - available if you need it!
import os
import urllib.parse
import socket
import struct
import math
# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
def make_json_compatible(data):
    """
    Recursively converts bytes in a data structure to strings,
    making it compatible for JSON serialization.
    """
    if isinstance(data, bytes):
        # Decode bytes to a string. Use 'latin-1' for safety as it can handle any byte value.
        return data.decode("latin-1")
    elif isinstance(data, dict):
        # Recursively process dictionary keys and values
        return {
            make_json_compatible(k): make_json_compatible(v) for k, v in data.items()
        }
    elif isinstance(data, list):
        # Recursively process list items
        return [make_json_compatible(item) for item in data]
    else:
        # Keep integers, floats, etc. as they are
        return data
def decode_bencode(bencoded_value, index=0):
    """Decode a bencoded value.
    Args:
        bencoded_value (bytes): The bencoded value to decode.
        index (int): The starting index for decoding.
    Returns:
        The decoded value, which can be a string, integer, or list.
    Raises:
        ValueError: If the bencoded value is invalid.
    """

    if bencoded_value[index : index + 1] == b"i":
        # This is a bencoded integer, e.g., "i42e"
        index += 1
        end_index = bencoded_value.index(b"e", index)
        integer_value = bencoded_value[index:end_index]
        try:
            return int(integer_value), end_index + 1
        except ValueError:
            raise ValueError("Invalid integer value in bencoded data")
    elif bencoded_value[index : index + 1].isdigit():
        # This is a bencoded string, e.g., "5:hello"
        first_colon_index = bencoded_value.index(b":", index)
        length = int(bencoded_value[index:first_colon_index])
        start_index = first_colon_index + 1
        end_index = start_index + length
        if end_index > len(bencoded_value):
            raise ValueError("Invalid bencoded string length")
        return bencoded_value[start_index:end_index], end_index
    elif bencoded_value[index : index + 1] == b"l":
        # This is a bencoded list, e.g., "l5:hello5:worlde"
        index += 1
        result = []
        while bencoded_value[index : index + 1] != b"e":
            item, index = decode_bencode(bencoded_value, index)
            result.append(item)

        return result, index + 1
    elif bencoded_value[index:index+1] == b"d":
        index = index + 1
        result = {}
        while bencoded_value[index:index + 1] != b"e":
            key,index = decode_bencode(bencoded_value,index)
            value,index = decode_bencode(bencoded_value,index)
            result[key] = value

        return result,index +1
    else:
        raise NotImplementedError("not implemented for this type of bencoded value")


def read_torrent(file_path,print_flag = 1):
    try:
        peer_id = os.urandom(20)
        with open(file_path,"rb") as f:
            data = f.read()
        
        decoded_data,_ = decode_bencode(data)
        decoded_data[b'peer_id'] = peer_id
        try:
            # pass
            info_dict = decoded_data[b"info"]
            encoded_info = bencode(info_dict)
            hash_object = hashlib.sha1(encoded_info)
            hex_dig = hash_object.hexdigest()
            piece_hex = decoded_data[b"info"][b"pieces"].hex()

        except KeyError:
            raise ValueError("The torrent file does not contain the 'info' key.")
        tracker_url = decoded_data[b"announce"].decode("utf-8")
        file_length_pice = decoded_data[b"info"][b'piece length']

        file_length = decoded_data[b"info"][b'length']
        if print_flag:
            print(f"Tracker URL: {tracker_url}")
            print(f"Length: {file_length}")
            print(f"Info Hash: {hex_dig}")
            print(f"Piece Length: {file_length_pice}")
            print(f"Piece Hashes: \n{"\n".join([piece_hex[i:i+40] for i in range(0,len(piece_hex),40)])}")
        return decoded_data
    except (FileNotFoundError, ValueError) as e:
        print(f"Error reading or parsing the torrent file: {e}", file=sys.stderr)
        return None

def bencode(bedecoded_value):
    byte_enc = b""
    if isinstance(bedecoded_value,Dict):
        byte_enc = byte_enc + b"d"
        for key in bedecoded_value:
            key_enc = bencode(key)
            val_enc = bencode(bedecoded_value[key])
            byte_enc = byte_enc + key_enc + val_enc
        byte_enc = byte_enc + b"e"

    elif isinstance(bedecoded_value,List):
        byte_enc = byte_enc + b"l"
        for i in bedecoded_value:
            enc_val = bencode(i)
            byte_enc = byte_enc + enc_val
        byte_enc = byte_enc + b"e"

    elif isinstance(bedecoded_value,int):
        byte_enc = byte_enc + b"i"
        b = str(bedecoded_value)
        byte_enc = byte_enc + b.encode() + b"e"
    else:
        size = len(bedecoded_value)
        b = str(size)
        byte_enc = byte_enc + b.encode() + b":" + bedecoded_value

    return byte_enc

def peer_decoding(peer_bytes):
    num_peers = len(peer_bytes)//6
    ip_port = {}
    for i in range(0,len(peer_bytes),6):
        ip_byte = peer_bytes[i:i+4]
        port_byte = peer_bytes[i+4:i+6]

        ip_addr = socket.inet_ntoa(ip_byte)
        port = int.from_bytes(port_byte,"big")

        ip_port[ip_addr] = port

    return ip_port
def get_info_hash(info):
    encoded_info = bencode(info)
    hash_obj = hashlib.sha1(encoded_info)
    info_hash = hash_obj.digest()
    return info_hash
def discover_peer(bedecoded_value,flag = 1):
    info = bedecoded_value[b'info']
    url = str(bedecoded_value[b'announce'],encoding="latin-1")
    info_hash = get_info_hash(info)
    uploaded = 0
    downloaded = 0
    port = 6881
    left = int(bedecoded_value[b'info'][b'length'])
    compact = 1
    
    peer_id = bedecoded_value[b'peer_id']
    params = {
        "info_hash":info_hash,
        "peer_id":peer_id,
        "port":port,
        "uploaded":uploaded,
"downloaded":downloaded,
        "left":left,
        "compact":compact
    }
    try:
        response = requests.get(url = url,params= params)
        decoded_responce,_ = decode_bencode(response.content)
        port_ip = peer_decoding(decoded_responce[b'peers']) 
        if flag:
            for i in port_ip:
                print(f"{i}:{port_ip[i]}")
        return port_ip
    except Exception as e:
        raise ValueError(f"{e}")

def decode_torrent_protocol(data):
    length = int.from_bytes(data[0:1])
    bit_string = str(data[1:20],encoding="latin-1")
    function_byte = data[20:28]
    info_hash = data[28:48]
    peer_id = data[48:68]
    
    decode_info = {}
    decode_info["length"] = length
    decode_info["bit_string"] = bit_string
    decode_info["function_byte"] = function_byte
    decode_info["info_hash"] = info_hash
    decode_info["peer_id"] = peer_id
   

    return decode_info
    
# This function read the current responce and acording it return the next message pay load and also set the step in which we are
def payload_create(request_info,message_return,stage = 0):
    payload_next = b''
    if stage == 0:
        payload_next = b'\x00\x00\x00\01'
        payload_next = payload_next + b'\x02'
        message_return['payload'] = payload_next
    elif stage == 1:
        #now send requested message
        index = request_info['index'].to_bytes(4,"big")
        begin = request_info['begin'].to_bytes(4,"big")
        length = request_info['length'].to_bytes(4,"big")
        payload_next = b'\x00\x00\x00\x0D\x06' + index + begin + length
        message_return['payload'] = payload_next
    return message_return

def hash_comp(data,hash):
    hash_obeject = hashlib.sha1(data)
    binary_hash = hash_obeject.digest()
    if binary_hash == hash:
        return 1
    else: 
        return 0
def read_message(message,request_info,stage = 0):
    message_legth = int.from_bytes(message[0:4],byteorder="big")
    message_type = int.from_bytes(message[4:5])
    payload = message[5:]


    message_return = {
        "stop":0,
        "downloaded_idx":None,
        "have_pices":None,
        "have_idx":None,
        "data":None,
        "begin_index":None,
        "payload":None,
        "piece_index":None
    }
    #choke
    if message_type == 0:
        message_return["stop"] = 1
    elif message_type == 1:
        message_return["stop"] = 0
    elif message_type == 5:
        message_return["have_pices"] = payload
    elif message_type == 4:
        message_return['have_idx'] = payload
    elif message_type == 7:
        piece_index =int.from_bytes(payload[0:4],byteorder="big")
        begin_index = payload[4:8]
        block_data = payload[8:]
        message_return['data'] = block_data
        message_return['begin_index'] = begin_index
        message_return['piece_index'] = piece_index
    #Now send Intrested message

    return message_return

def get_msb_index(bitfield):
    for byte_index, byte in enumerate(bitfield):
        for bit_index in range(8):
            if byte & (1 << (7 - bit_index)):  # check MSB first
                piece_index = byte_index * 8 + bit_index
                return 1, piece_index
    return 0, None  # no bits set

def set_piece(bitfield, piece_index,value = 1):
    byte_index = piece_index // 8
    bit_index = piece_index % 8
    mask = 1 << (7 - bit_index)  # MSB-first convention in BitTorrent

    if value:
        bitfield[byte_index] |= mask
    else:
        bitfield[byte_index] &= ~mask

def recv(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))

    while len(message)<int.from_bytes(length):
        message = message + s.recv(int.from_bytes(length) - len(message))
    
    return length + message

def download_whole_file(peer_info,decode_data,print_flag = 1,download = 0):
    
    def download_piece(socke_info,print_flag,download = 0):
        
    

def peer_tcp(socket_info,decode_data,print_flag = 1,download = 0):
    info_hash = socket_info["info_hash"]
    peer_id = socket_info["peer_id"]
    host = socket_info["host"]
    port = socket_info["port"]
    num_pieces = math.ceil(len(decode_data[b'info'][b'pieces'])/20)
    # This is the handshake Protocol
    protocol = b"\x13" + b"BitTorrent protocol" + 8*b"\x00"
    protocol = protocol + info_hash
    protocol = protocol + peer_id
    have_pieces = bytearray(math.ceil(num_pieces / 8))  # bytearray of zeros

    request_info = {
        "begin" : 0,
        "length" : 0,
        "index" : 0
    }

    current_have = bytearray(num_pieces*b'\x00')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host,port))
        client_socket.sendall(protocol)
        resp = client_socket.recv(68)

        peer_info = decode_torrent_protocol(resp)

        pices_hash = {}
        if print_flag == 1:
            print(f"Peer ID: {peer_info['peer_id'].hex()}")

        if download == 0:
            return pices_hash,current_have
        piece_length = decode_data[b'info'][b'piece length']
        total_length_file = decode_data[b'info'][b'length']

        bitfield_message = recv(client_socket)
        #print(f"bit filed {bitfield_message}")
        next_message = read_message(bitfield_message,request_info,stage=0)
        next_message = payload_create(request_info,next_message,stage=0)

        have_pieces = bytearray(next_message['have_pices'])
        step = 1
        pices_hash = {}

        for i in range(num_pieces):
            xor_result = bytearray(a ^ b for a, b in zip(have_pieces, current_have))
            have_pieces = bytearray(a & b for a, b in zip(have_pieces, xor_result))
            flag,index = get_msb_index(have_pieces)
            if socket_info["requested_index"]:
                index = socket_info["requested_index"]
            if not flag or index is None:
                break
            request_info["length"] = min(int.from_bytes(b'\x40\x00'),piece_length)
            request_info['index'] = index
            
            total_length = piece_length
            if index == num_pieces -1:
                total_length = total_length_file%total_length
            set_piece(have_pieces,index,value=0)
            set_piece(current_have,index)
            request_info['begin'] = 0
            if next_message['payload'] is None:
                next_message = payload_create(request_info,next_message,stage=1)

            while True:
                client_socket.send(next_message['payload'])
                new_message = recv(client_socket)
                #print(f"from while {new_message}")
                next_message = read_message(new_message,request_info,stage=step)
                if next_message['stop'] == 1:
                    break
                if next_message['have_idx']:
                    set_piece(have_pieces,int.from_bytes(next_message['have_idx'],byteorder="big"))
                if next_message['begin_index']:
                    begin_index = int.from_bytes(next_message['begin_index'],byteorder="big")
                if next_message['data']:
                    if index in pices_hash:
                        pices_hash[index] = pices_hash[index] + next_message['data']
                    else:
                        pices_hash[index] = next_message['data']
                    request_info['begin'] = request_info['begin']+len(next_message['data'])
                    total_length = total_length - len(next_message['data'])
                    if total_length > 0 and total_length < int.from_bytes(b'\x40\x00',byteorder="big"):
                        request_info['length'] = total_length
                    elif total_length<=0:
                        break
                    elif total_length>0:
                        request_info['length'] = int.from_bytes(b'\x40\x00',byteorder="big")
                next_message = payload_create(request_info,next_message,stage=step)
            
            if hash_comp(pices_hash[index],decode_data[b'info'][b'pieces'][(20*index):20*(index + 1)]) == 0:
                break
            if socket_info['requested_index']:
                break

    return pices_hash,have_pieces

def main():

    # print([[] , [] , []])
    if len(sys.argv) < 1:
        print("Usage: python main.py <command> [args]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!", file=sys.stderr)

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage

        print(json.dumps(make_json_compatible((decode_bencode(bencoded_value))[0]), default=bytes_to_str))
    elif command == "info":
        if len(sys.argv) < 3:
            print("Usage: python main.py info <torrent_file_path>", file=sys.stderr)
            sys.exit(1)
        torrent_file_path = sys.argv[2]
        read_torrent(torrent_file_path)
        
    elif command == "peers":
        if len(sys.argv) < 3:
            print("Usage: python main.py info <torrent_file_path>", file=sys.stderr)
            sys.exit(1)
        torrent_file_path = sys.argv[2]

        decode_data = read_torrent(torrent_file_path,print_flag=0)
        discover_peer(decode_data)
    elif command == "handshake":
        torrent_file_path = sys.argv[2]
        ip_port = sys.argv[3]
        ip_addr,port = ip_port.split(":")
        decode_data = read_torrent(torrent_file_path,print_flag=0)
        info_hash = get_info_hash(decode_data[b'info'])
        port = int(port)
        socket_info = {}
        socket_info["port"] = port
        socket_info["host"] = ip_addr
        socket_info["peer_id"] = decode_data[b'peer_id']
        socket_info["info_hash"] = info_hash
        peer_tcp(socket_info,decode_data)
    elif command == "download_piece":
        output_file = ""
        if sys.argv[2] == "-o":
            output_file = sys.argv[3]
        torrent_file_path = sys.argv[4]
        index = int(sys.argv[5])
        decode_data = read_torrent(torrent_file_path,print_flag=0)
        peer_info = discover_peer(decode_data,flag=0)
        info_hash = get_info_hash(decode_data[b'info'])
        #print(f"Info Hash {info_hash}")
        socket_info = {}
        socket_info['requested_index'] = None
        pices_data = None
        have_pices = None
        for i in peer_info:
            socket_info["port"] = peer_info[i]
            socket_info["host"] = i
            socket_info["peer_id"] = decode_data[b'peer_id']
            socket_info['info_hash'] = info_hash
            socket_info["requested_index"] = index
            pices_data,have_pices = peer_tcp(socket_info,decode_data,download=1,print_flag=0)
            break

        with open(output_file,'wb') as f:
            if pices_data[index]:
                f.write(pices_data[index])

    elif command == "download_piece":
        output_file = ""
        if sys.argv[2] == "-o":
            output_file = sys.argv[3]
        torrent_file_path = sys.argv[4]
        index = int(sys.argv[5])
        decode_data = read_torrent(torrent_file_path,print_flag=0)
        peer_info = discover_peer(decode_data,flag=0)
        info_hash = get_info_hash(decode_data[b'info'])
        #print(f"Info Hash {info_hash}")
        socket_info = {}
        socket_info['requested_index'] = None
        pices_data = None
        have_pices = None
        for i in peer_info:
            socket_info["port"] = peer_info[i]
            socket_info["host"] = i
            socket_info["peer_id"] = decode_data[b'peer_id']
            socket_info['info_hash'] = info_hash
            socket_info["requested_index"] = index
            pices_data,have_pices = peer_tcp(socket_info,decode_data,download=1,print_flag=0)
            break

        with open(output_file,'wb') as f:
            if pices_data[index]:
                f.write(pices_data[index])
    else: 
        raise NotImplementedError(f"Unknown command {command}")



if __name__ == "__main__":
    main()

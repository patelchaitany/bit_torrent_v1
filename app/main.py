import json
import sys
from typing import Dict, List
import hashlib
# import bencodepy #- available if you need it!
import requests  # - available if you need it!
import os
import urllib.parse
import socket
import struct
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
        with open(file_path,"rb") as f:
            data = f.read()
        
        decoded_data,_ = decode_bencode(data)
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
def discover_peer(bedecoded_value):
    info = bedecoded_value[b'info']
    url = str(bedecoded_value[b'announce'],encoding="latin-1")
    encoded_info = bencode(info)
    hash_obj = hashlib.sha1(encoded_info)
    info_hash = hash_obj.digest()
    uploaded = 0
    downloaded = 0
    port = 6881
    left = int(bedecoded_value[b'info'][b'length'])
    compact = 1
    
    peer_id = os.urandom(10)
    peer_id = peer_id.hex()
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
        for i in port_ip:
            print(f"{i}:{port_ip[i]}")
    except Exception as e:
        raise ValueError(f"{e}")
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
    else:
        raise NotImplementedError(f"Unknown command {command}")



if __name__ == "__main__":
    main()

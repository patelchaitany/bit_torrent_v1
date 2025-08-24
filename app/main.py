import json
import re
import sys
import asyncio
from typing import Dict, List, _type_repr
import hashlib
# import bencodepy #- available if you need it!
import requests  # - available if you need it!
import os
import urllib.parse
import socket
import math
from collections import defaultdict
import urllib.parse
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
def discover_peer(bedecoded_value,flag = 1,torrent = 0):
    
    url = str(bedecoded_value[b'announce'],encoding="latin-1")

    info = bedecoded_value[b'info']
    info_hash = info
    if torrent == 0 :
        info_hash = get_info_hash(info)

    uploaded = 0
    downloaded = 0
    port = 6881
    left = 999
    if torrent == 0:
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
def read_message(message):
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
        "piece_index":None,
        "message_type":message_type,
        "message_id" : None,
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
    elif message_type == 20:
        message_return["message_id"] = int.from_bytes(payload[0:1])
        message_return["payload"] = payload[1:]
        

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

def is_bit_set(bytearray_data, bit_index):
    byte_index = bit_index // 8
    bit_position = bit_index % 8
    return (bytearray_data[byte_index] & (1 << (7 - bit_position))) != 0
def recv(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))

    while len(message)<int.from_bytes(length):
        message = message + s.recv(int.from_bytes(length) - len(message))
    
    return length + message

async def recv_async(reader):
    # Read 4-byte length prefix
    length_bytes = await reader.read(4)
    while len(length_bytes) < 4:
        more = await reader.read(4 - len(length_bytes))
        length_bytes += more
    
    if len(length_bytes) < 4:
        raise ConnectionError("Connection closed before receiving length")
    length = int.from_bytes(length_bytes, byteorder='big')

    # Read the message payload
    message = b""
    while len(message) < length:
        chunk = await reader.read(length - len(message))
        message += chunk
    if len(message)<length:
        raise ConnectionError("Connection closed before receiving length")
    return length_bytes + message

class PieceManager:
    def __init__(self,num_pieces):
        
        self.needed_pieces = set()
        self.lock = asyncio.Lock()
        if isinstance(num_pieces,List):
            for i in num_pieces:
                self.needed_pieces.add(i)
        elif isinstance(num_pieces,int):
            self.needed_pieces = set(range(num_pieces))
        else:
            raise NotImplemented("currently this function is not implemented")

    async def get_piece_for_peer(self,have_pieces):
        async with self.lock:
            for idx in list(self.needed_pieces):
                if is_bit_set(have_pieces,idx):
                    self.needed_pieces.remove(idx)
                    return idx
        return None
    
    async def mark_failed(self,idx):
        async with self.lock:
            self.needed_pieces.add(idx)

    def get_size(self):
        return len(self.needed_pieces)


async def perform_handshke(writer,reader,socket_info,handshake_type = 0):
    info_hash = socket_info["info_hash"]
    peer_id = socket_info["peer_id"]
    protocol_bit = 8*b"\x00"
    if handshake_type == 1:
        protocol_bit = 5*b"\x00" + b"\x10" + 2*b"\x00"
    protocol = b"\x13" + b"BitTorrent protocol" + protocol_bit + info_hash + peer_id

    writer.write(protocol)
    await writer.drain()

    resp= await reader.read(68)
    return resp


async def request_piece(reader,writer,index,decode_data,next_message,have_pieces):

    pices_hash = {}
    num_pieces = math.ceil(len(decode_data[b'info'][b'pieces']) / 20)
    piece_length = decode_data[b'info'][b'piece length']
    total_length_file = decode_data[b'info'][b'length']
    
    host = decode_data[b'host'] 
    port = decode_data[b'port']
    request_info = {"begin": 0, "length": 0, "index": 0}
    request_info["length"] = min(16*1024, piece_length)  # 16KB blocks
    request_info['index'] = index
    request_info['begin'] = 0
     
    if index == num_pieces - 1:
        total_length = total_length_file % piece_length
    else:
        total_length = piece_length
     
    while total_length > 0:
        writer.write(next_message['payload'])
        await writer.drain()
        
        new_message = await recv_async(reader)
        next_message = read_message(new_message)
        #print(f"\n {index} {30*"-"} \n from while {host} : {port} \n message type : {next_message['message_type']} \n {30*"-"}\n")
        if next_message['stop']:
            break
        if next_message['have_idx']:
            set_piece(have_pieces, int.from_bytes(next_message['have_idx'], byteorder="big"))
        if next_message['data']:
            data = next_message['data']
            if index in pices_hash:
                pices_hash[index] += data
            else:
                pices_hash[index] = data

            request_info['begin'] += len(data)
            total_length -= len(data)
            request_info['length'] = min(16*1024, total_length)
            
        next_message = payload_create(request_info, next_message, stage=1)
    #print(f"{index} I am returning from this {host} : {port}") 
    return pices_hash



async def negociate_handshake(writer,reader,socket_info,handshake_type = 0):
    resp = await perform_handshke(writer,reader,socket_info,handshake_type= handshake_type)
    
    if len(resp) < 68:
        return None,None
    
    decoded_protocol = decode_torrent_protocol(resp)
    #print(f"decode protocol {decoded_protocol}") 
    supprt_extention = (decoded_protocol["function_byte"][5] & 0x10)!=0
    
    ut_metadata_id = None

    if "send_bitfield" in socket_info:
        bitfield_payload = b"\x05" + socket_info["send_bitfield"]
        message_legth = len(bitfield_payload).to_bytes(4,byteorder="big")
        bitfield_payload = message_legth + bitfield_payload
        writer.writer(message_legth)
        await writer.drain()

    resp_bitfield = await recv_async(reader)
    resp_bitfield = read_message(resp_bitfield)
    resp_handshake = None
    if supprt_extention:
        handshake_dict = {b"m":{b"ut_metadata" : 1 }}
        handshake_encoded = bencode(handshake_dict)
        message_id = b"\x14"
        payload_send = message_id + b"\x00" + handshake_encoded
        length = len(payload_send)
        length = length.to_bytes(4,"big")
        payload_send = length + payload_send
        
        writer.write(payload_send)
        await writer.drain()

        resp_handshake = await recv_async(reader)

        resp_handshake = read_message(resp_handshake)
        #print(f"extended handshake {decode_bencode(resp_handshake['payload'])}")

    if resp_handshake:
        resp_bitfield["message_id"] = resp_handshake["message_id"]
        resp_bitfield["payload"] = resp_handshake["payload"]

    return decoded_protocol,resp_bitfield

async def peer_tcp_async(socket_info, decode_data,piece_manager,data_buffer,handshake_type=0):
    host = socket_info["host"]
    port = socket_info["port"]
    index = None
    request_info = {"begin": 0, "length": 0, "index": 0}
    pices_hash = {}
    state = 0
    try:
        reader, writer = await asyncio.open_connection(host, port)
        
        peer_info,next_message = await negociate_handshake(writer,reader,socket_info,handshake_type)

        print(f"Peer Info {peer_info}")
        if peer_info is None or next_message is None:
            writer.close()
            await writer.wait_closed()
            #print(f"closed Due to peer Handshake Failded")
            return None
        if peer_info['length'] == 0:
            writer.close()
            await writer.wait_closed()
            #print(f"closed Due to peer Handshake Failded")
            return None
        
        #print(f"Bit Field {bitfield_message}")

        next_message = payload_create(request_info, next_message, stage=state)
        
        num_pieces = math.ceil(len(decode_data[b'info'][b'pieces']) / 20)
        have_pieces = bytearray(math.ceil(num_pieces / 8))
        have_pieces = bytearray(next_message['have_pices'])
        decode_data[b'host'] = host
        decode_data[b'port'] = port
        index = await piece_manager.get_piece_for_peer(have_pieces)

        #print(f"\n {index} from outside {host} : {port} message type : {next_message['message_type']} \n")

        if index is None:
            not_interested = (1).to_bytes(4, "big") + b"\x03"
            writer.write(not_interested)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return None 
        while True:
            next_message = payload_create(request_info,next_message,stage = state)

            #print(f"\n {index} from inside {host} : {port} message type : {next_message['message_type']} \n")
            #print(f"going to retrive next pay load")
            pices_hash = await request_piece(reader,writer,index,decode_data,next_message,have_pieces) 
            data_buffer[index] = pices_hash[index]
            #print(f"waiting for the next payload ")
            if hash_comp(data_buffer[index], decode_data[b'info'][b'pieces'][20*index:20*(index+1)]) == 0:
                await piece_manager.mark_failed(index)
            index = await piece_manager.get_piece_for_peer(have_pieces)
            if index is None:
                break
            state = 1
        not_interested = (1).to_bytes(4, "big") + b"\x03"
        writer.write(not_interested)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        # Verify has
        return pices_hash

    except Exception as e:
        print(f"{index} Error connecting to {host}:{port} -> {e}")
        if index:
            await piece_manager.mark_failed(index)
        return None


async def download_whole_file_async(peer_info, decode_data,index = None, timeout=60):
    num_pieces = math.ceil(len(decode_data[b'info'][b'pieces']) / 20)
    info_hash = get_info_hash(decode_data[b'info'])
    current_have = bytearray(num_pieces * b'\x00')
    data_buffer = {}
    socket_info = {
            "info_hash" : info_hash,
            "peer_id" : decode_data[b'peer_id']
        }
    piece_manager = PieceManager(num_pieces)
    if index is not None:
        piece_manager = PieceManager([index])
    task = []
    #print(f"peer Info :\n {peer_info}")
    print(f"num_pieces {num_pieces}")
    while True:
        for host, port in peer_info.items():
            socket_info_copy = {
                "host": host,
                "port": port,
                "peer_id": decode_data[b'peer_id'],
                "info_hash": info_hash,
            }
            task.append(asyncio.create_task(
                peer_tcp_async(socket_info_copy, decode_data, piece_manager, data_buffer)
            ))
        
        result = await asyncio.gather(*task)
        if piece_manager.get_size() == 0:
            break
        
        #result = await peer_tcp_async(socket_info,decode_data,piece_manager,data_buffer)
        #if result:
         #   print(f"got result")

    return data_buffer

def parse_magnet_link(magnet_link):
    info_hash_location = magnet_link.find("btih:") + 5
    info_hash = magnet_link[info_hash_location : info_hash_location + 40]
    url_location = magnet_link.find("tr=") + 3
    url = magnet_link[url_location:]
    return info_hash,url

def get_decode_style(magnet_link,info_hash):
    bencoded_value = {}
    bencoded_value[b'info'] = bytes.fromhex(info_hash)
    bencoded_value[b'announce'] = urllib.parse.unquote(magnet_link).encode("latin-1")
    bencoded_value[b'peer_id'] = os.urandom(20)
    return bencoded_value
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
        

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        reader, writer = loop.run_until_complete(asyncio.open_connection(ip_addr, port))
        resp = loop.run_until_complete(perform_handshke(writer, reader, socket_info))
        loop.close()
        peer_info = decode_torrent_protocol(resp)
        print(f"Peer ID: {peer_info["peer_id"].hex()}")
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
            #print(f"socket Info \n {socket_info}")
            pices_data = asyncio.run(download_whole_file_async(peer_info,decode_data,index = index))
            break
        #print(f"piece info {pices_data}")
        if pices_data:
            with open(output_file,'wb') as f:
                if pices_data[index]:
                    f.write(pices_data[index])
    elif command == "download":
        output_file = ""
        if sys.argv[2] == "-o":
            output_file = sys.argv[3]
        torrent_file_path = sys.argv[4]
        decode_data = read_torrent(torrent_file_path,print_flag=0)
        peer_info = discover_peer(decode_data,flag=0)
        result = asyncio.run(download_whole_file_async(peer_info,decode_data))

        if result:
            with open(output_file,'wb') as f:
                for i in result:
                    print(f"piece {i}")
                    f.write(result[i])
    elif command == "magnet_parse":
        magnet_link = sys.argv[2]
        info_hash,url = parse_magnet_link(magnet_link)
        print(f"Tracker URL: {urllib.parse.unquote(url)}")
        print(f"Info Hash: {info_hash}")
    elif command == "magnet_handshake":
        magnet_link = sys.argv[2]
        info_hash,url = parse_magnet_link(magnet_link)
        bencoded_value = get_decode_style(url,info_hash)
        peer_info = discover_peer(bencoded_value,torrent=1,flag=0)
        socket_info = {
            "info_hash":bencoded_value[b'info'],
            "peer_id":bencoded_value[b'peer_id']
        }
        for i in peer_info:
            socket_info["host"] = i
            socket_info["port"] = peer_info[i]

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            reader, writer = loop.run_until_complete(asyncio.open_connection(i,peer_info[i]))
            peer_info_new,bitfield = loop.run_until_complete(negociate_handshake(writer, reader, socket_info,handshake_type=1))
            loop.close()
            if peer_info_new is None:
                print(f"Peer Info is not abel to find")
            else :
                #print(f"bitfield {bitfield}")
                decoded_bitfield,_ = decode_bencode(bitfield['payload'])
                print(f"Peer ID: {peer_info_new["peer_id"].hex()}")
                print(f"Peer Metadata Extension ID : {decoded_bitfield[b'm'][b'ut_metadata']}")
    else: 
        raise NotImplementedError(f"Unknown command {command}")



if __name__ == "__main__":
    main()

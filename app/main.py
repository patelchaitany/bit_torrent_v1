import json
import re
import sys
import asyncio
from typing import Dict, List, _type_repr
import hashlib
import struct
# import bencodepy #- available if you need it!
import requests  # - available if you need it!
import os
import urllib.parse
import socket
import math
from collections import defaultdict
import urllib.parse
import time
import random
import traceback
import inspect
import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
import asyncio

bytes_in = 0
bytes_out = 0

executor = ThreadPoolExecutor(max_workers=20)
def log(*args, level="INFO", **kwargs):
    """
    Custom logging function that shows timestamp, level,
    caller function, filename, and line number.
    """
    # Get caller info
    frame = inspect.stack()[1]
    caller_func = frame.function
    line_no = frame.lineno
    filename = frame.filename.split("/")[-1]  # only filename, not full path

    # Timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Format log message
    prefix = f"[{caller_func}|{line_no}]"
    # if level == "Status" or level == "Error" or level == "Warning": #or level == "INFO":
    #     #print(prefix, "-", *args, **kwargs)
    #print(prefix, "-", *args, **kwargs)
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
        # print(decoded_data[b'info'])
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
            #print(f"Piece Hashes: \n{"\n".join([piece_hex[i:i+40] for i in range(0,len(piece_hex),40)])}")
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
    if isinstance(peer_bytes,list):
        for i in peer_bytes:
            ip_byte = str(i[b'ip'],encoding="latin-1")
            port = i[b'port']
            ip_port[ip_byte] = port
        return ip_port
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

    url_list = [str(bedecoded_value[b'announce'],encoding="latin-1")]
    if b'announce-list' in bedecoded_value:
        print(f"becoded value {bedecoded_value[b'announce-list']}")
        for url in bedecoded_value[b'announce-list']:
            if isinstance(url,list):
                for i in url:
                    url_list.append(str(i,encoding="latin-1"))
            else:
                url_list.append(str(url,encoding="latin-1"))
    return_peer_ip = {}
    try:
        for url in url_list:

            print(f"trying url {url}")
            if url.startswith("http://") or url.startswith("https://"):
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

                response = requests.get(url = url,params= params)
                decoded_responce,_ = decode_bencode(response.content)
                log(decoded_responce)
                port_ip = peer_decoding(decoded_responce[b'peers'])
                for i in port_ip:
                    if i not in return_peer_ip:
                        return_peer_ip[i] = port_ip[i]
                    if flag:
                        log(f"{i}:{port_ip[i]}")

        return return_peer_ip
    except Exception as e:
        # capture the full traceback as a string
        trace_str = traceback.format_exc()

        # store it in a local variable
        last_traceback = trace_str
        raise ValueError(f"{e}")

def decode_torrent_protocol(data):
   # print(f"decode_torrent_protocol {data}")
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
    log(f"request_info {request_info}")
    payload_next = b''
    # state 1 is for intrested and state 2 for the request
    if stage == 1:
        payload_next = b'\x00\x00\x00\01'
        payload_next = payload_next + b'\x02'
        message_return['payload'] = payload_next
    elif stage == 2:
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

def decode_metadata(data):
    
    #print(f"\033[92mdecode_metadata {data}\033[0m")
    if data is None:
        return None,None
    decode_data,index = decode_bencode(data)
    meta_data = None
    if decode_data[b'msg_type'] == 1:
        meta_data = data[index:]
    return decode_data,meta_data
def read_message(message):
    message_legth = int.from_bytes(message[0:4],byteorder="big")
    message_type = int.from_bytes(message[4:5])
    payload = message[5:]
    log(f"messgae Length {message_legth} {message_type}")
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
        # print(f"\033[92mextended message {payload}\033[0m")
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
async def recv_async(reader,flag = 0):
    # Read 4-byte length prefix
    if flag == 0:
        log(f"trying to read _buffer {len(reader._buffer)} {reader.at_eof()}")
        length_bytes = await reader.readexactly(4)

        if len(length_bytes) < 4:
            raise ConnectionError("Connection closed before receiving length")
        length = int.from_bytes(length_bytes, byteorder='big')
        log(f"messgae Len {length}")
    # Read the message payload
        message = b""
        
        chunk = await reader.readexactly(length - len(message))
        message += chunk
        log(f"chunk len {len(message)}")
        if len(message)<length:
            raise ConnectionError("Connection closed before receiving length")

        log(f"returens the readed message bytes")
        return length_bytes + message

    if flag == 1:
        log(f"trying to read _buffer {len(reader._buffer)} {reader.at_eof()}")
        if not reader._buffer:
            log(f"no data")
            return None
        length_bytes = await reader.readexactly(4)
        length = int.from_bytes(length_bytes, "big")
        log(f"message Len {length}")

        if length == 0:
            return length_bytes  # keepalive

        message = await reader.readexactly(length)
        log(f"returens the readed message bytes")
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
class Peer:
    def __init__(self,peer_info,manager):
        self.host = peer_info['host']
        self.port = peer_info['port']
        self.socket_info = peer_info
        self.reader : asyncio.StreamReader | None = None
        self.writer : asyncio.StreamWriter | None = None
        self.num_pieces = peer_info['num_pieces']
        self.have_pieces = bytearray(math.ceil(self.num_pieces/8)*b"\x00")
        self.peer_id = None
        self.handshake_type = peer_info["handshake_type"]
        self.state = 0
        self.intrested = 0
        self.data_map = {}
        self.last_keepalive = time.time()
        self.throughput = -float('inf')
        self.manager : PeerManager= manager
        self.piece_event = {}
        self.writer_lock =asyncio.Lock()
        self.reader_lock = asyncio.Lock()
        self.chocke = asyncio.Event()
        self.block_queues: dict[int, asyncio.Queue] = defaultdict(asyncio.Queue)
        log(f"object is created {self.__repr__()}")
        self.can_process = 3
        # state = 0 : intial state
        # state = 1 : ready to send intrested message
        # state = 2 : unchocked and ready to send piece request
        # state = 3 : chocked

    async def start(self):
        log(f"Peer.start() called for {self.host}:{self.port}")
        try:
            await self._setup()
            log(f"Peer._setup() completed for {self.host}:{self.port}")
        except Exception as e:
            trace_str = traceback.format_exc()

            # store it in a local variable
            last_traceback = trace_str
            log(f"Error in Peer.start() for {self.host}:{self.port}: {last_traceback}",level="Error")
            self.manager.remove_peer(self)
            # traceback.print_exc()
    def __repr__(self) -> str:
        return f"host : {self.host} port : {self.port} peer_id : {self.peer_id} {self.state}"
    async def _setup(self):
        try:

            log(f"shake is ongoing {self.__repr__()}")
            self.reader , self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=60)
            if self.reader is None or self.writer is None:
                self.manager.remove_peer(self)
                log(f"{self.__repr__()} peer have zero writer and zero reader")

            async with self.reader_lock:
                async with self.writer_lock:
                    decoded_info,resp_bitfield = await negociate_handshake(self.writer,self.reader,self.socket_info,handshake_type= self.handshake_type)
            if decoded_info:
                self.peer_id = decoded_info['peer_id']
                if self.socket_info['info_hash'] != decoded_info['info_hash']:
                    log(f"The info hash did not matched",level="Warning")
                    self.state = -1
                    self.manager.remove_peer(self)
                    return
            if resp_bitfield:
                if resp_bitfield['have_pices']:
                    log(f"resp bitfiel {resp_bitfield.keys()}")
                    self.have_pieces = bytearray(resp_bitfield['have_pices'])

            if self.peer_id is None:
                log(f"peer_id is None")
                self.manager.remove_peer(self)
                return
            self.state = 1
            asyncio.create_task(self.reader_loop())
            #asyncio.run_coroutine_threadsafe(self.reader_loop(),Peer._loop)
            log(f"shake is succssfull {self.__repr__()}")
        except Exception as e:
            self.manager.remove_peer(self)
            trace_str = traceback.format_exc()

            # store it in a local variable
            last_traceback = trace_str
            log(f"[{self.__repr__()}]Failed To cnnect -> {self.host} {self.port} {last_traceback}",level="Error")

    async def reader_loop(self):

        log(f"reader loop")
        while True:
            try:
                log(f"reader indide form while {self.__repr__()}")
                start_time = time.time()
                bytes_received = 0
                async with self.reader_lock:
                    raw_msg = await recv_async(self.reader)
                
                if raw_msg == None:
                    log(f"the raw_msg is None {self.__repr__()}")
                    await asyncio.sleep(0.1)
                    continue
                log(f"[{self.__repr__()}] print the raw msg {len(raw_msg)}")
                bytes_received += len(raw_msg)
                elapsed = time.time() - start_time
                self.throughput = bytes_received / elapsed if elapsed > 0 else 0  # bytes per second


                message = read_message(raw_msg)
                print(f"\033[94mmessage received {message['message_type']} {self.__repr__()}\033[0m")
                if message['stop'] == 1 or self.state == 3:
                    if message['stop'] == 0:
                        self.state = 2
                        self.chocke.set()
                    if message['stop'] == 1:
                        self.state = 3
                        self.chocke.clear()
                if message['stop'] == 0:
                    self.state = 2
                    self.chocke.set()
                if message['message_type'] == 7:
                    #print(f"\033[92mdata message received {self.__repr__()} {message['piece_index']} {message['begin_index']}\033[0m")
                    piece_key = (message['piece_index'],int.from_bytes(message['begin_index']))
                    if message['piece_index'] in self.block_queues:
                        self.data_map[piece_key] = message['data']
                        self.block_queues[message['piece_index']].put_nowait(piece_key)
                    if piece_key in self.piece_event:
                        event = self.piece_event.pop(piece_key) # Pop to clean up
                        event.set() #
                if message['message_type'] == 4:
                    log(f"\03392m have message received {self.__repr__()} {int.from_bytes(message['have_idx'],byteorder='big')}\033[0m")
                    set_piece(self.have_pieces,int.from_bytes(message['have_idx'],byteorder="big"))
                if message['message_type'] == 5:
                    self.have_pieces = bytearray(message['have_pices'])
                if message['message_type'] == 20:
                    payload = decode_bencode(message['payload'])
                    if message['message_id'] == 2:
                        self.manager.add_peer_pex(message['payload'])
                    # print(f"{30*'='}")
                    # print(f"\n\n\n")
                    # print(f"\033[92mextended message received {message['message_id']} \033[0m")
                    # print(f"\033[92mextended message received {payload} \033[0m")
                    # print(f"\n\n\n")
                    # print(f"{30*'='}")
                    # print(f"\n\n\n")
                log(f"[Peer {self.host}:{self.port} {self.state}] Downloaded {bytes_received} bytes in "
                f"{elapsed:.2f} sec → Throughput: {self.throughput/1024:.2f} {message['begin_index']} {message['piece_index']} KB/s")
                # await asyncio.sleep(0.1)
            except Exception as e:
                self.manager.remove_peer(self)
                trace_str = traceback.format_exc()

                # store it in a local variable
                last_traceback = trace_str
                log(f"peer {self} disconnected {last_traceback}",level="Error")
                self.manager.remove_peer(self)
                break

            await asyncio.sleep(0.1)

    async def send_msg(self,payload = None):
        global bytes_out
        if payload is None:  # keepalive
            payload = (0).to_bytes(4, "big")
            
        try:
        # Lock was acquired
            async with self.writer_lock:
                log(f"[{self.__repr__()}]>> Lock acquired! {payload}")
                self.writer.write(payload)
                await self.writer.drain()
                bytes_out += len(payload)
                return 1
        except Exception as e:
            trace_str = traceback.format_exc()
            last_traceback = trace_str
            log(f"[{self}] an Exception is occurred {last_traceback}",level="Error")
            self.manager.remove_peer(self)
            return 0

    async def request_piece(self,decoded_data,index,parallel = 1):
        self.can_process = self.can_process - 1
        # self.block_queue = asyncio.Queue()
        pices_hash = {}
        num_pieces = math.ceil(len(decoded_data[b'info'][b'pieces'])/20)
        piece_length = decoded_data[b'info'][b'piece length']
        total_length_file = decoded_data[b'info'][b'length']
        
        total_length = piece_length
        if index == num_pieces - 1:
            total_length = total_length_file % piece_length
        byte_message = bytearray(total_length*b"\x00")
        request_info = {"begin": 0, "length": 0, "index": 0}
        request_info["length"] = min(16*1024, total_length)  # 16KB blocks
        request_info['index'] = index
        request_info['begin'] = 0
        next_message = {}
        next_message = payload_create(request_info,next_message,stage= self.state)

        if self.state == 1:
            log(f"[{self.__repr__()}]sending the intreseted messgae {total_length}")
            await self.send_msg(next_message['payload'])

        next_message = payload_create(request_info,next_message,self.state)
        request_piece = []
        try:
            while total_length>0:
                print(f"\033[93mrequest_piece FOR: {request_piece} {total_length}\033[0m")
                while len(request_piece) < parallel and total_length > 0:
                    temp_request_info = request_info.copy()
                    log(f"[{self.__repr__()}]waiting for being unchocked")
                    if self.state == 3 or self.state == 1:
                        await self.chocke.wait()
                    #await asyncio.sleep(0.1)
                    log(f"inside while loop {temp_request_info}")
                    next_message = payload_create(temp_request_info,next_message,self.state)
                    await self.send_msg(next_message['payload'])
                    log(f"the payload is written {next_message['payload']}")
                    piece_key = (index,temp_request_info['begin'])
                    request_piece.append(piece_key)
                    #print(f"\033[96m [{self}] requested piece {piece_key} total length remaining {total_length}\033[0m")
                    # if piece_key not in self.data_map:
                    #     if piece_key not in self.piece_event:
                    #         self.piece_event[piece_key] = asyncio.Event()
                    #     event = self.piece_event[piece_key]
                    #     log(f"Payload sent, now waiting for piece: {piece_key}")
                    #     await event.wait()
                    #     log(f"Event received! Data has arrived for piece: {piece_key}")
                    print(f"\033[93m [{self.__repr__()}]request_piece Inside: {request_piece} {total_length} {self.block_queues} {request_info}\033[0m")
                    request_info['begin'] += min(16*1024, total_length)
                    total_length -= min(16*1024, total_length)
                    request_info['length'] = min(16*1024, total_length)
                    await asyncio.sleep(0.2)
                    
                    
                    
                for piece_key in list(request_piece):
                    try:
                        if index not in self.block_queues:
                            self.block_queues[index] = asyncio.Queue()

                        piece_key_request = await asyncio.wait_for(self.block_queues[index].get(), timeout=30)
                        data = self.data_map.pop(piece_key_request)
                        _,begin = piece_key_request
                        byte_message[begin:begin+len(data)] = data
                        request_piece.remove(piece_key_request)
                    except Exception as e:
                        # self.manager.remove_peer(self)
                        if index in self.block_queues:
                            del self.block_queues[index]
                        traceback.print_exc()
                        trace_str = traceback.format_exc()
                        last_traceback = trace_str
                        self.can_process = self.can_process + 1
                        log(f"[{self.__repr__()}] {last_traceback}",level="Error")
                        return None
                        
            print(f"\033[93mrequest_piece outside: {request_piece} {total_length}\033[0m")
            for piece_key in list(request_piece):
                try:
                    if index not in self.block_queues:
                        self.block_queues[index] = asyncio.Queue()
                    piece_key_request = await asyncio.wait_for(self.block_queues[index].get(), timeout=30)
                    data = self.data_map.pop(piece_key_request)
                    _,begin = piece_key_request
                    byte_message[begin:begin+len(data)] = data
                    request_piece.remove(piece_key_request)
                except Exception as e:
                    traceback.print_exc()
                    trace_str = traceback.format_exc()
                    last_traceback = trace_str
                    if index in self.block_queues:
                        del self.block_queues[index]
                    self.can_process = self.can_process + 1
                    log(f"[{self.__repr__()}] {last_traceback}",level="Error")
                    return None
                
            if index not in pices_hash:
                pices_hash[index] = b""
                pices_hash[index] += byte_message
                if index in self.block_queues:
                    del self.block_queues[index]
            print(f"\033[92mcompleted downloading the piece {index} from peer {self.__repr__()}\033[0m")
            self.can_process = self.can_process + 1
            return pices_hash
        except Exception as e:
            traceback.print_exc()
            trace_str = traceback.format_exc()
            last_traceback = trace_str
            if index in self.block_queues:
                del self.block_queues[index]
            self.can_process = self.can_process + 1
            log(f"[{self.__repr__()}] {last_traceback}",level="Error")
            return None

def peer_sort_key(peer):
    return (-peer.throughput, not peer.intrested)

class PeerManager:

    def __init__(self,decode_data = None):
        self.peer = []
        self.not_connected = []
        self.unchocked_list = []
        self.decode_data = decode_data
        self.connected_peers = 0
        self.connected_peers_list = []
        self.seeder = 0
        self.leacher = 0
        self.num_pieces = math.ceil(len(decode_data[b'info'][b'pieces']) / 20)
        #asyncio.create_task(self.keep_alive_loop())
        self.info_hash = get_info_hash(decode_data[b'info'])
    def add_peer_pex(self,payload):
        peer_info,_ = decode_bencode(payload)
        if b'added' in peer_info:
            for i in range(0,len(peer_info[b'added']),6):
                ip_byte = peer_info[b'added'][i:i+4]
                port_byte = peer_info[b'added'][i+4:i+6]
                ip_addr = socket.inet_ntoa(ip_byte)
                port = int.from_bytes(port_byte,"big")
                #print(f"\033[94madded {ip_addr}:{port}\033[0m")
                if b'added.f' in peer_info:
                    if peer_info[b'added.f'][i//6]&0x02:
                        self.seeder += 1   
                    else:
                        self.leacher += 1
                self.not_connected.append({"host":ip_addr,"port":port})

    def add_peer(self, socket_info):
        peer = Peer(socket_info, self)
        self.peer.append(peer)
        asyncio.create_task(peer.start())
        self.connected_peers += 1
        self.connected_peers_list.append({"host":socket_info['host'],"port":socket_info['port']})
    def remove_peer(self,peer):
        if peer in self.peer:
            print(f"\033[97mremoving peer {peer}\033[0m")
            try :
                peer.writer.close()
            except:
                trace_str = traceback.format_exc()
                last_traceback = trace_str
                log(f"[{peer.__repr__()}] error in cloasing peer {last_traceback}",level="Error")
            finally:
                #print(f"\033[97mremoving peer {peer}\033[0m")
                self.peer.remove(peer)
                if self.unchocked_list:
                    if peer in self.unchocked_list:
                        self.unchocked_list.remove(peer)
                #self.not_connected.append(peer.socket_info)
                self.connected_peers -= 1
                self.connected_peers_list.remove({"host":peer.host,"port":peer.port})
                del peer

    async def keep_alive_loop(self):
        while True:
            now = time.time()
            for peer in list(self.peer):
                log(f"sending keep keep_alive_loop {peer}")
                if peer.writer and now - peer.last_keepalive > 100:
                    await peer.send_msg(None)
    
    async def chek_alive(self,peer):
        if peer.writer is None:
            self.remove_peer(peer)
        try:
            res = await peer.send_msg()
            return res
        except Exception as e:
            self.remove_peer(peer)
            trace_str = traceback.format_exc()
            last_traceback = trace_str
            log(f"[{peer.__repr__()}] error in cheking alive {last_traceback}",level="Error")
            return 0

    async def choke(self):
        while True:
            print(f"\033[94mchoke loop started {self.connected_peers_list}\033[0m")
            for i in list(self.peer):
                if i.peer_id is None:
                    self.remove_peer(i)
            sortes = sorted(self.peer,key = peer_sort_key)
            global bytes_in,bytes_out
            
            print(f"\033[92mDownloaded: {bytes_in/1024:.2f} KB, Uploaded: {bytes_out/1024:.2f} KB Leacher: {self.leacher} Seeder: {self.seeder}\033[0m ")
            top_peers = sortes[:min(len(sortes),len(sortes))]
            chocked = b"\x00\x00\x00\x01\x00"
            unchocked = b"\x00\x00\x00\x01\x01"
            remaining_peers = None
            if len(sortes) > len(sortes):
                remaining_peers = sortes[10:]
                selected_peer = random.choice(remaining_peers)
                top_peers.append(selected_peer)
                remaining_peers.remove(selected_peer)
            self.unchocked_list = top_peers
            print(f"\033[92mnumber of peer available from choke {len(self.unchocked_list)}\033[0m")
            for peer in self.peer:
                if peer not in top_peers:
                    await peer.send_msg(chocked)
                else:
                    await peer.send_msg(unchocked)
            if len(self.peer) < 50:
                for i in list(self.not_connected):
                    if len(self.peer) < 50:
                        print(f"\033[95madding peer {self.connected_peers} {i['host']}:{i['port']}\033[0m")
                        if i not in self.connected_peers_list:
                            socket_info = {
                                "host" : i['host'],
                                "port" : i['port'],
                                "num_pieces" : self.num_pieces,
                                "info_hash":self.info_hash,
                                'peer_id' : self.decode_data[b'peer_id'],
                                "handshake_type":0
                            }
                            self.add_peer(socket_info)
                            self.not_connected.remove(i)
                            # await asyncio.sleep(1)
            await asyncio.sleep(10)



class MetadataManger:

    def __init__(self,num_pieces):
        self.num_pieces = num_pieces
        self.pieces = {i: None for i in range(num_pieces)}
        self.lock = asyncio.Lock()

    async def get_next_missing(self):
        async with self.lock:
            for i,data in self.pieces.items():
                if data is None:
                    self.pieces[i] = b'get'
                    return i
        return None

    async def add_piece(self,index,data):
        async with self.lock:
            self.pieces[index] = data

    async def falied(self,index):
        async with self.lock:
            if self.pieces[index] == b'get':
                self.pieces[index] = None

    async def is_complete(self):
        async with self.lock:
            return all(v is not None for v in self.pieces.values())

    def assemble(self):
        return b''.join(self.pieces[i] for i in range(self.num_pieces))


async def perform_handshke(writer,reader,socket_info,handshake_type = 0):
    info_hash = socket_info["info_hash"]
    peer_id = socket_info["peer_id"]
    protocol_bit = 8*b"\x00"
    if handshake_type == 1:
        protocol_bit = 5*b"\x00" + b"\x10" + b"\x00" + b"\x04"
    #pstrlen + pstr + reserved + info_hash + peer_id
    # print(f"\033[92minfo_hash {type(info_hash)} {len(info_hash)}\033[0m")
    # print(f"\033[92mpeer_id {type(peer_id)} {len(peer_id)}\033[0m")
    # print(f"\033[92mprotocol_bit {type(protocol_bit)} {len(protocol_bit)}\033[0m")
    protocol = b"\x13" + b"BitTorrent protocol" + protocol_bit + info_hash + peer_id

    writer.write(protocol)
    await writer.drain()

    resp= await reader.read(68)
    return resp

async def negociate_handshake(writer,reader,socket_info,handshake_type = 0):
    try :
        resp = await perform_handshke(writer,reader,socket_info,handshake_type= handshake_type)
        if len(resp) < 68:
            return None,None

        
        decoded_protocol = decode_torrent_protocol(resp)
        supprt_extention = (decoded_protocol["function_byte"][5] & 0x10)!=0
        #print(f"responce from the peer {decoded_protocol}")
        ut_metadata_id = None

        if "send_bitfield" in socket_info:
            #print(f"Sending bitfield {socket_info['send_bitfield']}")
            bitfield_payload = b"\x05" + socket_info["send_bitfield"]
            message_legth = len(bitfield_payload).to_bytes(4,byteorder="big")
            bitfield_payload = message_legth + bitfield_payload
            #print(f"bitfield payload {bitfield_payload}")
            writer.write(bitfield_payload)
            await writer.drain()

        resp_bitfield = await recv_async(reader,flag=1)
        #log(f"responce bitfield {resp_bitfield}")
        if resp_bitfield:
            resp_bitfield = read_message(resp_bitfield)
        resp_handshake = None
        if supprt_extention:
            log(f"extended handshake")
            handshake_dict = {b"m":{b"ut_metadata" : 1 ,b"ut_pex" : 2},b"v":b"my_client"}
            handshake_encoded = bencode(handshake_dict)
            message_id = b"\x14"
            payload_send = message_id + b"\x00" + handshake_encoded
            length = len(payload_send)
            length_prefix = struct.pack(">I",len(payload_send))
            payload_send = length_prefix + payload_send

            writer.write(payload_send)
            await writer.drain()

            resp_handshake = await recv_async(reader,flag=1)
            if resp_handshake:
                log(f"responce handshake {resp_handshake}")
                resp_handshake = read_message(resp_handshake)
                log(f"responce handshake {resp_handshake}")
        #print(f"extended handshake {decode_bencode(resp_handshake['payload'])}")
        log(f"decoded_protocol {len(decoded_protocol)}")
        
        if resp_handshake:
            if resp_bitfield:
                resp_bitfield["message_id"] = resp_handshake["message_id"]
                resp_bitfield["payload"] = resp_handshake["payload"]

            else:
                resp_bitfield = resp_handshake
        return decoded_protocol,resp_bitfield
    except Exception as e:
        trace_str = traceback.format_exc()

        # store it in a local variable
        last_traceback = trace_str
        log(f"some error is occurred during handshake {last_traceback}",level="Error")
        return None,None

MAX_QUEUE = 100
BLOCK_TIMEOUT = 120  # seconds

async def worker(name, queue, peer_manager, piece_manager, decode_data, data_buffer):
    global bytes_in,bytes_out
    while True:
        peer, index = await queue.get()   # <- consumes one request
        try:
            res = await asyncio.wait_for(peer.request_piece(decode_data, index, parallel=3),
                                         timeout=BLOCK_TIMEOUT)

            if res is None:
                print(f"[{name}] Peer {peer} returned None")
                # peer_manager.remove_peer(peer)
                await piece_manager.mark_failed(index)
            else:
                for piece_index, piece_data in res.items():
                    if piece_index not in data_buffer:
                        data_buffer[piece_index] = piece_data
                    else:
                        data_buffer[piece_index] += piece_data  

                    hash_index = decode_data[b'info'][b'pieces'][20*piece_index:20*(piece_index+1)]
                    if hash_comp(data_buffer[piece_index], hash_index) == 0:
                        print(f"\033[91mpiece {piece_index} failed hash\033[0m")
                        del data_buffer[piece_index]
                        # peer_manager.remove_peer(peer)
                        await piece_manager.mark_failed(piece_index)
                    else:
                        bytes_in += len(piece_data)
                        print(f"\033[92mpiece {piece_index} verified\033[0m")

        except asyncio.TimeoutError:
            print(f"[{name}] Peer {peer} timed out on piece {index}")
            # peer_manager.remove_peer(peer)
            await piece_manager.mark_failed(index)
        except Exception as e:
            print(f"[{name}] Peer {peer} failed with error {e}")
            # peer_manager.remove_peer(peer)
            await piece_manager.mark_failed(index)
        finally:
            queue.task_done()

async def peer_tcp_async(decode_data,piece_manager:PieceManager,peer_manager:PeerManager,data_buffer,handshake_type=0):
    index = None
    request_info = {"begin": 0, "length": 0, "index": 0}
    pices_hash = {}
    queue = asyncio.Queue(maxsize=MAX_QUEUE)
    num_pieces = math.ceil(len(decode_data[b'info'][b'pieces'])/20)
    have_pieces = bytearray(num_pieces*b"\x00")
    state = 0

    global bytes_in,bytes_out
    workers = [asyncio.create_task(worker(f"W{i}", queue, peer_manager, piece_manager, decode_data, data_buffer))
               for i in range(MAX_QUEUE)]
    try:
        while piece_manager.get_size() > 0:
            for peer in list(peer_manager.unchocked_list):
                print(f"\033[92mchecking peer {peer}\033[0m")
                if peer.can_process <= 0:
                    print(f"\033[92mpeer busy {peer}\033[0m")
                    continue
                if await peer_manager.chek_alive(peer) == 0:
                    print(f"\033[92mpeer dead {peer}\033[0m")
                    continue
                if peer.state == 3:
                    print(f"\033[92mpeer choked {peer}\033[0m")
                    continue

                index = await piece_manager.get_piece_for_peer(peer.have_pieces)
                if index is None:
                    peer_manager.remove_peer(peer)
                    continue

                await queue.put((peer, index))
                await asyncio.sleep(0.1)   # enqueue one task
                print(f"Enqueued request: peer={peer}, piece={index}")

            await asyncio.sleep(20)

        # wait for all enqueued jobs to finish
        await queue.join()

    except Exception as e:
        log(f"{index} -> {e}",level="Error")
        traceback.print_exc()
        sys.exit(1)
        if index:
            await piece_manager.mark_failed(index)
        return None
    finally:
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    print("All pieces processed.")

   

async def get_meta_data(writer,reader,meta_id:int,messaghe_info,meta_manager:MetadataManger,host,port):

    while True:
        piece_index = await meta_manager.get_next_missing()
        log(f"index {piece_index} {host} {port} {meta_id}")
        if piece_index is None:
            break
        messaghe_info[b'piece'] = piece_index

        encoded_message = bencode(messaghe_info)
        print(f"encoded message {encoded_message}")
        payload = b"\x14" + meta_id.to_bytes(1,"big") + encoded_message
        payload = len(payload).to_bytes(4,byteorder="big") + payload
        meta_data = None
        if messaghe_info[b'msg_type'] == 0:
            log(f"requesting meta data {payload}")
            writer.write(payload)
            await writer.drain()

            resp = await recv_async(reader)
            log(f"responce from the peer {resp}")
            resp =read_message(resp)
            
            other_info,meta_data = decode_metadata(resp['payload'])

        if meta_data is None:
            await meta_manager.falied(piece_index)
        else:
            await meta_manager.add_piece(piece_index,meta_data)

async def meta_info_downloader(peer_info,socket_info):
    meta_manager = None
    async def download(host,port):
        nonlocal meta_manager
        reader,writer = await asyncio.open_connection(host=host,port=port)
        peer_info_new,bitfield = await negociate_handshake(writer,reader,socket_info,handshake_type=1)
        if bitfield['payload'] is None:
            return
        decode_meta_info ,_ = decode_bencode(bitfield['payload'])
        print(f"decode_meta_info {decode_meta_info}" )
        meta_id = decode_meta_info[b'm'][b'ut_metadata']
        meta_data_size = decode_meta_info[b'metadata_size']
        message_info = {
            b'msg_type':0,
            b'piece':0
        }
        if meta_manager is None:
            num_pieces = math.ceil(meta_data_size/16384)
            meta_manager = MetadataManger(num_pieces)

        while True:
            if meta_manager is not None:
                break

        await get_meta_data(writer,reader,meta_id,message_info,meta_manager,host,port)

        await writer.drain()
        writer.close()

    task = []

    for i in peer_info:
        task.append(asyncio.create_task(download(i,peer_info[i])))

    await asyncio.gather(*task)

    if meta_manager:
        decoded_meta_data,_ = decode_bencode(meta_manager.assemble())
        calculated_info_hash= get_info_hash(decoded_meta_data)
        if calculated_info_hash == socket_info['info_hash']:
            log(decoded_meta_data)
            return decoded_meta_data
        else:
            log(f"it dose not matched ")
            return None
async def download_whole_file_async(peer_info, decode_data,index = None,handshake_type = 0):
    start_time = time.time()
    print(decode_data.keys())
    num_pieces = math.ceil(len(decode_data[b'info'][b'pieces']) / 20)
    info_hash = get_info_hash(decode_data[b'info'])
    current_have = bytearray(math.ceil(num_pieces/8) * b'\x00')
    data_buffer = {}
    socket_info = {
            "info_hash" : info_hash,
            "peer_id" : decode_data[b'peer_id']
        }
    piece_manager = PieceManager(num_pieces)
    if index is not None:
        piece_manager = PieceManager([index])
    peer_manager = PeerManager(decode_data = decode_data)
    task = []
    print(f"peer Info :\n {peer_info} {len(peer_info)}")
    print(30*"\n")
    log(f"num_pieces {num_pieces}")
    for i in peer_info:
        print(f"\033[93madding peer {i} {peer_info[i]} {info_hash}\033[0m")
        socket_info = {
            "host" : i,
            "port" : peer_info[i],
            "num_pieces" : num_pieces,
            "info_hash":info_hash,
            'peer_id' : decode_data[b'peer_id'],
            "handshake_type":handshake_type,
            "send_bitfield":current_have
        }
        peer_manager.add_peer(socket_info)
        await asyncio.sleep(1)
        # if isinstance(index,int):
        #     break
    
    asyncio.create_task(peer_manager.choke())
    await asyncio.sleep(10)
    result = await peer_tcp_async(decode_data,piece_manager,peer_manager,data_buffer)

        #result = await peer_tcp_async(socket_info,decode_data,piece_manager,data_buffer)
    complet_time = - start_time + time.time()
    log(f"got result {complet_time}")

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

def parse_ip_port(address_string: str) -> tuple[str, int]:
    """
    Parses a string containing an IP address and port for both IPv4 and IPv6.

    Args:
        address_string: The string to parse (e.g., "192.168.1.1:8080"
                        or "[2a10:e780:11:1::6d]:51413").

    Returns:
        A tuple containing the IP address (str) and the port (int).

    Raises:
        ValueError: If the string format is invalid.
    """
    # Check if it's an IPv6 address enclosed in brackets
    if address_string.startswith('[') and ']:' in address_string:
        last_bracket_index = address_string.rfind(']')
        ip_addr = address_string[1:last_bracket_index]
        port_str = address_string[last_bracket_index+2:]
    # Otherwise, assume it's IPv4 or a plain IPv6 without bracketsf
    else:
        # rsplit splits from the right, ensuring we only split on the last colon
        parts = address_string.rsplit(':', 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid address format: {address_string}")
        ip_addr, port_str = parts

    try:
        port = int(port_str)
        return ip_addr, port
    except ValueError:
        raise ValueError(f"Invalid port number in address: {address_string}")

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
        ip_addr,port = parse_ip_port(ip_port)
        print(ip_addr,port)
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
        print(peer_info)
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
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(download_whole_file_async(peer_info,decode_data))
        loop.close()
        if result:
            with open(output_file,'wb') as f:
                for i in sorted(result.keys()):
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
                print(f"Peer Metadata Extension ID: {decoded_bitfield[b'm'][b'ut_metadata']}")
    elif command == "magnet_info":
        magnet_link = sys.argv[2]
        info_hash,url = parse_magnet_link(magnet_link)
        bencoded_value = get_decode_style(url,info_hash)
        peer_info = discover_peer(bencoded_value,torrent=1,flag=0)
        socket_info = {
            "info_hash":bencoded_value[b'info'],
            "peer_id":bencoded_value[b'peer_id']
        }

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        decoded_metadata = loop.run_until_complete(meta_info_downloader(peer_info,socket_info))
        print(f"Tracker URL: {urllib.parse.unquote(url)}")
        print(f"Length: {decoded_metadata[b'length']}")
        print(f"Info Hash: {bencoded_value[b'info'].hex()}")
        print(f"Piece Length: {decoded_metadata[b'piece length']}")
        print(f"Piece Hashes:")
        for i in range(0,len(decoded_metadata[b'pieces']),20):
            print(f"{decoded_metadata[b'pieces'][i:i+20].hex()}")

        loop.close()
    elif command == "magnet_download_piece":
        output_file = sys.argv[3]
        magnet_link = sys.argv[4]
        piece_nr = int(sys.argv[5])
        info_hash,url = parse_magnet_link(magnet_link)
        bencoded_value = get_decode_style(url,info_hash)
        peer_info = discover_peer(bencoded_value,torrent=1,flag=0)
        socket_info = {
            "info_hash":bencoded_value[b'info'],
            "peer_id":bencoded_value[b'peer_id']
        }

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        decoded_metadata = loop.run_until_complete(meta_info_downloader(peer_info,socket_info))
        print(f"Tracker URL: {urllib.parse.unquote(url)}")
        print(f"Length: {decoded_metadata[b'length']}")
        print(f"Info Hash: {bencoded_value[b'info'].hex()}")
        print(f"Piece Length: {decoded_metadata[b'piece length']}")
        print(f"Piece Hashes:")
        for i in range(0,len(decoded_metadata[b'pieces']),20):
            print(f"{decoded_metadata[b'pieces'][i:i+20].hex()}")

        bencoded_value[b'info'] = decoded_metadata

        pices_data = loop.run_until_complete(download_whole_file_async(peer_info,bencoded_value,index = piece_nr,handshake_type=1))
        loop.close()

        if pices_data:
            with open(output_file,'wb') as f:
                if pices_data[piece_nr]:
                    f.write(pices_data[piece_nr])

    elif command == "magnet_download":
        output_file = sys.argv[3]
        magnet_link = sys.argv[4]
        info_hash,url = parse_magnet_link(magnet_link)
        bencoded_value = get_decode_style(url,info_hash)
        peer_info = discover_peer(bencoded_value,torrent=1,flag=0)
        socket_info = {
            "info_hash":bencoded_value[b'info'],
            "peer_id":bencoded_value[b'peer_id']
        }

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        decoded_metadata = loop.run_until_complete(meta_info_downloader(peer_info,socket_info))
        print(f"Tracker URL: {urllib.parse.unquote(url)}")
        print(f"Length: {decoded_metadata[b'length']}")
        print(f"Info Hash: {bencoded_value[b'info'].hex()}")
        print(f"Piece Length: {decoded_metadata[b'piece length']}")
        print(f"Piece Hashes:")
        for i in range(0,len(decoded_metadata[b'pieces']),20):
            print(f"{decoded_metadata[b'pieces'][i:i+20].hex()}")

        bencoded_value[b'info'] = decoded_metadata

        result = loop.run_until_complete(download_whole_file_async(peer_info,bencoded_value,handshake_type=1))
        loop.close()

        if result:
            with open(output_file,'wb') as f:
                for i in sorted(result.keys()):
                    print(f"piece {i}")
                    f.write(result[i])
    elif command == "nhandshake":
        torrent_file_path = sys.argv[2]
        ip_port = sys.argv[3]
        ip_addr,port = parse_ip_port(ip_port)
        print(ip_addr,port)
        decode_data = read_torrent(torrent_file_path,print_flag=0)
        info_hash = get_info_hash(decode_data[b'info'])
        port = int(port)
        num_pieces = math.ceil(decode_data[b'info'][b'length']/(8*decode_data[b'info'][b'piece length']))
        print(f"num_pieces {num_pieces}")
        current_have = bytearray(num_pieces*b'\x00')
        socket_info = {}
        socket_info["port"] = port
        socket_info["host"] = ip_addr
        socket_info["peer_id"] = decode_data[b'peer_id']
        socket_info["info_hash"] = info_hash
        socket_info["send_bitfield"] = current_have


        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        reader, writer = loop.run_until_complete(asyncio.open_connection(ip_addr, port))
        resp = loop.run_until_complete(negociate_handshake(writer, reader, socket_info,handshake_type=0))
        loop.close()
        # peer_info = decode_torrent_protocol(resp)
        #print(resp)
        #print(f"Peer ID: {peer_info["peer_id"].hex()}")
    else:
        raise NotImplementedError(f"Unknown command {command}")



if __name__ == "__main__":
    start_time = time.time()
    main()
    total_time = time.time() - start_time
    print(f"total_time  {total_time}")

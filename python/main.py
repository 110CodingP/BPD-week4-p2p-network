import requests
import re

import socket

import struct
import random
import hashlib

import time

def main():

    # get external ip
    response = requests.get("http://checkip.dyndns.org").text
    ip = re.search("(?:[0-9]{1,3}\.){3}[0-9]{1,3}", response).group()

    print(ip)

    # print(response)
    
    # get peers to connect to
    dns_seeds = [
        ("seed.bitcoin.sipa.be",8333),
        ("dnsseed.bluematt.me",8333),
        ("dnsseed.bitcoin.dashjr.org",8333),
        ("seed.bitcoinstats.com",8333),
        ("seed.bitcoin.jonasschnelli.ch",8333),
        ("seed.btc.petertodd.org",8333),
    ]

    peers = []
    try:
        for (ip_addr, port) in dns_seeds:
            for info in socket.getaddrinfo(ip_addr, port, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP):
                peers.append((info[4][0],info[4][1]))
    except Exception:
        print("Exception occured")
    
    
    # make connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    connected_peer = peers[0]

    for peer in peers:
        try: 
          err = sock.connect(peer)
          connected_peer = peer
          break
        except Exception:
            pass
    
    print(connected_peer)

    # do version-verack handshake
      # version msg
    version = struct.pack("i",70015)
    services = struct.pack("Q",0)
    timestamp = struct.pack("q",int(time.time()))
    addr_recv_services = struct.pack("Q",1)
    addr_recv_ip = struct.pack(">16s", bytes.fromhex("00000000000000000000ffff") + socket.inet_aton(connected_peer[0]))
    addr_recv_port = struct.pack("H",connected_peer[1])
    addr_trans_services = struct.pack("Q",0)
    addr_trans_ip = struct.pack(">16s",bytes.fromhex("00000000000000000000ffff") + socket.inet_aton(ip))
    addr_trans_port = struct.pack("H",8333)
    nonce = struct.pack("Q",random.getrandbits(64))
    user_agent_bytes = struct.pack("B",0)
    start_ht = struct.pack("i",0)
    relay = struct.pack("?",False)
    payload = (
        version +
        services +
        timestamp + 
        addr_recv_services +
        addr_recv_ip +
        addr_recv_port +
        addr_trans_services +
        addr_trans_ip +
        addr_trans_port +
        nonce +
        user_agent_bytes +
        start_ht +
        relay
    )
    start = bytes.fromhex("f9beb4d9")
    command = struct.pack("12s",bytes("version","utf-8"))
    payload_size = struct.pack("I",len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    version_msg = start + command + payload_size + checksum + payload

      # verack msg
    command = struct.pack("12s",bytes("verack","utf-8"))
    payload_size = bytes.fromhex("00000000")
    checksum = bytes.fromhex("5df6e0e2")

    verack_msg = start + command + payload_size + checksum

    sock.send(version_msg)
    time.sleep(1)
    # send verack
    while True:
        received_header = sock.recv(24)
        print(received_header[4:16].rstrip(b"\00"))
        if (not received_header):
            break
        else:
            if (received_header[4:16] == struct.pack("12s",bytes("version","utf-8"))):
                sock.send(verack_msg)
                sock.recv(int(received_header[16:20].hex(),base=16))
                break
            else:
                sock.recv(int(received_header[16:20].hex(),base=16))


    # getdata to get the block
    count = bytes.fromhex("01")
    req_type = bytes.fromhex("02000040")
    block_hash = bytes.fromhex("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5")[::-1]
    payload = (
        count +
        req_type +
        block_hash
    )
    
    command = struct.pack("12s",bytes("getdata","utf-8"))
    payload_size = struct.pack("I",len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    getdata_msg = start + command + payload_size + checksum + payload

    sock.send(getdata_msg)

    # listen for block
    block = ""
    while True:
        received_header = sock.recv(24)
        print(received_header[4:16].rstrip(b"\00"))
        if (not received_header):
            break
        else:
            if (received_header[4:16] == struct.pack("12s",bytes("block","utf-8"))):
                block = sock.recv(int(received_header[16:20].hex(),base=16))
                block = block.hex()
                break
            else:
                sock.recv(int(received_header[16:20].hex(),base=16))
    
    def hash256(data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    header = block[:160]    
    received_block_hash = hash256(bytes.fromhex(block[:160]))[::-1].hex()

    def find_size(data,idx):
        var_int_start = bytes.fromhex(data[idx:idx+2])
        if (var_int_start<=bytes.fromhex("fc")):
            return [idx+2,bytes.fromhex(data[idx:idx+2])]
        elif (var_int_start==bytes.fromhex("fd")):
            return [idx+6,bytes.fromhex(data[idx+2:idx+6])[::-1]]
        elif (var_int_start == bytes.fromhex("fe")):
            return [idx+10,bytes.fromhex(data[idx+2:idx+10])[::-1]]
        else:
            return [idx+18,bytes.fromhex(data[idx+2:idx+18])[::-1]]

    def find_pushbytes(data,idx):
        if (data[idx] == "4c"):
            return [idx+4, bytes.fromhex(data[idx+2:idx+4])[::-1]]
        elif (data[idx] == "4d"):
            return [idx+6, bytes.fromhex(data[idx+2:idx+6])[::-1]]
        else:
            return [idx+2, bytes.fromhex(data[idx:idx+2])]

    next_idx , tx_ct = find_size(block,160)
    tx_ct = int(tx_ct.hex(),base=16)
    # print(tx_ct)
    # find the message and calc fee
    fee = 0
    version = block[next_idx:next_idx+8]
    next_idx += 8
    if (block[next_idx:next_idx+2]=="00"):
        marker = "00"
        flag = "01"
        next_idx += 4
    next_idx,input_ct = find_size(block,next_idx)
    input_ct = int(input_ct.hex(),base=16)
    assert(input_ct == 1)
    next_idx += 72
    # print(next_idx)
    next_idx,script_sig_sz = find_size(block,next_idx)
    script_start = next_idx
    # print(next_idx)
    script_sig_sz = int(script_sig_sz.hex(),base=16)
    # script_sig = block[next_idx:next_idx + script_sig_sz*2]
    # # find how to deserialize pushbytes
    next_idx, block_ht_len = find_pushbytes(block,next_idx)
    block_ht_len = int(block_ht_len.hex(),base=16)
    block_ht = bytes.fromhex(block[next_idx:next_idx+block_ht_len*2])[::-1].hex()
    next_idx += block_ht_len*2
    miner_info = block[next_idx+4:next_idx+50]
    miner_info = bytes.fromhex(miner_info).decode()
    next_idx = script_start
    next_idx += script_sig_sz*2
    # seq
    # print(block[next_idx:next_idx+8])
    next_idx+=8
    next_idx, output_ct = find_size(block,next_idx)
    output_ct = int(output_ct.hex(),base=16)
    for ct in range(output_ct):
        fee += int(bytes.fromhex(block[next_idx:next_idx+16])[::-1].hex(),base=16)
        next_idx  += 16
        next_idx, spk_size = find_size(block,next_idx)
        spk_size = int(spk_size.hex(),base=16)
        next_idx += spk_size*2
    fee -= int(3.125*(10**8))
    
    f = open("./out.txt","w")
    f.write(f"{header}\n{received_block_hash}\n{fee}\n{miner_info}")
    f.close()






if __name__ == "__main__":
    main()

"""
   References:
   - making a connection: http://sebastianappelt.com/understanding-blockchain-peer-discovery-and-establishing-a-connection-with-python/
   - P2P reference: https://developer.bitcoin.org/reference/p2p_networking.html
   - networking basics: https://web.mit.edu/6.031/www/fa19/classes/23-sockets-networking/
   - version-verack handshake: https://en.bitcoin.it/wiki/Version_Handshake
   - addr_recv_ip : https://en.bitcoin.it/wiki/Protocol_documentation#Network_address and https://stackoverflow.com/questions/33244775/converting-ip-address-into-bytes-in-python
   - as always: https://learnmeabitcoin.com/technical/networking/
   - get block at certain ht: https://bitcoin.stackexchange.com/questions/83990/getting-individual-block-by-height-from-bitcoin-p2p-network
   - message types: https://en.bitcoin.it/wiki/Protocol_documentation#Message_types
   - getting block hash of block 840000: https://mempool.space/block/0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5
   - using a loop to receive messages: https://learnmeabitcoin.com/technical/networking/#keeping-connected
   - https://stackoverflow.com/questions/38883476/how-to-remove-those-x00-x00
   - convert hex to ascii - https://stackoverflow.com/questions/9641440/convert-from-ascii-string-encoded-in-hex-to-plain-ascii
"""
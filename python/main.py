import requests
import re

import socket
import time

def main():

    # get external ip
    response = requests.get("http://checkip.dyndns.org").text
    ip = re.search("(?:[0-9]{1,3}\.){3}[0-9]{1,3}", response).group()

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
    
    print(peers)



if __name__ == "__main__":
    main()

"""
   References:
   - making a connection: http://sebastianappelt.com/understanding-blockchain-peer-discovery-and-establishing-a-connection-with-python/
   - P2P reference: https://developer.bitcoin.org/reference/p2p_networking.html
   - networking basics: https://web.mit.edu/6.031/www/fa19/classes/23-sockets-networking/

"""
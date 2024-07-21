import requests
import re

def main():

    # get external ip
    response = requests.get("http://checkip.dyndns.org").text
    ip = re.search("(?:[0-9]{1,3}\.){3}[0-9]{1,3}", response).group()




if __name__ == "__main__":
    main()

"""
   References:
   - making a connection: http://sebastianappelt.com/understanding-blockchain-peer-discovery-and-establishing-a-connection-with-python/
   - P2P reference: https://developer.bitcoin.org/reference/p2p_networking.html
   - networking basics: https://web.mit.edu/6.031/www/fa19/classes/23-sockets-networking/

"""
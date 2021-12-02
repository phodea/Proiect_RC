import socket
import netifaces as ni
import struct
import sys
import select
import threading
import time

interfaces = [] #stores a list of available interfaces IP addresses

for interface in ni.interfaces():
    if interface != "lo" and interface != "enp0s3":
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        interfaces.append(ip)

MCAST_GRP = '224.0.0.9'
MCAST_PORT = 5007
MULTICAST_TTL = 20

class routingTable():
    routing_table = {}

    def __init__(self):
        for interface_ip in interfaces:
            #self.add_entry(routingTableEntry(interface_ip, '0.0.0.0', 0))
            self.routing_table.update({interface_ip: ['0.0.0.0', 0]})

    def __repr__(self):
        str = "dest ip       next_hop    cost\n" + "------        --------    ----\n"
        for dest_ip, next_hop_and_metric in self.routing_table.items():
            str = str + "%s    %s    %d\n" % (dest_ip, next_hop_and_metric[0], next_hop_and_metric[1])
        return str

    def update_routing_table(self, ip_address, next_hop, metric):
        if self.routing_table.get(ip_address):
            if metric < self.routing_table.get(ip_address)[1]:
                self.routing_table.update({ip_address: [next_hop, metric]})
        else:
            self.routing_table.update({ip_address: [next_hop, metric]})


    def serialize(self):
        buffer = struct.pack('b', 1)
        buffer += struct.pack('b', len(self.routing_table))
        for dest_ip, next_hop_and_metric in self.routing_table.items():
            buffer = buffer + struct.pack('4s4sH', socket.inet_aton(dest_ip), socket.inet_aton(next_hop_and_metric[0]), next_hop_and_metric[1])

        return buffer

class RipV2:
    #we need to create a list of sockets for sending multicast packets thorugh every interface
    routing_table: routingTable
    sock_list = []

    def create_multicast_sock(self, host_ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

        #add membership to receive multicast messages
        membership = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(host_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.bind((MCAST_GRP, MCAST_PORT))
        self.sock_list.append(sock)

    def __init__(self, routing_table):
        self.routing_table = routing_table
        for interface_ip in interfaces:
            print("creating mcast sock for %s" % interface_ip)
            self.create_multicast_sock(interface_ip)
        threading.Thread(target=self.periodic_updates).start()


    def periodic_updates(self):
        global running
        while running:
            self.send(routing_table.serialize())
            time.sleep(30)

    def send(self, message):
        for sock in self.sock_list:
            #print("sending %s...." % message)
            sock.sendto(bytes(message), (MCAST_GRP, MCAST_PORT))

    def process_reply_message(self, data, source_ip):
        number_of_entries = struct.unpack('b', data[:1])[0]
        data = data[1:]

        for i in range(1, number_of_entries + 1):
            dest_ip = socket.inet_ntoa(struct.unpack('4s', data[:4])[0])
            data = data[4:]
            next_hop = socket.inet_ntoa(struct.unpack('4s', data[:4])[0])
            data = data[4:]
            metric = struct.unpack('H', data[:2])[0]
            metric += 1
            data = data[2:]

            self.routing_table.update_routing_table(dest_ip, source_ip, metric)

    def receive_fct(self, sock):
        global running
        while running:
            data, address = sock.recvfrom(1024)
            #print("S-a receptionat ", str(data), " de la ", address)
            message_type = struct.unpack('b', data[:1])[0]
            data = data[1:]
            if message_type == 1:
                self.process_reply_message(data, address[0])

    def recv(self):
        threading.Thread(target=self.receive_fct, args=(self.sock_list[0],)).start()


routing_table = routingTable()
print(routing_table)

running = True
ripv2 = RipV2(routing_table)
ripv2.recv()
print("started receiving messages....")
while True:
    try:
        data = input("Trimite: ")

        if data == "--rtable":
            print(routing_table)
        else:
            ripv2.send(bytes(data, encoding="ascii"))
    except KeyboardInterrupt:
        running = False
        break

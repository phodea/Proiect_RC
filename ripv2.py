import datetime
import socket
import ipaddress
import netifaces as ni
import struct
import sys
import select
import threading
import time
import os

interfaces = [] #stores a list of available interfaces IP addresses

for interface in ni.interfaces():
    if interface != "lo" and interface != "enp0s3":
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        print(interface)
        interfaces.append(ip)

MCAST_GRP = '224.0.0.9'
MCAST_PORT = 5007
MULTICAST_TTL = 20

debug_enabled = False

update_timer = 30

class routingTable():
    entries = []

    def __init__(self):
        for interface_ip in interfaces:
            self.entries.append(RIPv2RouteEntry(interface_ip, '255.255.255.0', '0.0.0.0', 0))

    def __repr__(self):
        str = "dest ip       next_hop    cost\n" + "------        --------    ----\n"
        for entry in self.entries:
            str = str + "%s    %s    %d\n" % (entry.address, entry.next_hop, entry.metric)
        return str

    def update(self, received_entries, next_hop):
        changedEntries = []
        for rte in received_entries:
            isEntryFound = False
            for entry in self.entries:
                if entry.address == rte.address:
                    if entry.metric > rte.metric + 1:
                        entry.next_hop = rte.next_hop
                        entry.metric = rte.metric + 1
                        entry.isChanged = True
                        changedEntries.append(entry)
                    isEntryFound = True

            if not isEntryFound:
                new_entry = RIPv2RouteEntry(rte.address, '255.255.255.0', next_hop, rte.metric + 1)
                new_entry.isChanged = True
                changedEntries.append(new_entry)
                self.entries.append(new_entry)
        return changedEntries


    def serialize(self):
        buffer = struct.pack('b', 1)
        buffer += struct.pack('b', len(self.entries))
        for entry in self.entries:
            buffer = buffer + struct.pack('4s4sH', socket.inet_aton(entry.dest_ip), socket.inet_aton(entry.next_hop), entry.metric)

        return buffer

class RIPv2RouteEntry:
    FORMAT = "HH4s4s4sI"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16

    def __init__(self, *args):#address, subnet_mask, next_hop, metric):
        if len(args) == 1:
            self.init_entry_from_serialized_message(message=args[0])
        elif len(args) == 4:
            self.addr_family_id = socket.AF_INET
            self.route_tag = 0  # must be 0
            self.address = args[0]
            self.subnet_mask = args[1]
            self.next_hop = args[2]
            self.metric = args[3]

            self.isChanged = False
            self.garbage = False

            self.resetTimer()

    def init_entry_from_serialized_message(self, message):
        self.addr_family_id, self.route_tag, address, subnet_mask, next_hop, self.metric = \
        struct.unpack(self.FORMAT, message)

        self.address = socket.inet_ntoa(address)
        self.subnet_mask = socket.inet_ntoa(subnet_mask)
        self.next_hop = socket.inet_ntoa(next_hop)

    def resetTimer(self):
        self.timeout = datetime.datetime.now()

    def serialize(self):
        return struct.pack(self.FORMAT,
                           self.addr_family_id,
                           self.route_tag,
                           socket.inet_aton(self.address),
                           socket.inet_aton(self.subnet_mask),
                           socket.inet_aton(self.next_hop),
                           self.metric)

class RIPV2Header():
    FORMAT = "BBH"
    SIZE = struct.calcsize(FORMAT)
    REQUEST = 1
    REPLY = 2

    def __init__(self, data):
        time.sleep(int(1))
        if isinstance(data, int):
            assert data == self.REQUEST or data == self.REPLY, "Invalid opcode"

            self.command = data
            self.version = 2
            self.unused = 0
        elif isinstance(data, bytes):
            self.init_header_from_serialized_message(message=data)

    #deserialize a ripv2 header
    def init_header_from_serialized_message(self, message):
        self.command, self.version, self.unused = struct.unpack(self.FORMAT, message)

    def serialize(self):
        return struct.pack(self.FORMAT, self.command, self.version, self.unused)

class RIPV2Packet(RIPV2Header):
    entries = []

    def __init__(self, *args):
        if len(args) == 1:
            self.init_packet_from_serialized_message(message=args[0])
        elif len(args) == 2:
            super().__init__(args[0])#command
            self.entries = args[1]   #routing table entries (list)

    #deserialize a ripv2 packet
    def init_packet_from_serialized_message(self, message):
        number_of_entries = int((len(message) - RIPV2Header.SIZE) / RIPv2RouteEntry.SIZE)
        index = 0

        #deserialize the header
        super().__init__(message[index:RIPV2Header.SIZE])
        index += RIPV2Header.SIZE

        #deserialize the entries
        for i in range(number_of_entries):
            self.entries.append(RIPv2RouteEntry(message[index:index + RIPv2RouteEntry.SIZE]))
            index += RIPv2RouteEntry.SIZE

    def serialize_message(self):
        packed = super().serialize()

        for entry in self.entries:
            packed += entry.serialize()

        return packed

class RipV2:
    #we need to create a list of sockets for sending multicast packets thorugh every interface
    routing_table: routingTable

    #dictionary with socket : interface_ip pairs
    sock_list = {}

    def create_multicast_sock(self, interface_ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

        #add membership to receive multicast messages
        membership = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(interface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.bind((MCAST_GRP, MCAST_PORT))

        self.sock_list[sock] = interface_ip

    def __init__(self, routing_table):
        self.routing_table = routing_table
        for interface_ip in interfaces:
            self.create_multicast_sock(interface_ip)
        threading.Thread(target=self.periodic_update).start()


    def periodic_update(self):
        global running
        while running:
            self.send(RIPV2Packet(RIPV2Header.REPLY, self.routing_table.entries).serialize_message())
            time.sleep(int(update_timer))

    def triggered_updates(self, changed_entries):
        packet = RIPV2Packet(RIPV2Header.REPLY, changed_entries)
        self.send(packet.serialize())

    def send(self, message):
        for sock in self.sock_list:
            #print("sending %s...." % message)
            sock.sendto(bytes(message), (MCAST_GRP, MCAST_PORT))

    def process_reply_message(self, entries, source_ip):
        changed_entries = self.routing_table.update(entries, source_ip)

        if len(changed_entries) > 0:
            self.triggered_updates(changed_entries)

    def receive_fct(self, sock):
        global running
        while running:
            data, address = sock.recvfrom(1024)
            interface_ip = self.sock_list[sock]

            #since all sockets are bound to the same mcast_grp address, we need to check if the message is received on
            #the correct interface ( checking if the sender is in the same network with the interface )
            network1 = ipaddress.IPv4Network(interface_ip + '/255.255.255.0', strict=False)
            network2 = ipaddress.IPv4Network(address[0] + '/255.255.255.0', strict=False)

            if network1 == network2:
                if debug_enabled:
                    print("\nS-a receptionat ", str(data), " de la ", address, " pe ", self.sock_list[sock])
                packet = RIPV2Packet(data)

                if packet.command == RIPV2Header.REPLY:
                    self.process_reply_message(packet.entries, address[0])
    def recv(self):
        for socket in self.sock_list:
            threading.Thread(target=self.receive_fct, args=(socket,)).start()


def display_menu():
    print("-------MENIU--------")
    print("comenzi: routing table    - afisare tabela de routare")
    print("         set update timer - setare timer pentru update-uri periodice")
    print("         enable debug     - activeaza afisarea tuturor pachetelor care se primesc/trimit")
    print("         disable debug    - dezactiveaza afisarea tuturor pachetelor care se primesc/trimit")
    print("         menu             - afiseaza meniul")
    print("         quit             - inchide procesul RipV2")

def get_user_command():
    global debug_enabled
    global update_timer
    data = input("comanda: ")

    if data == "routing table":
        print(routing_table)
    elif data == "enable debug":
        debug_enabled = True
    elif data == "disable debug":
        debug_enabled = False
    elif data == "menu":
        display_menu()
    elif data == "set update timer":
        update_timer = input("introduceti timer-ul: ")
    elif data == "quit":
        os._exit(0)

if __name__ == '__main__':
    routing_table = routingTable()
    print(routing_table)

    running = True
    ripv2 = RipV2(routing_table)
    ripv2.recv()
    print("started receiving messages....")
    while True:
        try:
            get_user_command()
        except KeyboardInterrupt:
            running = False
            break
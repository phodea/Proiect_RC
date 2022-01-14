import datetime
import random
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
MCAST_PORT = 520
MULTICAST_TTL = 20

debug_enabled = False

PERIODIC_UPDATE_TIMER = 10 # 30
ROUTE_TIMEOUT = 20 # 180
GARBAGE_COLLECTION_TIMER = 20 # 120

def print_message(message):
    if debug_enabled:
        print("\n[" + time.strftime("%H:%M:%S") + "]: " + message)

class routingTable():
    entries = []

    def __init__(self):
        for interface_ip in interfaces:
            self.entries.append(RIPv2RouteEntry(socket.AF_INET, interface_ip, '255.255.255.0', '0.0.0.0', 0))

    def __repr__(self):
        str = "dest ip       next hop    metric\n" + "------        --------    ------\n"
        for entry in self.entries:
            str += "%s    %s    %d" % (entry.address, entry.next_hop, entry.metric)
            if entry.garbage.is_alive():
                str += "   G"
            str += "\n"
        return str

    def update(self, received_entries, next_hop):
        changedEntries = []

        for rte in received_entries:
            #we exclude local interfaces
            if rte.address not in interfaces:
                best_route = self.getEntry(rte.address)
                #destination address found
                if best_route != None:
                    #existing route is not marked as garbage
                    if not best_route.garbage.is_alive():
                        if best_route.metric > rte.metric + 1:
                            print_message("Route to " + best_route.address + " updated, with next hop: " + next_hop + ", metric: " + str(rte.metric + 1))
                            best_route.next_hop = next_hop
                            best_route.metric = rte.metric + 1
                            changedEntries.append(best_route)
                        elif best_route.metric < RIPv2RouteEntry.MAX_METRIC and rte.metric + 1 >= RIPv2RouteEntry.MAX_METRIC:
                            print_message("Route to " + best_route.address + " started garbage collection timer.")
                            best_route.garbage.start()
                            best_route.metric = RIPv2RouteEntry.MAX_METRIC
                            changedEntries.append(best_route)
                elif rte.metric < RIPv2RouteEntry.MAX_METRIC:
                    #destination address not found
                    print_message("Adding route: " + rte.address + ", next hop: " + next_hop + ", metric: " + str(rte.metric + 1))
                    new_entry = RIPv2RouteEntry(socket.AF_INET, rte.address, '255.255.255.0', next_hop, rte.metric + 1)
                    changedEntries.append(new_entry)
                    self.entries.append(new_entry)

        return changedEntries

    def getEntry(self, address):
        for entry in self.entries:
            if entry.address == address:
                return entry
        return None

    def serialize(self):
        buffer = struct.pack('b', 1)
        buffer += struct.pack('b', len(self.entries))
        for entry in self.entries:
            buffer = buffer + struct.pack('4s4sH', socket.inet_aton(entry.dest_ip), socket.inet_aton(entry.next_hop), entry.metric)

        return buffer

def remove_entry_from_routing_table(entry):
    print_message("Garbage timer expired: route to " + entry.address + " will be deleted")
    routing_table.entries.remove(entry)

class RIPv2RouteEntry:
    FORMAT = "HH4s4s4sI"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16

    def __init__(self, *args):
        if len(args) == 1:
            self.init_entry_from_serialized_message(message=args[0])
        elif len(args) == 5:
            self.addr_family_id = args[0]
            self.route_tag = 0  # must be 0
            self.address = args[1]
            self.subnet_mask = args[2]
            self.next_hop = args[3]
            self.metric = args[4]
            self.garbage = threading.Timer(GARBAGE_COLLECTION_TIMER, remove_entry_from_routing_table, args=[self])

    def __repr__(self):
        return '[ {} | {} | {} ]\n'.format(self.address, self.next_hop, self.metric)

    def init_entry_from_serialized_message(self, message):
        self.addr_family_id, self.route_tag, address, subnet_mask, next_hop, self.metric = \
        struct.unpack(self.FORMAT, message)

        self.address = socket.inet_ntoa(address)
        self.subnet_mask = socket.inet_ntoa(subnet_mask)
        self.next_hop = socket.inet_ntoa(next_hop)

    def reset_garbage_timer(self):
        self.garbage.cancel()
        self.garbage = threading.Timer(GARBAGE_COLLECTION_TIMER, remove_entry_from_routing_table, args=[self])


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

    def __init__(self, *args):
        self.entries = []
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

    def serialize(self):
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

        self.recv()
        self.send_request_message()
        self.periodic_updates()

    def send_request_message(self):
        #send request to neighbours for their whole routing table
        entry = RIPv2RouteEntry(0, '0.0.0.0', '0.0.0.0', '0.0.0.0', RIPv2RouteEntry.MAX_METRIC)
        packet = RIPV2Packet(RIPV2Header.REQUEST, [entry])

        self.send(packet.serialize())

    def periodic_updates(self):
        delay = random.randint(-5, 5)
        period = PERIODIC_UPDATE_TIMER + delay
        self.send(RIPV2Packet(RIPV2Header.REPLY, self.routing_table.entries).serialize())

        threading.Timer(period, self.periodic_updates).start()

    def triggered_updates(self, changed_entries, sock_to_exclude):
        packet = RIPV2Packet(RIPV2Header.REPLY, changed_entries)
        self.send(packet.serialize(), sock_to_exclude)

    def send(self, message, sock_to_exclude=None):
        for sock in self.sock_list:
            if sock == sock_to_exclude:
                continue
            sock.sendto(bytes(message), (MCAST_GRP, MCAST_PORT))

    def process_reply_message(self, entries, source_ip, sock_to_exclude):
        #we don't need to send triggered updates back to the source of the packet
        changed_entries = self.routing_table.update(entries, source_ip)
        if len(changed_entries) > 0:
            self.triggered_updates(changed_entries, sock_to_exclude)

    def process_request_message(self, entries):
        if (len(entries)) == 1 and \
            entries[0].addr_family_id == 0 and\
            entries[0].metric == RIPv2RouteEntry.MAX_METRIC:
            #request for whole routing table
            packet = RIPV2Packet(RIPV2Header.REPLY, self.routing_table.entries)
        else:
            #request for a part of routing table
            routes = []
            for entry in entries:
                route = self.routing_table.getEntry(entry.address)
                if route != None:
                    routes.append(route)

            if len(routes) > 0:
                packet = RIPV2Packet(RIPV2Header.REPLY, routes)
            else:
                return None
        return packet

    def receive_fct(self, sock, timer):
        isActive = False
        sender_address = ''
        global running
        while running:
            sock.settimeout(ROUTE_TIMEOUT)
            try:
                data, address = sock.recvfrom(1024)
            except socket.timeout:
                if isActive == True:
                    self.mark_as_garbage(sender_address, sock)
                    isActive = False
            else:
                interface_ip = self.sock_list[sock]

                #since all sockets are bound to the same mcast_grp address, we need to check if the message is received on
                #the correct interface ( checking if the sender is in the same network with the interface )
                network1 = ipaddress.IPv4Network(interface_ip + '/255.255.255.0', strict=False)
                network2 = ipaddress.IPv4Network(address[0] + '/255.255.255.0', strict=False)

                if network1 == network2:
                    isActive = True
                    sender_address = address[0]
                    timer = datetime.datetime.now()
                    packet = RIPV2Packet(data)

                    command_type = 'REQUEST' if packet.command == RIPV2Header.REQUEST else 'REPLY'
                    #print informations about the packet
                    print_message("Received message from {}\nType = {}\nVersion = {}"
                                  .format(address[0], command_type, packet.version))
                    str = 'Entries = '
                    for entry in packet.entries:
                        str += repr(entry)
                    print(str)

                    if packet.command == RIPV2Header.REPLY:
                        self.process_reply_message(packet.entries, address[0], sock)
                    elif packet.command == RIPV2Header.REQUEST:
                        packet2send = self.process_request_message(packet.entries)
                        if packet2send != None:
                            sock.sendto(packet2send.serialize(), (MCAST_GRP, MCAST_PORT))

                if ((datetime.datetime.now() - timer).total_seconds() > ROUTE_TIMEOUT and isActive == True):
                    isActive = False
                    print_message("Connection " + sender_address + " broke.")
                    self.mark_as_garbage(sender_address, sock)

    def mark_as_garbage(self, sender_address, sock_to_exclude):
        if sender_address:
            changedEntries = []

            for entry in self.routing_table.entries:
                if entry.next_hop == sender_address:
                    print_message("Route to " + entry.address + " started garbage collection timer.")
                    entry.garbage.start()
                    entry.metric = RIPv2RouteEntry.MAX_METRIC
                    changedEntries.append(entry)

            if len(changedEntries) > 0:
                self.triggered_updates(changedEntries, sock_to_exclude)

    def recv(self):
        for socket in self.sock_list:
            threading.Thread(target=self.receive_fct, args=(socket, datetime.datetime.now(),)).start()


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

routing_table = routingTable()

if __name__ == '__main__':
    print(routing_table)

    running = True
    ripv2 = RipV2(routing_table)
    print("started receiving messages....")
    while True:
        try:
            get_user_command()
        except KeyboardInterrupt:
            running = False
            break
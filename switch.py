#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# am declarat variabile globale ca sa retin informatiile actualizate
Mac_Table = {}
port_state = {}
global root_bridge_ID
global own_bridge_ID
global root_path_cost
global root_port

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

'''functie care face un pachet bdpu - am facut propria structura care contine doar: 
adresele sursa si destinatie, root_bridge_id-ul, root_path_cost-ul si own_bridge_id-ul
din mometul respectiv'''
def create_bpdu():
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost

    # adresa MAC destinatie pentru pachetele BDPU din cerinta
    dest_mac = b'\x01\x80\xc2\x00\x00\x00'
    
    src_mac = get_switch_mac()

    llc_length = struct.pack('!H', 6 + 6 + 2 + 4 + 4 + 4)

    # root_bridge_id - 4 bytes
    root_bridge_bytes = struct.pack('!I', root_bridge_ID)
    
    # root_path_cost - 4 bytes
    root_path_cost_bytes = struct.pack('!I', root_path_cost)
    
    # bridge_id - 4 bytes
    bridge_id_bytes = struct.pack('!I', own_bridge_ID)

    bpdu_config = root_bridge_bytes + root_path_cost_bytes + bridge_id_bytes
    bpdu_frame = dest_mac + src_mac + llc_length + bpdu_config

    return bpdu_frame

'''functia care trimite pachete bdpu mereu'''
def send_bpdu_every_sec(switch, interfaces):

    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost

    while True:

        # trimit pachete daca sunt root (initial toate sunt root)
        if own_bridge_ID == root_bridge_ID:
            for interface in interfaces:
                for port, config in switch["ports"].items():
                    if config["type"] == "trunk":
                        # print(f"Trimit {port}")
                        # creez cadrul bdpu pe care il trimit
                        bpdu_frame = create_bpdu()
                        # print(f"Trimit BPDU pe portul {port}")
                        send_to_link(interface, len(bpdu_frame), bpdu_frame)
        
        time.sleep(1)

'''functia de parsare a datelor bdpu'''
def parse_bpdu(bpdu_frame):

    dest_mac = bpdu_frame[0:6]
    src_mac = bpdu_frame[6:12]

    llc_length = struct.unpack('!H', bpdu_frame[12:14])[0]

    # toate sunt de 4 bytes
    root_bridge_id = struct.unpack('!I', bpdu_frame[14:18])[0]
    root_path_cost = struct.unpack('!I', bpdu_frame[18:22])[0]
    bridge_id = struct.unpack('!I', bpdu_frame[22:26])[0]

    # returnez ce am nevoie
    return src_mac, root_bridge_id, bridge_id, root_path_cost

def is_unicast(mac_address):
    return (int(mac_address.split(':')[0], 16) & 1) == 0

'''functia pentru citirea switch-ului in care imi initializez variabilele globale
si porturile'''
def read_switch_config(filename):

    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost
    global root_port

    #structura pentru fiecare switch
    switch = {
        "priority": None,
        "ports": {},
        "root_path_cost": 0,
    }

    with open(filename, "r") as file:
        lines = file.readlines()

    switch["priority"] = int(lines[0].strip())

    # declar fiecare switch ca fiind root initial
    own_bridge_ID =  switch["priority"]
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    root_port = None

    # citesc de pe fiecare linie configuratia porturilor
    for line in lines[1:]:
        parts = line.strip().split()
        interface_name = parts[0]
        
        # daca e de tip trunk initializez starea cu "BLOCKING" si nu pun vlan_id
        if parts[1] == "T":
            switch["ports"][interface_name] = {
                "type": "trunk",
                "vlan": None,
                "state": "BLOCKING",
                "port_type": None
            }

            # dupa pseudocod, porturile root-ului devin DESUGNATED
            if own_bridge_ID == root_bridge_ID:
                switch["ports"][interface_name]["state"] = "LISTENING"  # Porturile trunk sunt în LISTENING
                switch["ports"][interface_name]["port_type"] = "DESIGNATED_PORT"
        else:
            # daca e de tip acces initializez starea cu "LISTENING" si pun vlan_id
            vlan_id = int(parts[1])
            switch["ports"][interface_name] = {
                "type": "access",
                "vlan": vlan_id,
                "state": "LISTENING"
            }

    return switch

'''functia pentru getsionarea VLAN'''
def transport_vlan(data, vlan_id, src_port_config, dest_port_config):
   
    # daca primesc de pe un port de tip acces
    if src_port_config["type"] == "access":
        # si trimit pe unul trunk, atunci adaug tag
        if dest_port_config["type"] == "trunk":
            data = data[:12] + create_vlan_tag(vlan_id) + data[12:]

        # si trimit tot pe acces, atunci nu adaug
        elif dest_port_config["type"] == "access":
            if vlan_id != dest_port_config["vlan"]:
                # ignor daca nu se potriveste vlan_id ul
                return None
            return data

    # daca primesc de pe un port de tip trunk
    elif src_port_config["type"] == "trunk":
        # si trimit pe unul acces, atunci elimin tag-ul
        if dest_port_config["type"] == "access":
            if vlan_id != dest_port_config["vlan"]:
                # ignor daca nu se potriveste vlan_id ul
                return None 
            return data[:12] + data[16:]

    #daca trimit tot pe trunk nu modific nimic
    return data

'''functia din pseudocod care gestioneaza pachetele bdpu primite
    root_bridge_id - id-ul root pe care il stie switch-ul de la care primesc  pachet
    sender_bridge_ID - id-ul senderului
    sender_path_cost - costul pana la root al senderului'''
def receive_bpdu(interface, switch, port, src_mac, root_bridge_id, sender_bridge_ID, sender_path_cost):
    global root_bridge_ID
    global own_bridge_ID
    global root_path_cost
    global root_port

    print(f'AM PRIMIT BDPU')

    # daca root_bridge_id-ul primit in pachet e mai mic decat cel stiut de switch-ul curent, actualizez datele
    if root_bridge_id < root_bridge_ID:

        root_bridge_ID = root_bridge_id
        root_path_cost = sender_path_cost + 10
        root_port = port

        # blochez toate porturile in afara de root_port
        if root_bridge_id == root_bridge_ID:
            for p, config in switch["ports"].items():
                if p != root_port and config["type"] == "trunk":
                    switch["ports"][p]["state"] = "BLOCKING"

        # daca root_port e blocat il pun pe LISTENING
        if switch["ports"][root_port]["state"] == "BLOCKING":
            switch["ports"][root_port]["state"] = "LISTENING"

        # trimit pachet cu datele actualizate pe toate porturile trunk
        for p, config in switch["ports"].items():
            if config["type"] == "trunk":
                bpdu_frame = create_bpdu()
                send_to_link(interface, len(bpdu_frame), bpdu_frame)

    # daca id-urile root sunt egale, verific daca actualizez costul
    elif root_bridge_id == root_bridge_ID:
        if port == root_port and (sender_path_cost + 10) < root_path_cost:
            root_path_cost = sender_path_cost + 10
        
        # daca nu e root port, verific daca e designated
        elif port != root_port:
            if sender_path_cost > root_path_cost:
                # actualizez root_port si schimb starea si tipul
                root_port = port
                switch["ports"][port]["state"] = "LISTENING"
                switch["ports"][port]["port_type"] = "DESIGNATED_PORT"
    
    # daca pachetul vine de pe acelasi bridge_id, atunci e o bucla si blocam portul
    elif sender_bridge_ID == own_bridge_ID:
        switch["ports"][port]["state"] = "BLOCKING"
        print(f"Port {port} set to BLOCKING")

    else:
        print(f"BPDU discarded: {port}")
        return

    # daca sunt root_bridge, setez toate porturile trunk ca fiind designated
    if own_bridge_ID == root_bridge_ID:
        for p, config in switch["ports"].items():
            if config["type"] == "trunk":
                switch["ports"][p]["state"] = "LISTENING"
                switch["ports"][p]["port_type"] = "DESIGNATED_PORT"

def main():

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    #print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    config_filename = f"configs/switch{switch_id}.cfg"
    switch = read_switch_config(config_filename)

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bpdu_every_sec, args=(switch, interfaces))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()
        dest_mac = data[0:6]
        # destinatia MAC din enunt prin care identific cadrele BDPU
        target_mac = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])
        port_config = switch["ports"].get(get_interface_name(interface), {})

        # daca e BDPU parsez datele primite si apelez functia in care le gestionez pentru STP
        if dest_mac == target_mac:
            src_mac, root_bridge_id, sender_bridge_ID, sender_path_cost = parse_bpdu(data)
            receive_bpdu(interface, switch, get_interface_name(interface), src_mac, root_bridge_id, sender_bridge_ID, sender_path_cost)

        #daca nu e BDPU:
        else:
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            # Print the MAC src and MAC dst in human readable format
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            # TODO: Implement forwarding with learning

            # daca vlan ul nu e speificat si portul e de tip acces, atunci il folosim pe cel din configuratie
            if vlan_id == -1 and port_config["type"] == "access":
                vlan_id = port_config["vlan"]

            # aduagam intrare noua
            if vlan_id not in Mac_Table:
                Mac_Table[vlan_id] = {}

            Mac_Table[vlan_id][src_mac] = interface

            if is_unicast(dest_mac):

                outgoing_data = None

                # daca destinatia e in tabela MAC si are acelasi vlan_id, trimitem
                if dest_mac in Mac_Table[vlan_id]:
                    dest_interface = get_interface_name(Mac_Table[vlan_id][dest_mac])
                    dest_port_config = switch["ports"].get(dest_interface, {})
                    outgoing_data = transport_vlan(data, vlan_id, port_config, dest_port_config)
                    if outgoing_data is not None:
                        send_to_link(Mac_Table[vlan_id][dest_mac], len(outgoing_data), outgoing_data)
                else:
                    # daca destinatia nu e in tabela MAC, fac flooding
                    for p in interfaces:
                        if p != interface:
                            dest_port_config = switch["ports"].get(get_interface_name(p), {})
                            #trimit doar pe porturile LISTENING
                            if dest_port_config.get("state") == "LISTENING":
                                outgoing_data = transport_vlan(data, vlan_id, port_config, dest_port_config)
                                if outgoing_data is not None:
                                    send_to_link(p, len(outgoing_data), outgoing_data)
            else:
                # broadcast, fac flooding pe porturile cu acelasi vlan
                for p in interfaces:
                    if p != interface:
                        dest_port_config = switch["ports"].get(get_interface_name(p), {})
                        #trimit doar pe porturile LISTENING
                        if dest_port_config.get("state") == "LISTENING":
                            outgoing_data = transport_vlan(data, vlan_id, port_config, dest_port_config)
                            if outgoing_data is not None:
                                send_to_link(p, len(outgoing_data), outgoing_data)

            # TODO: Implement VLAN support
            # TODO: Implement STP support

            # data is of type bytes.
            # send_to_link(i, length, data)

if __name__ == "__main__":
    main()

import struct
import sys

def read_pcap(PCAP_FILE):

    # This is basically the code from the tutorial to read the pcap file and parse it

    # STEP 1: Open the PCAP file in binary mode
    with open(PCAP_FILE, 'rb') as f:    # Open the PCAP file in binary mode
        # STEP 2: Read the global header (first 24 bytes)
        global_header = f.read(24)         # Read the global header (first 24 bytes)
        if len(global_header) < 24:  # Check if the global header is complete
            print("Incomplete global header")
            exit(1)
    
        # STEP 3: Determine endianness by checking the magic number
        # Parse magic number to determine endianness
        # Try both byte orders to detect the correct one
        # I -> unsigned int (4 bytes)
        magic_big = struct.unpack('>I', global_header[:4])[0]
        magic_little = struct.unpack('<I', global_header[:4])[0]

        if magic_big == 0xa1b2c3d4 or magic_big == 0xa1b23c4d:
            endian = '>'  # Big-endian
        elif magic_little == 0xa1b2c3d4 or magic_little == 0xa1b23c4d:
            endian = '<'  # Little-endian
        else:
            print("Unknown magic number, cannot determine endianness")
            exit(1)
    
        #print(f"Detected byte order: {'Big-endian' if endian == '>' else 'Little-endian' if endian == '<' else 'Native'}")
    
        packet_count = 0

        packets = []
        while True:
            # STEP 4: Read packet header (next 16 bytes)
            packet_header = f.read(16)     # Read the packet header (next 16 bytes)
            if len(packet_header) < 16:    # If less than 16 bytes are read, end of file is reached
                break
        
        # STEP 5: Determine the length of the packet data
        # Unpack the packet header to get the length of the packet data
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('{}IIII'.format(endian), packet_header)
        # STEP 6: Read the packet data
            packet_data = f.read(incl_len) # Read the packet data based on incl_len
            if len(packet_data) < incl_len: # If less data is read than expected, break
                print("Incomplete packet data")
                break
            packet_count += 1
            packets.append((ts_sec + ts_usec/ 1e6, packet_data)) # Just add time and the data into a packet list
        
        return packets

def ethernet(data):
    # parse the data from ethernet header

    dst_mac, src_mac, eth_type = struct.unpack('!6s6sH', data[:14])
    return eth_type, data[14:] # if 0x0800 it IPv4, 14 bytes because that's how big the ethernet header is

def ip(data):
    # parse the data from ip header

    version_ihl = data[0]
    if isinstance(version_ihl, str):
        version_ihl = ord(version_ihl)
    ihl = version_ihl & 0x0F
    iph_length = ihl * 4 # get ip header
    total_len = struct.unpack('!H', data[2:4])[0] # get total length of everything for later
    src_ip = '.'.join(map(str, data[12:16])) # get the source ip
    dst_ip = '.'.join(map(str, data[16:20])) # get the destination ip
    protocol = data[9]
    return protocol, src_ip, dst_ip, iph_length, total_len, data[iph_length:] # return all the information

def tcp(data):
    # parse the data from the tcp header

    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14]) # get source port, destination port, and all other things needed
    offset = (offset_reserved_flags >> 12) * 4 # tcp header
    flags = offset_reserved_flags & 0x01FF # get the flags for fin, syn and rst
    fin = bool(flags & 0x001) #check first bit for fin
    syn = bool(flags & 0x002) # check second bit for syn
    rst = bool(flags & 0x004) # check third bit for rst
    ack_flag = bool(flags & 0x010) # check for ack
    window_size = struct.unpack('!H', data[14:16])[0] # get the window size for last question
    payload = data[offset:] # rest of the data
    return src_port, dst_port, syn, fin, rst, ack_flag, ack, seq, window_size, len(payload), offset

def connection_data(connections):
    # for part b (and a bit of part c and d) basically just prints out all the information for each connection

    count = 1 # count every connection
    complete_connections = 0
    reset_connections = 0
    conn_before_cap = 0
    connection_times = []
    total_packets_list = []
    window_list = []
    for key, values in connections.items(): # for every connection print out all the necessary information
        print("Connection {}:".format(count))
        print("Source Address: {}".format(values['src_ip']))
        print("Destination address: {}".format(values['dst_ip']))
        print("Source Port: {}".format(values['src_port']))
        print("Destination Port: {}".format(values['dst_port']))
    
        # do status check for R and S#F#
        Status = "S{}F{}".format(values['syn'], values['fin'])
        # if syn is 1 or bigger and fin is 1 or bigger, make complete tcp connections one more
        if (values['syn'] >= 1 and values['fin'] >= 1):
            complete_connections += 1
            window_list += values['window_sizes']
        
        # look for connections before capture started
        if (values['syn'] == 0):
            conn_before_cap += 1

        # look for number of reset TCP connections
        if (values["rst"] > 0):
            Status = 'R'
            reset_connections += 1

        print("Status: {}".format(Status))

        # if there's no end time don't do this
        # print out all of the times, packets and bytes for each connection
        if (values["end_time"] != 0):
            print("Start time: {} seconds".format(values['start_time']))
            print("End Time: {} seconds".format(values['end_time']))
            duration = round((values['end_time'] - values['start_time']), 6)
            print("Duration: {} seconds".format(duration))
            connection_times.append(duration) # for mean, min, and max for times
            
            print("Number of packets sent from Source to Destination: {}".format(values['src_to_dst']))
            print("Number of packets sent from Destination to Source: {}".format(values['dst_to_src']))
            total_packets = values['src_to_dst'] + values['dst_to_src']
            print("Total number of packets: {}".format(total_packets))
            total_packets_list.append(total_packets) # for mean, min, and max for packets
            
            print("Number of data bytes sent from Source to Destination: {}".format(values['bytes_to_dst']))
            print("Number of data bytes sent from Destination to Source: {}".format(values['bytes_to_src']))
            total_bytes = values['bytes_to_dst'] + values['bytes_to_src']
            print("Total number of data bytes: {}".format(total_bytes))

        print("END\n")
        print("+++++++++++++++++++++++++++++++++\n")
        count += 1
    return complete_connections, reset_connections, conn_before_cap, connection_times, total_packets_list, window_list

def make_key(src_ip, src_port, dst_ip, dst_port):
    # makes sure there's not duplicates by adding a key for the (src_ip, src_port) and (dst_ip, dst_port) that we already have

    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port)
    else:
        return (dst_ip, dst_port, src_ip, src_port)


def main():
    # kinda put a lot in this main function, probably should have split it up into smaller functions - but it works so I can't complain

    if (len(sys.argv) < 2):
        print("No website in command line")
        sys.exit(1)
    PCAP_FILE = sys.argv[1]
    # if reading the file dosen't work (which it should because I've tested it like 5 times) uncomment the following line and replace the file with the path to actually open it
    PCAP_FILE = 'sample-capture-file.cap' 
    packets = read_pcap(PCAP_FILE)
    connections = {} # (src_ip, src_port, dst_ip, dst_port)
    ethernet_total = []
    ip_total = []
    connection_times = []
    RTT_times = []

    # unpack ethernet
    for ts, data1 in packets:
        eth_type, payload_ethernet = ethernet(data1)
        ethernet_total.append((payload_ethernet, ts - packets[0][0])) # gets the payload without the first 14 and the time (thats not in 2006 lol)
    # unpack ip
    for data2, ts1 in ethernet_total:
        protocol, src_ip, dst_ip, ip_header, total_length, payload_ip = ip(data2)
        ip_total.append((payload_ip, src_ip, dst_ip, ts1, ip_header, total_length)) # get the payload, source ip, destination ip, time, ip_header and total length from ip
    # unpack tcp and put it into a dictionary
    for data3, sip, dip, ts2, ip_header2, total_length2 in ip_total:
        src_port, dst_port, syn, fin, rst, ack_flag, ack, seq, window_size, payload, tcp_header = tcp(data3) # unpack all information from tcp
        payload = total_length2 - ip_header2 - tcp_header # get the total number of data bytes (from IP_header.total_len - IP_header.ip_header_len -TCP_header.data_offse)
        key = make_key(sip, src_port, dip, dst_port) # make sure there's no duplicates
        if key not in connections: # make new dictionary for all the values needed in each connection (really should have done classes but too late now)
            connections[key] = {
                "dst_ip": dip, "src_ip": sip, "dst_port": dst_port, 
                "src_port": src_port, "syn": 0, "fin": 0, "rst": 0, 
                "ack_flag": ack_flag, "start_time": round(ts2, 6), "end_time": 0,
                "src_to_dst": 0, "dst_to_src": 0, "bytes_to_dst": 0,
                "bytes_to_src": 0, "not_acked_src": {}, "not_acked_dst": {},
                "window_sizes": []
            }
        expected_ack = 0 # get the ack for rtt
        connections[key]["window_sizes"].append(window_size) # add window size to list of windows

        # if the source ip is the same as the connection source ip, then add number of packets going from source to destination
        if (sip == connections[key]["src_ip"]):
            connections[key]["src_to_dst"] += 1
            connections[key]["bytes_to_dst"] += payload
            unacked = connections[key]["not_acked_src"]
            other_unacked = connections[key]["not_acked_dst"]
        else:
            # do the same thing but for destination ip
            connections[key]["dst_to_src"] += 1
            connections[key]["bytes_to_src"] += payload
            unacked = connections[key]["not_acked_dst"]
            other_unacked = connections[key]["not_acked_src"]
        # check syn flag
        if (syn == True):
            connections[key]["syn"] += 1 
            expected_ack += 1 # SYN/FIN each consume one sequence number
        # check fin flag and add end time if it's the end
        if (fin == True):
            connections[key]["fin"] += 1 
            connections[key]["end_time"] = round(ts2, 6)
            expected_ack += 1
        # check rst flag
        if (rst == True):
            connections[key]["rst"] += 1 
        expected_ack += seq + payload # for rtt to see when the ack comes back
        unacked[expected_ack] = ts2 # add a time for the ack to see rtt

        if (ack_flag == True): # add times to rtt time if ack flag is set and ack is unacked previously
            if (ack in other_unacked):
                time = other_unacked.pop(ack)
                if 0.001 < ts2 - time < 60: # for edge cases
                    RTT_times.append(round((ts2 - time), 6))
    print("A) Total number of connections: {}\n".format(len(connections))) # total connections is length of the array named "connections"
    print("B) Connections' details:\n")

    # get all the information form part B for part C and D
    complete_connections, reset_connections, conn_before_cap, connection_times, total_packets_list, window_list = connection_data(connections)
    
    open_conn = len(connections) - complete_connections # get open connections
    # input all the information
    print("C) General\n")
    print("The total number of complete TCP connections: {}".format(complete_connections))
    print("The number of reset TCP connections: {}".format(reset_connections))
    print("The number of TCP connections that were still open when the trace capture ended: {}".format(open_conn))
    print("The number of TCP connections established before the capture started: {}\n".format(conn_before_cap))

    # next three are very similar so I won't explain all three, just this one
    print("D) Complete TCP connections:\n")
    print("Minimum time duration: {} seconds".format(min(connection_times)))     # get minimum from min
    mean_time = round((sum(connection_times) / len(connection_times)),6) # get the mean and round it to 6 decimals
    print("Mean time duration: {} seconds".format(mean_time))
    print("Maximum time duration: {} seconds\n".format(max(connection_times))) # get max from max()

    print("Minimum RTT value: {} seconds".format(min(RTT_times)))
    mean_RTT = round((sum(RTT_times) / len(RTT_times)),6)
    print("Mean RTT value: {} seconds".format(mean_RTT))
    print("Maximum RTT value: {} seconds\n".format(max(RTT_times)))

    print("Minimum number of packets including both send/received: {}".format(min(total_packets_list)))
    mean_packets = round((sum(total_packets_list) / len(total_packets_list)),6)
    print("Mean number of packets including both send/received: {}".format(mean_packets))
    print("Maximum number of packets including both send/received: {}\n".format(max(total_packets_list)))

    print("Minimum receive window size including both send/received: {} bytes".format(min(window_list)))
    mean_window = round((sum(window_list) / len(window_list)),6)
    print("Mean receive window size including both send/received: {} bytes".format(mean_window))
    print("Maximum receive window size including both send/received: {} bytes".format(max(window_list)))


if __name__ == '__main__':
    main()
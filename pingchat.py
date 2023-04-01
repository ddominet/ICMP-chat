import socket
import struct
import threading


def send_message(dest_addr, message):
    # create a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # ensure message is less than or equal to 50 bytes
    if len(message) > 50:
        fragments = [message[i : i + 50] for i in range(0, len(message), 50)]
    else:
        fragments = [message]

    # pad the last fragment if necessary
    last_fragment_len = len(fragments[-1])
    if last_fragment_len < 50:
        fragments[-1] += "\0" * (50 - last_fragment_len)

    # send each fragment in a separate ICMP packet
    for i, fragment in enumerate(fragments):
        # create the ICMP header
        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 1
        icmp_seq = i + 1

        # create the ICMP packet
        icmp_header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq
        )
        data = fragment.encode("utf-8")
        packet = icmp_header + data

        # calculate the checksum
        checksum = 0
        for j in range(0, len(packet), 2):
            checksum += (packet[j] << 8) + packet[j + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        packet = packet[:2] + struct.pack("!H", checksum) + packet[4:]

        # send the packet
        s.sendto(packet, (dest_addr, 0))

    s.close()


def receive_message():
    # create a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    # receive the packet
    packet = s.recvfrom(65565)[0]

    # parse the IP header
    ip_header = packet[:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    src_addr = socket.inet_ntoa(iph[8])

    # parse the ICMP header
    icmp_header = packet[20:28]
    icmph = struct.unpack("!BBHHH", icmp_header)

    # get the message data
    message_data = packet[28:]

    # get the sequence number and fragment count from the ICMP header
    sequence_num = icmph[4]
    fragment_count = icmph[3]

    # parse the message fragments
    fragment_data = []
    for i in range(fragment_count):
        fragment_start = i * 50
        fragment_end = min((i + 1) * 50, len(message_data))
        fragment = message_data[fragment_start:fragment_end]
        fragment_data.append(fragment.decode("utf-8"))

    message = "".join(fragment_data)

    s.close()

    return src_addr, message


def receiver():
    while True:
        # receive a message
        src_addr, message = receive_message()

        # print the message
        print(f"Received message from {src_addr}: {message}")


def sender():
    while True:
        message = input("You: ")
        send_message(dest_addr, message)


if __name__ == "__main__":
    dest_addr = input("Enter destination address to establish connection: ")
    thread1 = threading.Thread(target=receiver)
    thread2 = threading.Thread(target=sender)

    thread1.start()
    thread2.start()

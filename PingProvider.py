import subprocess
import sys
import re
import socket

def ping(domain):
    # Thực hiện lệnh ping 10 gói tin ICMP
    result = subprocess.run(['ping', '-n', '10', domain], capture_output=True, text=True)
    output = result.stdout

    # Tìm kiếm thông tin packet loss, số gói tin gửi đi và thời gian latency
    packets_sent = re.search(r"Packets: Sent = (\d+)", output)
    packet_loss = re.search(r"(\d+)% loss", output)
    latency = re.search(r"Average = (\d+ms)", output)

    if packets_sent:
        packets_sent = packets_sent.group(1)
    else:
        packets_sent = "N/A"

    if packet_loss:
        packet_loss = packet_loss.group(1) + "%"
    else:
        packet_loss = "N/A"

    if latency:
        latency = latency.group(1)
    else:
        latency = "N/A"

    return packets_sent, packet_loss, latency

def resolve_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "N/A"  # In case domain resolution fails

def process_file(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Tạo tiêu đề cho bảng kết quả
        print(f"{'Domain':<40}{'Country':<15}{'IP Address':<20}{'Packets Sent':<15}{'Packet Loss':<15}{'Avg Latency'}")
        print("=" * 115)

        # Xử lý từng dòng trong file
        for line in lines:
            country, domain = line.strip().split(' ', 1)  # Tách theo khoảng trắng đầu tiên
            ip_address = resolve_ip(domain)
            packets_sent, packet_loss, latency = ping(domain)
            print(f"{domain:<40}{country:<15}{ip_address:<20}{packets_sent:<15}{packet_loss:<15}{latency}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_ping.py <data_file>")
    else:
        process_file(sys.argv[1])

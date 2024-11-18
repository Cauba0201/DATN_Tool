import subprocess
import sys
import re
import socket
import psycopg2  # Import for PostgreSQL connection
from concurrent.futures import ThreadPoolExecutor, as_completed  # Import for multithreading
from ipwhois import IPWhois  # Import for getting ISP information
import time  # Import to use sleep for periodic execution
from datetime import datetime, timedelta

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

def get_isp(ip_address):
    try:
        # Sử dụng ipwhois để lấy thông tin về nhà mạng từ địa chỉ IP
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        isp = result['network']['name'] if 'network' in result and 'name' in result['network'] else "Unknown"
        return isp
    except Exception as e:
        print(f"Error getting ISP for {ip_address}: {e}")
        return "Unknown"

def insert_data_to_db(country, ip, packets_sent, packet_loss, avg_latency, isp):
    try:
        # Connect to your PostgreSQL database
        connection = psycopg2.connect(
            user="postgres",
            password="a",
            host="127.0.0.1",
            port="5432",
            database="postgres"
        )
        cursor = connection.cursor()

        # Insert the data, including ISP information
        insert_query = """
        INSERT INTO public.testping (country, ip, packets_sent, packet_loss, avg_latency, isp)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (country, ip, packets_sent, packet_loss, avg_latency, isp))
        connection.commit()
        print(f"Data for {country} inserted successfully.")

    except Exception as e:
        print(f"Error inserting data: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def process_domain(country, domain):
    ip_address = resolve_ip(domain)
    packets_sent, packet_loss, latency = ping(domain)
    isp = get_isp(ip_address) if ip_address != "N/A" else "Unknown"
    print(f"{domain:<40}{country:<15}{ip_address:<20}{packets_sent:<15}{packet_loss:<15}{latency:<15}{isp}")

    # Insert into the database
    insert_data_to_db(country, ip_address, packets_sent, packet_loss, latency, isp)

def process_file(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Tạo tiêu đề cho bảng kết quả
        print(f"{'Domain':<40}{'Country':<15}{'IP Address':<20}{'Packets Sent':<15}{'Packet Loss':<15}{'Avg Latency':<15}{'ISP'}")
        print("=" * 130)

        # Sử dụng ThreadPoolExecutor để chạy nhiều tiến trình ping song song
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for line in lines:
                country, domain = line.strip().split(' ', 1)  # Tách theo khoảng trắng đầu tiên
                futures.append(executor.submit(process_domain, country, domain))

            # Đảm bảo tất cả các tiến trình hoàn thành
            for future in as_completed(futures):
                try:
                    future.result()  # Xử lý kết quả của từng tiến trình
                except Exception as e:
                    print(f"Error in thread: {e}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"Error: {e}")

def ping_loop(file_path):
    """
    Hàm để thực hiện ping cứ mỗi giờ theo giờ hiện tại.
    """
    while True:
        print(f"\nStarting new ping cycle...")
        process_file(file_path)  # Thực hiện ping tất cả các host

        # Tính thời gian đến giờ tiếp theo
        now = datetime.now()
        next_hour = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        time_to_next_hour = (next_hour - now).total_seconds()

        print(f"Waiting until the next hour at {next_hour.strftime('%I:%M %p')}...\n")
        time.sleep(time_to_next_hour)  # Chờ đến đầu giờ tiếp theo

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_ping.py <data_file>")
    else:
        file_path = sys.argv[1]
        ping_loop(file_path)

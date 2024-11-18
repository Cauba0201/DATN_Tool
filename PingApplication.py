import subprocess
import sys
import re
import socket
import psycopg2  # Import for PostgreSQL connection
from concurrent.futures import ThreadPoolExecutor, as_completed  # Import for multithreading
from ipwhois import IPWhois  # Import for getting ISP information
import time  # Import to use sleep for periodic execution

def ping(domain):
    # Perform a ping with 10 ICMP packets
    result = subprocess.run(['ping', '-n', '10', domain], capture_output=True, text=True)
    output = result.stdout

    # Extract packet loss, packets sent, and latency information
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
        # Use ipwhois to get ISP information from the IP address
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        isp = result['network']['name'] if 'network' in result and 'name' in result['network'] else "Unknown"
        return isp
    except Exception as e:
        print(f"Error getting ISP for {ip_address}: {e}")
        return "Unknown"

def insert_data_to_db(application_name, ip, packets_sent, packet_loss, avg_latency, isp):
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
        INSERT INTO public.PINGAPP (application_name, ip, packets_sent, packet_loss, avg_latency, isp)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (application_name, ip, packets_sent, packet_loss, avg_latency, isp))
        connection.commit()
        print(f"Data for {application_name} inserted successfully.")

    except Exception as e:
        print(f"Error inserting data: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def process_domain(application_name, domain):
    ip_address = resolve_ip(domain)
    packets_sent, packet_loss, latency = ping(domain)
    isp = get_isp(ip_address) if ip_address != "N/A" else "Unknown"
    print(f"{domain:<40}{application_name:<15}{ip_address:<20}{packets_sent:<15}{packet_loss:<15}{latency:<15}{isp}")

    # Insert into the database
    insert_data_to_db(application_name, ip_address, packets_sent, packet_loss, latency, isp)

def process_file(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Print header for the results table
        print(f"{'Domain':<40}{'Application Name':<15}{'IP Address':<20}{'Packets Sent':<15}{'Packet Loss':<15}{'Avg Latency':<15}{'ISP'}")
        print("=" * 130)

        # Use ThreadPoolExecutor to run multiple pings concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for line in lines:
                application_name, domain = line.strip().split(' ', 1)  # Split on the first whitespace
                futures.append(executor.submit(process_domain, application_name, domain))

            # Ensure all threads complete
            for future in as_completed(futures):
                try:
                    future.result()  # Process the result of each thread
                except Exception as e:
                    print(f"Error in thread: {e}")

    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"Error: {e}")

def ping_loop(file_path, interval=60):
    """
    Function to perform continuous ping every `interval` seconds (default is 300 seconds = 5 minutes).
    """
    while True:
        print(f"\nStarting new ping cycle...")
        process_file(file_path)  # Ping all hosts
        print(f"Waiting for {interval // 60} minutes before next cycle...\n")
        time.sleep(interval)  # Wait `interval` seconds before the next cycle

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_ping.py <data_file>")
    else:
        file_path = sys.argv[1]
        ping_loop(file_path, interval=60)  # Default 5 minutes (300 seconds)

import subprocess
import sys
import re
import socket
import psycopg2  # Import for PostgreSQL connection
from concurrent.futures import ThreadPoolExecutor, as_completed  # Import for multithreading
from ipwhois import IPWhois  # Import for getting ISP information
import requests  # Import for getting external IP info
import time  # Import to use sleep for periodic execution

def ping(domain):
    # Perform a ping with 10 ICMP packets
    result = subprocess.run(['ping', '-n', '10', domain], capture_output=True, text=True)
    output = result.stdout

    # Extract packet loss, packets sent, and latency information
    packets_sent = re.search(r"Packets: Sent = (\d+)", output)
    packet_loss = re.search(r"(\d+)% loss", output)
    latency = re.search(r"Average = (\d+ms)", output)

    packets_sent = packets_sent.group(1) if packets_sent else "N/A"
    packet_loss = packet_loss.group(1) if packet_loss else "N/A"
    latency = latency.group(1) if latency else "N/A"

    return packets_sent, packet_loss, latency

def resolve_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "N/A"  # In case domain resolution fails

def get_isp(ip_address):
    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        isp = result['network']['name'] if 'network' in result and 'name' in result['network'] else "Unknown"
        return isp
    except Exception as e:
        print(f"Error getting ISP for {ip_address}: {e}")
        return "Unknown"

def get_local_isp():
    try:
        # Fetch external IP to determine ISP
        external_ip = requests.get("https://api64.ipify.org").text
        obj = IPWhois(external_ip)
        result = obj.lookup_rdap()
        local_isp = result['network']['name'] if 'network' in result and 'name' in result['network'] else "Unknown"
        return local_isp
    except Exception as e:
        print(f"Error getting local ISP: {e}")
        return "Unknown"

def insert_data_to_db(country, ip, packets_sent, packet_loss, avg_latency, isp, local_isp):
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="a",
            host="127.0.0.1",
            port="5432",
            database="postgres"
        )
        cursor = connection.cursor()

        # Insert the data, including ISP and Local ISP information
        insert_query = """
        INSERT INTO public.testping (country, ip, packets_sent, packet_loss, avg_latency, isp, local_isp)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (country, ip, packets_sent, packet_loss, avg_latency, isp, local_isp))
        connection.commit()
        print(f"Data for {country} inserted successfully.")

    except Exception as e:
        print(f"Error inserting data: {e}")
    finally:
        if connection:
            cursor.close()
            connection.close()

def process_domain(application_name, domain, local_isp):
    ip_address = resolve_ip(domain)
    packets_sent, packet_loss, latency = ping(domain)
    isp = get_isp(ip_address) if ip_address != "N/A" else "Unknown"
    print(f"{domain:<40}{application_name:<15}{ip_address:<20}{packets_sent:<15}{packet_loss:<15}{latency:<15}{isp:<20}{local_isp}")

    # Insert into the database
    insert_data_to_db(application_name, ip_address, packets_sent, packet_loss, latency, isp, local_isp)

def process_file(file_path):
    try:
        local_isp = get_local_isp()  # Get the ISP of the machine running the script

        with open(file_path, 'r') as file:
            lines = file.readlines()

        # Print header for the results table
        print(f"{'Domain':<40}{'Application Name':<15}{'IP Address':<20}{'Packets Sent':<15}{'Packet Loss':<15}{'Avg Latency':<15}{'ISP':<20}{'Local ISP'}")
        print("=" * 150)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for line in lines:
                application_name, domain = line.strip().split(' ', 1)  # Split on the first whitespace
                futures.append(executor.submit(process_domain, application_name, domain, local_isp))

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
    while True:
        print(f"\nStarting new ping cycle...")
        process_file(file_path)  # Ping all hosts
        print(f"Waiting for {interval // 60} minutes before next cycle...\n")
        time.sleep(interval)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python process_ping.py <data_file>")
    else:
        file_path = sys.argv[1]
        ping_loop(file_path, interval=60)

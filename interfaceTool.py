import socket
import tkinter as tk
from tkinter import filedialog, scrolledtext
from tkinter import ttk  # For improved styles
from threading import Thread, Event
import time
import subprocess
import re

import requests
from ipwhois import IPWhois


class PingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("National Connection Quality Monitoring System")
        self.root.geometry("1000x700")  # Set a larger window size for better layout
        self.root.resizable(True, True)  # Allow resizing

        self.file_path = None
        self.stop_event = Event()

        # Define styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TButton", font=("Helvetica", 12))
        self.style.configure("TLabel", font=("Helvetica", 12))

        # Colors for Wireshark-like theme
        self.primary_bg = "#2B3E50"  # Dark blue
        self.secondary_bg = "#34495E"  # Slightly lighter blue
        self.highlight_bg = "#27AE60"  # Green highlight
        self.text_color = "#ECF0F1"  # Light text
        self.stop_color_button = "#FF0000" #red
        self.start_color_button = "#00FF00" #green
        self.blue_color = "#0099FF" #blue

        self.root.configure(bg=self.primary_bg)

        # Add menu bar
        self.create_menu_bar()

        # Header
        # header = tk.Label(root, text="National Connection Quality Monitoring System", font=("Helvetica", 18, "bold"), bg=self.highlight_bg, fg="white")
        # header.pack(fill=tk.X, pady=10)

        # Main frame for content
        main_frame = tk.Frame(root, bg=self.primary_bg, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left configuration panel
        config_frame = tk.Frame(main_frame, relief=tk.GROOVE, borderwidth=2, bg=self.secondary_bg, padx=10, pady=10)
        config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(config_frame, text="Configuration", font=("Helvetica", 14, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)

        # File selection
        file_label = ttk.Label(config_frame, text="Select a file:", background=self.secondary_bg, foreground=self.text_color)
        file_label.pack(anchor=tk.W, pady=5)

        file_frame = tk.Frame(config_frame, bg=self.secondary_bg)
        file_frame.pack(fill=tk.X, pady=5)

        self.file_label = ttk.Label(file_frame, text="No file selected", width=30, anchor="w")
        self.file_label.pack(side=tk.LEFT, padx=5)

        self.select_button = tk.Button(file_frame, text="Browse", command=self.select_file, bg=self.blue_color, fg="white", font=("Helvetica", 12))
        self.select_button.pack(side=tk.RIGHT, padx=5)

        # Ping settings
        tk.Label(config_frame, text="Ping Settings:", font=("Helvetica", 12, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=10)

        tk.Label(config_frame, text="Number of Pings:", bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)
        self.ping_count = ttk.Entry(config_frame, width=10)
        self.ping_count.insert(0, "4")
        self.ping_count.pack(anchor=tk.W, pady=5)

        tk.Label(config_frame, text="Interval (seconds):", bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)
        self.ping_interval = ttk.Entry(config_frame, width=10)
        self.ping_interval.insert(0, "60")
        self.ping_interval.pack(anchor=tk.W, pady=5)

        # Tracert option
        self.tracert_enabled = tk.BooleanVar()
        tracert_checkbox = ttk.Checkbutton(config_frame, text="Enable Tracert", variable=self.tracert_enabled)
        tracert_checkbox.pack(anchor=tk.W, pady=5)

        # Start/Stop buttons
        self.start_button = tk.Button(config_frame, text="Start", command=self.start_test, state=tk.DISABLED,  fg="white", font=("Helvetica", 12))
        self.start_button.pack(fill=tk.X, pady=10)

        self.stop_button = tk.Button(config_frame, text="Stop", command=self.stop_test, state=tk.DISABLED, bg=self.stop_color_button, fg="white", font=("Helvetica", 12))
        self.stop_button.pack(fill=tk.X, pady=5)

        # Right result panel
        result_frame = tk.Frame(main_frame, relief=tk.GROOVE, borderwidth=2, bg=self.secondary_bg, padx=10, pady=10)
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(result_frame, text="Results", font=("Helvetica", 14, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)

        self.output_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, font=("Courier", 10), bg="#2B3E50", fg=self.text_color, height=25)
        self.output_area.pack(fill=tk.BOTH, expand=True, pady=10)

    def create_menu_bar(self):
        menu_bar = tk.Menu(self.root)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Open", command=self.select_file)
        file_menu.add_command(label="Save", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Settings menu
        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Preferences")
        menu_bar.add_cascade(label="Settings", menu=settings_menu)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menu_bar)

    def show_about(self):
        tk.messagebox.showinfo("About", "National Connection Quality Monitoring System\nVersion 1.0")

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_area.get("1.0", tk.END))

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.file_label.config(text=f"Selected: {self.file_path}")
            self.start_button.config(state=tk.NORMAL)
        else:
            self.file_label.config(text="No file selected")

    def start_test(self):
        if not self.file_path:
            return

        self.stop_event.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Run test process in a separate thread
        self.test_thread = Thread(target=self.test_loop)
        self.test_thread.start()

    def stop_test(self):
        self.stop_event.set()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def test_loop(self):
        interval = int(self.ping_interval.get())
        while not self.stop_event.is_set():
            self.output_area.insert(tk.END, "Starting new test cycle...\n")
            self.output_area.see(tk.END)

            if self.file_path:
                with open(self.file_path, 'r') as file:
                    lines = file.readlines()
                    for line in lines:
                        if self.stop_event.is_set():
                            break
                        domain = line.strip()
                        ping_result = self.ping(domain)
                        self.output_area.insert(tk.END, ping_result + "\n")
                        if self.tracert_enabled.get():
                            tracert_result = self.tracert(domain)
                            self.output_area.insert(tk.END, tracert_result + "\n")
                        self.output_area.see(tk.END)

            self.output_area.insert(tk.END, "Waiting for next cycle...\n\n")
            self.output_area.see(tk.END)
            time.sleep(interval)  # Wait specified seconds before next cycle

    def ping(self, domain):
        try:
            count = self.ping_count.get()
            result = subprocess.run(['ping', '-n', '10', domain], capture_output=True, text=True)
            output = result.stdout

            # Kiểm tra đầu ra có lỗi không
            if result.returncode != 0:
                return f"Error pinging {domain}: Host unreachable or invalid."

            # Sử dụng regex để lấy thông tin gói mất và độ trễ trung bình
            packets_sent = re.search(r"Packets: Sent = (\d+)", output)
            packet_loss = re.search(r"(\d+)% loss", output)
            latency = re.search(r"Average = (\d+)ms", output)

            packets_sent = int(packets_sent.group(1)) if packets_sent else "N/A"
            packet_loss = int(packet_loss.group(1)) if packet_loss else "N/A"
            latency = int(latency.group(1)) if latency else "N/A"

            return f"{domain}: Packet Loss = {packet_loss}%, Latency = {latency}ms, packet Sent = {packets_sent} "
        except subprocess.TimeoutExpired:
            return f"Timeout while pinging {domain}."
        except Exception as e:
            return f"Error pinging {domain}: {e}"

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
                local_isp = result['network']['name'] if 'network' in result and 'name' in result[
                    'network'] else "Unknown"
                return local_isp
            except Exception as e:
                print(f"Error getting local ISP: {e}")
                return "Unknown"

    def tracert(self, domain):
        try:
            result = subprocess.run(['tracert', domain], capture_output=True, text=True)
            output = result.stdout

            # Extract hop information
            hops = re.findall(r"(\d+)\s+<.*?>\s+([\d.]+ ms)+.*", output)
            hop_details = " | ".join([f"Hop {hop[0]}: {hop[1]}" for hop in hops])

            return f"{domain}: Traceroute Details:\n{hop_details if hop_details else output}"
        except Exception as e:
            return f"Error tracing route to {domain}: {e}"

if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()
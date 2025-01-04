import socket
import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, messagebox
from tkinter import ttk
from threading import Thread, Event
import time
import subprocess
import re
import platform
import requests
from ipwhois import IPWhois
import gspread
from google.oauth2.service_account import Credentials

#API google sheet
scopes = ["https://www.googleapis.com/auth/spreadsheets"]
creds = Credentials.from_service_account_file("credentials.json", scopes=scopes)
client = gspread.authorize(creds)
sheet_id = "1xd2kk9R7lQJQfJqTxdT_2AOqxmBVEHv209hWuvt_o3Y"
workbook = client.open_by_key(sheet_id)

class PingApp:
    def __init__(self, root):
        self.test_thread = None
        self.root = root
        self.root.title("National Connection Quality Monitoring System")
        self.root.geometry("1244x850")  # Set a larger window size for better layout
        self.root.resizable(True, True)  # Allow resizing
        self.host_list = []  # List of IPs/Domains

        self.stop_event = Event()

        # Define styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TButton", font=("Helvetica", 12))
        self.style.configure("TLabel", font=("Helvetica", 12))

        # Colors for Wireshark-like theme
        self.primary_bg = "#2B3E50"  # Dark blue
        self.secondary_bg = "#34495E"  # Slightly lighter blue
        self.text_color = "#ECF0F1"  # Light text
        self.black_bg = "#000000" # black

        self.root.configure(bg=self.primary_bg)

        # Add menu bar
        self.create_menu_bar()

        # Main frame for content
        main_frame = tk.Frame(root, bg=self.primary_bg, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left configuration panel
        config_frame = tk.Frame(main_frame, relief=tk.GROOVE, borderwidth=2, bg=self.secondary_bg, padx=10, pady=10)
        config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(config_frame, text="IP Address & Domain", font=("Helvetica", 14, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)

        # Display host list
        self.lst_hosts = tk.Listbox(config_frame, height=15, width=50, font=("Courier", 12))
        self.lst_hosts.pack(pady=10)

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

        # Tracert settings
        tk.Label(config_frame, text="Tracert Settings:", font=("Helvetica", 12, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=10)

        self.tracert_enabled = tk.BooleanVar(value=True)
        self.tracert_checkbox = tk.Checkbutton(config_frame, text="Enable Tracert", variable=self.tracert_enabled, bg=self.secondary_bg, fg=self.text_color, selectcolor=self.secondary_bg)
        self.tracert_checkbox.pack(anchor=tk.W, pady=5)

        tk.Label(config_frame, text="Max Hops:", bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)
        self.tracert_max_hops = ttk.Entry(config_frame, width=10)
        self.tracert_max_hops.insert(0, "30")
        self.tracert_max_hops.pack(anchor=tk.W, pady=5)

        # Start/Stop buttons
        self.start_button = tk.Button(config_frame, text="Start", command=self.start_test, font=("Helvetica", 12))
        self.start_button.pack(fill=tk.X, pady=10)

        self.stop_button = tk.Button(config_frame, text="Stop", command=self.stop_test, font=("Helvetica", 12))
        self.stop_button.pack(fill=tk.X, pady=5)

        # Right result panel
        result_frame = tk.Frame(main_frame, relief=tk.GROOVE, borderwidth=2, bg=self.secondary_bg, padx=10, pady=10)
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(result_frame, text="Results", font=("Helvetica", 14, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)

        self.output_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, font=("Courier", 10), bg=self.black_bg, fg=self.text_color, height=25)
        self.output_area.pack(fill=tk.BOTH, expand=True, pady=10)

    def update_host_display(self):
        # Update Listbox display
        self.lst_hosts.delete(0, tk.END)
        for host in self.host_list:
            self.lst_hosts.insert(tk.END, f"{host}")


    def create_menu_bar(self):
        menu_bar = tk.Menu(self.root)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Save", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Host management menu
        manage_hosts_menu = tk.Menu(menu_bar, tearoff=0)
        manage_hosts_menu.add_command(label="Manage Hosts", command=self.open_list_host_form)
        menu_bar.add_cascade(label="Manager", menu=manage_hosts_menu)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menu_bar)

    def show_about(self):
        tk.messagebox.showinfo("About System", "National Connection Quality Monitoring System\nVersion 1.0 \nDesign by An Nguyen")


    def open_list_host_form(self):
        form_list_host = FormListHost(self.root, self.host_list)
        self.root.wait_window(form_list_host.top)  # Wait for the child form to close
        self.host_list = form_list_host.host_list  # Update host list
        self.update_host_display()

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_area.get("1.0", tk.END))

    def start_test(self):
        if not self.host_list:
            messagebox.showwarning("Warning", "No hosts to test!")
            return
        self.stop_event.clear()

        # Run test process in a separate thread
        self.test_thread = Thread(target=self.test_loop)
        self.test_thread.start()

    def stop_test(self):
        self.stop_event.set()
        self.output_area.insert(tk.END, ">>> Stopped the cycle!\n")
        self.output_area.see(tk.END)

    def test_loop(self):
        interval = int(self.ping_interval.get())
        while not self.stop_event.is_set():
            self.output_area.insert(tk.END, ">>> Starting new test cycle...\n")
            self.output_area.see(tk.END)

            for domain in self.host_list:
                if self.stop_event.is_set():
                    break

                # Run ping
                ping_thread = Thread(target=self.execute_ping, args=(domain,))
                ping_thread.start()
                ping_thread.join()

                # Run tracert if enabled
                if self.tracert_enabled.get():
                    tracert_thread = Thread(target=self.execute_tracert, args=(domain,))
                    tracert_thread.start()
                    tracert_thread.join()

            self.output_area.insert(tk.END, ">>> Waiting for next cycle...\n\n")
            self.output_area.see(tk.END)
            time.sleep(interval)  # Wait specified seconds before next cycle

    def ping(self, domain):
        try:
            ping_count = int(self.ping_count.get())
            if platform.system() == "Windows":
                command = ['ping', '-n', str(ping_count), domain]
            else:
                command = ['ping', '-c', str(ping_count), domain]

            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout

            if result.returncode != 0:
                return {
                    "domain": domain,
                    "latency": "N/A",
                    "packet_loss": "N/A",
                    "packets_sent": "N/A",
                    "error": f"Error pinging {domain}: Host unreachable or invalid."
                }

            latency_match = re.search(r"Average = (\d+)ms", output) or re.search(r"avg = (\d+\.\d+) ms", output)
            latency = latency_match.group(1) if latency_match else "N/A"

            packet_loss_match = re.search(r"(\d+)% packet loss", output)
            packet_loss = packet_loss_match.group(1) + "%" if packet_loss_match else "0"

            packets_sent_match = re.search(r"(\d+) packets transmitted", output) or re.search(r"Sent = (\d+)", output)
            packets_sent = packets_sent_match.group(1) if packets_sent_match else "N/A"

            return {
                "domain": domain,
                "latency": latency,
                "packet_loss": packet_loss,
                "packets_sent": packets_sent,
                "error": None
            }
        except Exception as e:
            return {
                "domain": domain,
                "latency": "N/A",
                "packet_loss": "N/A",
                "packets_sent": "N/A",
                "error": str(e)
            }

    def tracert(self, domain):
        try:
            max_hops = self.tracert_max_hops.get()
            if platform.system() == "Windows":
                command = ['tracert', '-h', max_hops, domain]
            else:
                command = ['traceroute', '-m', max_hops, domain]

            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout

            if result.returncode != 0:
                return f"Error tracing route to {domain}: Unable to complete traceroute."

            return f"Traceroute results for {domain}:\n{output}"
        except Exception as e:
            return f"Error tracing route to {domain}: {e}"

    def write_to_sheet(self, domain, packets_sent, packet_loss, latency, country, ip_address, isp, local_isp):
        try:
            sheet = workbook.worksheet("Trang tính1")
            row = [
                time.strftime("%Y-%m-%d %H:%M:%S"),
                domain,
                country,
                ip_address,
                packets_sent,
                packet_loss,
                latency,
                isp,
                local_isp
            ]
            sheet.append_row(row)
        except Exception as e:
            self.output_area.insert(tk.END, f"Error writing to Google Sheets: {e}\n")
            self.output_area.see(tk.END)

    def execute_ping(self, domain):
        result = self.ping(domain)
        if result["error"]:
            self.output_area.insert(tk.END, f"{result['error']}\n")
        else:
            self.output_area.insert(
                tk.END,
                f"{result['domain']}: Latency = {result['latency']}ms, Packet Loss = {result['packet_loss']}%, Packets Sent = {result['packets_sent']}\n"
            )
            # Gọi hàm write_to_sheet với các giá trị cụ thể
            self.write_to_sheet(
                result["domain"],
                result["packets_sent"],
                result["packet_loss"],
                result["latency"]
            )
        self.output_area.see(tk.END)

    def execute_tracert(self, domain):
        result = self.tracert(domain)
        self.output_area.insert(tk.END, result + "\n")
        self.output_area.see(tk.END)

    def resolve_ip(self, domain):
        try:
            ip_address = socket.gethostbyname(domain)
            return ip_address
        except socket.gaierror:
            return "N/A"  # In case domain resolution fails

    def get_isp(self, ip_address):
        try:
            obj = IPWhois(ip_address)
            result = obj.lookup_rdap()
            isp = result['network']['name'] if 'network' in result and 'name' in result['network'] else "Unknown"
            return isp
        except Exception as e:
            self.output_area.insert(tk.END, f"Error getting ISP for {ip_address}: {e}\n")
            self.output_area.see(tk.END)
            return "Unknown"

    def get_local_isp(self):
        try:
            external_ip = requests.get("https://api64.ipify.org").text
            obj = IPWhois(external_ip)
            result = obj.lookup_rdap()
            local_isp = result['network']['name'] if 'network' in result and 'name' in result['network'] else "Unknown"
            return local_isp
        except Exception as e:
            self.output_area.insert(tk.END, f"Error getting local ISP: {e}\n")
            self.output_area.see(tk.END)
            return "Unknown"

    def start_test(self):
        if not self.host_list:
            messagebox.showwarning("Warning", "No hosts to test!")
            return

        self.stop_event.clear()

        local_isp = self.get_local_isp()

        self.test_thread = Thread(target=self.test_loop, args=(local_isp,))
        self.test_thread.start()

    def test_loop(self, local_isp):
        interval = int(self.ping_interval.get())
        while not self.stop_event.is_set():
            self.output_area.insert(tk.END, ">>> Starting new test cycle...\n")
            self.output_area.see(tk.END)

            for domain in self.host_list:
                if self.stop_event.is_set():
                    break
                self.process_domain("Unknown Country", domain, local_isp)

            self.output_area.insert(tk.END, ">>> Waiting for next cycle...\n\n")
            self.output_area.see(tk.END)
            time.sleep(interval)

    def get_country_by_ip(self, ip_address):
        try:
            # URL API của iplocation.net
            url = f"https://api.iplocation.net/?ip={ip_address}"

            # Gửi yêu cầu GET đến API
            response = requests.get(url)

            if response.status_code != 200:
                self.output_area.insert(tk.END, f"Error: API request failed with status code {response.status_code}\n")
                self.output_area.see(tk.END)
                return "Unknown"

            data = response.json()

            # Lấy thông tin country
            country = data.get("country_name", "Unknown")
            return country
        except Exception as e:
            self.output_area.insert(tk.END, f"Error getting country for {ip_address}: {e}\n")
            self.output_area.see(tk.END)
            return "Unknown"

    def process_domain(self, country, domain, local_isp):
        # Lấy địa chỉ IP
        ip_address = self.resolve_ip(domain)
        if ip_address == "N/A":
            self.output_area.insert(tk.END, f"{domain}: Unable to resolve IP\n")
            self.output_area.see(tk.END)
            return

        # Lấy thông tin quốc gia từ API
        detected_country = self.get_country_by_ip(ip_address)

        # Ping domain
        result = self.ping(domain)
        isp = self.get_isp(ip_address)

        if result["error"]:
            self.output_area.insert(tk.END, f"{result['error']}\n")
        else:
            self.output_area.insert(
                tk.END,
                f"IP/Domain = {domain}: Country = {detected_country}, IP = {ip_address}, ISP = {isp}, "
                f"Local ISP = {local_isp}, Latency = {result['latency']}ms, "
                f"Packet Loss = {result['packet_loss']}%, Packets Sent = {result['packets_sent']}\n"
            )

            # Ghi thông tin vào Google Sheets
            self.write_to_sheet(
                domain,
                result["packets_sent"],
                result["packet_loss"],
                result["latency"],
                detected_country,
                ip_address,
                isp,
                local_isp
            )
        self.output_area.see(tk.END)


class FormListHost:
    def __init__(self, parent, host_list):
        self.top = tk.Toplevel(parent)
        self.top.title("Manage Hosts")
        self.top.geometry("400x300")

        self.host_list = host_list.copy()  # Copy the initial list

        # Listbox display
        self.lst_hosts = tk.Listbox(self.top, height=12, width=40, font=("Courier", 12))
        self.lst_hosts.pack(pady=10)

        self.update_host_display()

        # Buttons
        self.btn_add = tk.Button(self.top, text="Add", command=self.add_host, font=("Arial", 10))
        self.btn_add.pack(side=tk.LEFT, padx=5)

        self.btn_edit = tk.Button(self.top, text="Edit", command=self.edit_host, font=("Arial", 10))
        self.btn_edit.pack(side=tk.LEFT, padx=5)

        self.btn_delete = tk.Button(self.top, text="Delete", command=self.delete_host, font=("Arial", 10))
        self.btn_delete.pack(side=tk.LEFT, padx=5)

        self.btn_save = tk.Button(self.top, text="Save & Close", command=self.save_and_close, font=("Arial", 10))
        self.btn_save.pack(side=tk.RIGHT, padx=5)

    def update_host_display(self):
        # Update Listbox display
        self.lst_hosts.delete(0, tk.END)
        for host in self.host_list:
            self.lst_hosts.insert(tk.END, f"{host}")

    def add_host(self):
        new_host = simpledialog.askstring("Add Host", "Enter IP or domain:")
        if new_host:
            self.host_list.append(new_host)
            self.update_host_display()

    def edit_host(self):
        selected_index = self.lst_hosts.curselection()
        if selected_index:
            current_host = self.host_list[selected_index[0]]
            new_host = simpledialog.askstring("Edit Host", "Enter new address:", initialvalue=current_host)
            if new_host:
                self.host_list[selected_index[0]] = new_host
                self.update_host_display()
        else:
            messagebox.showwarning("Warning", "Please select a host to edit.")

    def delete_host(self):
        selected_index = self.lst_hosts.curselection()
        if selected_index:
            self.host_list.pop(selected_index[0])
            self.update_host_display()
        else:
            messagebox.showwarning("Warning", "Please select a host to delete.")

    def save_and_close(self):
        self.top.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()

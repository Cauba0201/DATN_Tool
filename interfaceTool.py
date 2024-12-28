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
import socket


class PingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("National Connection Quality Monitoring System")
        self.root.geometry("1000x700")  # Set a larger window size for better layout
        self.root.resizable(True, True)  # Allow resizing
        self.host_list = []  # Danh sách IP/Domain
        #logo
        self.root.iconbitmap("logo_lobackground.ico")

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
        # Main frame for content
        main_frame = tk.Frame(root, bg=self.primary_bg, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left configuration panel
        config_frame = tk.Frame(main_frame, relief=tk.GROOVE, borderwidth=2, bg=self.secondary_bg, padx=10, pady=10)
        config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(config_frame, text="IP Address & Domain", font=("Helvetica", 14, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)

        # File selection
        #file_label = ttk.Label(config_frame, text="Select a file:", background=self.secondary_bg, foreground=self.text_color)
        #file_label.pack(anchor=tk.W, pady=5)

        file_frame = tk.Frame(config_frame, bg=self.secondary_bg)
        file_frame.pack(fill=tk.X, pady=5)

        #self.file_label = ttk.Label(file_frame, text="No file selected", width=30, anchor="w")
        #self.file_label.pack(side=tk.LEFT, padx=5)

        #self.select_button = tk.Button(file_frame, text="Browse", command=self.select_file, bg=self.blue_color, fg="white", font=("Helvetica", 12))
        #self.select_button.pack(side=tk.RIGHT, padx=5)

        # Hiển thị danh sách các Host
        self.lst_hosts = tk.Listbox(file_frame, height=15, width=50, font=("Courier", 12))
        self.lst_hosts.pack(pady=10)

        # Ping settings
        tk.Label(config_frame, text="Ping Settings :", font=("Helvetica", 12, "bold"), bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=10)

        tk.Label(config_frame, text="Number of Pings :", bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)
        self.ping_count = ttk.Entry(config_frame, width=10)
        self.ping_count.insert(0, "4")
        self.ping_count.pack(anchor=tk.W, pady=5)

        tk.Label(config_frame, text="Interval (seconds) :", bg=self.secondary_bg, fg=self.text_color).pack(anchor=tk.W, pady=5)
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

    def update_host_display(self):
        # Cập nhật Listbox hiển thị danh sách
        self.lst_hosts.delete(0, tk.END)
        for host in self.host_list:
            self.lst_hosts.insert(tk.END, host)

    def test_hosts(self):
        # Hiển thị danh sách sẽ kiểm tra
        if not self.host_list:
            messagebox.showinfo("Thông báo", "Không có địa chỉ nào để kiểm tra!")
            return

        for host in self.host_list:
            # Ở đây có thể thực hiện hàm kiểm tra ping với từng host
            print(f"Đang kiểm tra: {host}")
        messagebox.showinfo("Thông báo", "Kiểm tra hoàn tất!")

    def create_menu_bar(self):
        menu_bar = tk.Menu(self.root)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        # file_menu.add_command(label="Open", command=self.select_file)
        file_menu.add_command(label="Save", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # List Host
        manage_hosts_menu = tk.Menu(menu_bar, tearoff=0)
        manage_hosts_menu.add_command( label="IP Address & Domain", command=self.open_list_host_form)
        menu_bar.add_cascade(label="Manager", menu=manage_hosts_menu)

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
        tk.messagebox.showinfo("About System", "National Connection Quality Monitoring System\nVersion 1.0 \nDesign by An Nguyen")

    def open_list_host_form(self):
        form_list_host = FormListHost(self.root, self.host_list)
        self.root.wait_window(form_list_host.top)  # Chờ khi Form con đóng
        self.host_list = form_list_host.host_list  # Cập nhật danh sách
        self.update_host_display()

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_area.get("1.0", tk.END))
    #
    # def select_file(self):
    #     self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    #     if self.file_path:
    #         self.file_label.config(text=f"Selected: {self.file_path}")
    #         self.start_button.config(state=tk.NORMAL)
    #     else:
    #         self.file_label.config(text="No file selected")

    def start_test(self):
        if not self.host_list:
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
            # Tùy chỉnh tham số lệnh ping theo hệ điều hành
            ping_count = 10  # Mặc định ping 10 lần
            if platform.system() == "Windows":
                command = ['ping', '-n', str(ping_count), domain]
            else:
                command = ['ping', '-c', str(ping_count), domain]

            # Thực thi lệnh ping
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout

            # Kiểm tra nếu lệnh không thành công
            if result.returncode != 0:
                return f"Error pinging {domain}: Host unreachable or invalid."

            # Trích xuất thông tin từ đầu ra
            packets_sent = re.search(r"Sent = (\d+)", output) or re.search(r"Transmitted, (\d+)", output)
            packet_loss = re.search(r"(\d+)% loss", output) or re.search(r"(\d+)% packet loss", output)
            latency = re.search(r"Average = (\d+)ms", output) or re.search(r"avg = (\d+\.\d+) ms", output)

            packets_sent = int(packets_sent.group(1)) if packets_sent else "N/A"
            packet_loss = int(packet_loss.group(1)) if packet_loss else "N/A"
            latency = float(latency.group(1)) if latency else "N/A"

            return f"{domain}: Packet Loss = {packet_loss}%, Latency = {latency}ms, Packets Sent = {packets_sent}"
        except subprocess.TimeoutExpired:
            return f"Timeout while pinging {domain}."
        except FileNotFoundError:
            return f"Ping command not found. Please ensure it is installed on your system."
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


class FormListHost:
    def __init__(self, parent, host_list):
        self.top = tk.Toplevel(parent)
        self.top.title("Quản lý danh sách")
        self.top.geometry("400x300")

        self.host_list = host_list.copy()  # Sao chép danh sách ban đầu

        # Listbox hiển thị danh sách
        self.lst_hosts = tk.Listbox(self.top, height=12, width=40, font=("Courier", 12))
        self.lst_hosts.pack(pady=10)

        # Cập nhật hiển thị ban đầu
        self.update_host_display()

        # Nút thêm
        self.btn_add = tk.Button(self.top, text="Thêm", command=self.add_host, font=("Arial", 10))
        self.btn_add.pack(side=tk.LEFT, padx=5)

        # Nút sửa
        self.btn_edit = tk.Button(self.top, text="Sửa", command=self.edit_host, font=("Arial", 10))
        self.btn_edit.pack(side=tk.LEFT, padx=5)

        # Nút xóa
        self.btn_delete = tk.Button(self.top, text="Xóa", command=self.delete_host, font=("Arial", 10))
        self.btn_delete.pack(side=tk.LEFT, padx=5)

        # Nút Lưu
        self.btn_save = tk.Button(self.top, text="Lưu và Đóng", command=self.save_and_close, font=("Arial", 10))
        self.btn_save.pack(side=tk.RIGHT, padx=5)

    def update_host_display(self):
        # Cập nhật Listbox hiển thị danh sách
        self.lst_hosts.delete(0, tk.END)
        for host in self.host_list:
            self.lst_hosts.insert(tk.END, host)

    def add_host(self):
        new_host = simpledialog.askstring("Thêm Host", "Nhập địa chỉ IP hoặc domain:")
        if new_host:
            self.host_list.append(new_host)
            self.update_host_display()

    def edit_host(self):
        selected_index = self.lst_hosts.curselection()
        if selected_index:
            current_host = self.host_list[selected_index[0]]
            new_host = simpledialog.askstring("Sửa Host", "Nhập địa chỉ mới:", initialvalue=current_host)
            if new_host:
                self.host_list[selected_index[0]] = new_host
                self.update_host_display()
        else:
            messagebox.showwarning("Chú ý", "Vui lòng chọn một Host để sửa!")

    def delete_host(self):
        selected_index = self.lst_hosts.curselection()
        if selected_index:
            del self.host_list[selected_index[0]]
            self.update_host_display()
        else:
            messagebox.showwarning("Chú ý", "Vui lòng chọn một Host để xóa!")

    def save_and_close(self):
        self.top.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()
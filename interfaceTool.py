import tkinter as tk
from tkinter import filedialog, scrolledtext
from tkinter import ttk  # For improved styles
from threading import Thread, Event
import time
import subprocess
import re


class PingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ping Application")
        self.root.geometry("1000x700")  # Set a larger window size for better layout
        self.root.resizable(False, False)

        self.file_path = None
        self.stop_event = Event()

        # Define styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TButton", font=("Helvetica", 12))
        self.style.configure("TLabel", font=("Helvetica", 12))

        # Header
        header = tk.Label(root, text="Ping Application", font=("Helvetica", 18, "bold"), bg="#4CAF50", fg="white")
        header.pack(fill=tk.X, pady=10)

        # Main frame for content
        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left configuration panel
        config_frame = tk.Frame(main_frame, relief=tk.GROOVE, borderwidth=2, padx=10, pady=10)
        config_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(config_frame, text="Configuration", font=("Helvetica", 14, "bold")).pack(anchor=tk.W, pady=5)

        # File selection
        file_label = ttk.Label(config_frame, text="Select a file:")
        file_label.pack(anchor=tk.W, pady=5)

        file_frame = tk.Frame(config_frame)
        file_frame.pack(fill=tk.X, pady=5)

        self.file_label = ttk.Label(file_frame, text="No file selected", width=30, anchor="w")
        self.file_label.pack(side=tk.LEFT, padx=5)

        self.select_button = ttk.Button(file_frame, text="Browse", command=self.select_file)
        self.select_button.pack(side=tk.RIGHT, padx=5)

        # Ping settings
        tk.Label(config_frame, text="Ping Settings:", font=("Helvetica", 12, "bold")).pack(anchor=tk.W, pady=10)

        tk.Label(config_frame, text="Number of Pings:").pack(anchor=tk.W, pady=5)
        self.ping_count = ttk.Entry(config_frame, width=10)
        self.ping_count.insert(0, "4")
        self.ping_count.pack(anchor=tk.W, pady=5)

        tk.Label(config_frame, text="Interval (seconds):").pack(anchor=tk.W, pady=5)
        self.ping_interval = ttk.Entry(config_frame, width=10)
        self.ping_interval.insert(0, "60")
        self.ping_interval.pack(anchor=tk.W, pady=5)

        # Start/Stop buttons
        self.start_button = ttk.Button(config_frame, text="Start Ping", command=self.start_ping, state=tk.DISABLED)
        self.start_button.pack(fill=tk.X, pady=10)

        self.stop_button = ttk.Button(config_frame, text="Stop Ping", command=self.stop_ping, state=tk.DISABLED)
        self.stop_button.pack(fill=tk.X, pady=5)

        # Right result panel
        result_frame = tk.Frame(main_frame, relief=tk.GROOVE, borderwidth=2, padx=10, pady=10)
        result_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(result_frame, text="Ping Results", font=("Helvetica", 14, "bold")).pack(anchor=tk.W, pady=5)

        self.output_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, font=("Courier", 10), bg="#f9f9f9",
                                                     height=25)
        self.output_area.pack(fill=tk.BOTH, expand=True, pady=10)

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.file_label.config(text=f"Selected: {self.file_path}")
            self.start_button.config(state=tk.NORMAL)
        else:
            self.file_label.config(text="No file selected")

    def start_ping(self):
        if not self.file_path:
            return

        self.stop_event.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Run ping process in a separate thread
        self.ping_thread = Thread(target=self.ping_loop)
        self.ping_thread.start()

    def stop_ping(self):
        self.stop_event.set()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def ping_loop(self):
        interval = int(self.ping_interval.get())
        while not self.stop_event.is_set():
            self.output_area.insert(tk.END, "Starting new ping cycle...\n")
            self.output_area.see(tk.END)

            if self.file_path:
                with open(self.file_path, 'r') as file:
                    lines = file.readlines()
                    for line in lines:
                        if self.stop_event.is_set():
                            break
                        domain = line.strip()
                        result = self.ping(domain)
                        self.output_area.insert(tk.END, result + "\n")
                        self.output_area.see(tk.END)

            self.output_area.insert(tk.END, "Waiting for next cycle...\n\n")
            self.output_area.see(tk.END)
            time.sleep(interval)  # Wait specified seconds before next cycle

    def ping(self, domain):
        try:
            count = self.ping_count.get()
            result = subprocess.run(['ping', '-n', count, domain], capture_output=True, text=True)
            output = result.stdout

            # Extract packet loss and latency information
            packet_loss = re.search(r"(\d+)% loss", output)
            avg_latency = re.search(r"Average = (\d+)ms", output)

            packet_loss = packet_loss.group(1) if packet_loss else "N/A"
            avg_latency = avg_latency.group(1) if avg_latency else "N/A"

            return f"{domain}: Packet Loss = {packet_loss}%, Avg Latency = {avg_latency}ms"
        except Exception as e:
            return f"Error pinging {domain}: {e}"


if __name__ == "__main__":
    root = tk.Tk()
    app = PingApp(root)
    root.mainloop()

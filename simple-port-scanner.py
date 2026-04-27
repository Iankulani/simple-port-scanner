import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import socket
import threading
import time
from datetime import datetime
from collections import OrderedDict
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# For charts
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ==========================
# Port Scanner Application
# ==========================
class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Port Scanner")
        self.root.geometry("1100x700")
        self.root.resizable(True, True)
        
        # Set blue theme color scheme
        self.bg_color = "#0a2f44"        # deep blue background
        self.fg_color = "#e0f2fe"        # light text
        self.accent_color = "#1e88e5"    # bright blue for buttons
        self.frame_bg = "#0c3f55"        # slightly lighter blue for frames
        self.button_bg = "#1565c0"       # button background
        self.button_fg = "white"
        
        # Configure main window style
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TLabel', background=self.bg_color, foreground=self.fg_color, font=('Segoe UI', 10))
        self.style.configure('TFrame', background=self.frame_bg)
        self.style.configure('TButton', background=self.button_bg, foreground=self.button_fg, font=('Segoe UI', 10, 'bold'))
        self.style.map('TButton', background=[('active', '#0d47a1')])
        self.style.configure('TEntry', fieldbackground='white', foreground='black')
        
        # Variables
        self.target_ip = tk.StringVar()
        self.start_port = tk.IntVar(value=1)
        self.end_port = tk.IntVar(value=1024)
        self.scanning = False
        self.open_ports = []
        self.closed_count = 0
        self.total_scanned = 0
        self.scan_start_time = None
        
        # Build GUI
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ========== Input Section ==========
        input_frame = ttk.LabelFrame(main_frame, text="Target Configuration", padding="10")
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP / Hostname
        ttk.Label(input_frame, text="Target IP / Hostname:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ip_entry = ttk.Entry(input_frame, textvariable=self.target_ip, width=30, font=('Segoe UI', 10))
        ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ip_entry.insert(0, "127.0.0.1")
        
        # Start port
        ttk.Label(input_frame, text="Start Port:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        start_spin = ttk.Spinbox(input_frame, from_=1, to=65535, textvariable=self.start_port, width=8)
        start_spin.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # End port
        ttk.Label(input_frame, text="End Port:").grid(row=0, column=4, sticky=tk.W, padx=5, pady=5)
        end_spin = ttk.Spinbox(input_frame, from_=1, to=65535, textvariable=self.end_port, width=8)
        end_spin.grid(row=0, column=5, sticky=tk.W, padx=5, pady=5)
        
        # Scan button + progress
        self.scan_btn = ttk.Button(input_frame, text="🔍 START SCAN", command=self.start_scan, width=15)
        self.scan_btn.grid(row=0, column=6, padx=15, pady=5)
        
        self.stop_btn = ttk.Button(input_frame, text="⛔ STOP", command=self.stop_scan, state=tk.DISABLED, width=10)
        self.stop_btn.grid(row=0, column=7, padx=5, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(input_frame, mode='determinate', length=300)
        self.progress.grid(row=1, column=0, columnspan=8, sticky=tk.EW, padx=5, pady=10)
        
        # Status label
        self.status_label = ttk.Label(input_frame, text="Ready. Enter target and click START SCAN.")
        self.status_label.grid(row=2, column=0, columnspan=8, sticky=tk.W, padx=5, pady=2)
        
        # ========== Results Area (Open Ports + Stats) ==========
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left side: Open ports list
        left_frame = ttk.LabelFrame(results_frame, text="🔓 Open Ports", padding="5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.open_ports_listbox = tk.Listbox(left_frame, bg="#e3f2fd", fg="#0a2f44", font=('Consolas', 10), height=20)
        self.open_ports_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.open_ports_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.open_ports_listbox.config(yscrollcommand=scrollbar.set)
        
        # Right side: Statistics
        right_frame = ttk.LabelFrame(results_frame, text="📊 Port Statistics", padding="10")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5, expand=False, ipadx=20)
        
        self.stats_text = ScrolledText(right_frame, width=30, height=12, bg="#f5f9ff", font=('Segoe UI', 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # ========== Action Buttons ==========
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        self.bar_chart_btn = ttk.Button(action_frame, text="📊 Bar Chart", command=self.show_bar_chart, width=15)
        self.bar_chart_btn.pack(side=tk.LEFT, padx=5)
        
        self.pie_chart_btn = ttk.Button(action_frame, text="🥧 Pie Chart", command=self.show_pie_chart, width=15)
        self.pie_chart_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(action_frame, text="💾 Export Data (JSON)", command=self.export_data, width=20)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(action_frame, text="🗑 Clear Results", command=self.clear_results, width=15)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.exit_btn = ttk.Button(action_frame, text="❌ Exit", command=self.root.quit, width=10)
        self.exit_btn.pack(side=tk.RIGHT, padx=5)
        
        # Initial stats display
        self.update_stats_display()
    
    def update_stats_display(self):
        """Update statistics text widget"""
        self.stats_text.delete(1.0, tk.END)
        if self.total_scanned == 0:
            stats = "No scan data yet.\nClick START SCAN to begin."
        else:
            open_pct = (len(self.open_ports) / self.total_scanned) * 100 if self.total_scanned else 0
            closed_pct = (self.closed_count / self.total_scanned) * 100 if self.total_scanned else 0
            stats = f"""
┌─────────────────────────────┐
│     PORT SCAN RESULTS       │
├─────────────────────────────┤
│ Target        : {self.target_ip.get():<20}│
│ Ports scanned : {self.total_scanned:<20}│
│ Open ports    : {len(self.open_ports):<20}│
│ Closed ports  : {self.closed_count:<20}│
│ Open %        : {open_pct:.2f}%                │
│ Closed %      : {closed_pct:.2f}%                │
│ Scan duration : {self.scan_duration():<12}│
└─────────────────────────────┘

Open Ports Details:
{', '.join(map(str, self.open_ports)) if self.open_ports else 'None'}
"""
        self.stats_text.insert(tk.END, stats)
    
    def scan_duration(self):
        if self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            return f"{elapsed:.2f} sec"
        return "N/A"
    
    def clear_results(self):
        """Clear all scan results"""
        self.open_ports.clear()
        self.closed_count = 0
        self.total_scanned = 0
        self.open_ports_listbox.delete(0, tk.END)
        self.update_stats_display()
        self.status_label.config(text="Results cleared.")
    
    def start_scan(self):
        """Validate input and start scanning thread"""
        target = self.target_ip.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname.")
            return
        
        start = self.start_port.get()
        end = self.end_port.get()
        if start < 1 or end > 65535 or start > end:
            messagebox.showerror("Error", "Invalid port range. Ports must be 1-65535 and start ≤ end.")
            return
        
        # Resolve hostname
        try:
            resolved_ip = socket.gethostbyname(target)
            self.target_ip.set(resolved_ip)  # update with actual IP
        except socket.gaierror:
            messagebox.showerror("Error", "Cannot resolve hostname. Please check target.")
            return
        
        # Clear previous results
        self.clear_results()
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress['value'] = 0
        self.status_label.config(text=f"Scanning {resolved_ip} from port {start} to {end} ...")
        self.scan_start_time = time.time()
        
        # Run scanning in background thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(resolved_ip, start, end), daemon=True)
        scan_thread.start()
    
    def stop_scan(self):
        """Stop ongoing scan"""
        self.scanning = False
        self.status_label.config(text="Stopping scan... Please wait...")
    
    def perform_scan(self, ip, start_port, end_port):
        """Multi-threaded port scanning using ThreadPoolExecutor"""
        total_ports = end_port - start_port + 1
        self.total_scanned = 0
        self.open_ports = []
        self.closed_count = 0
        lock = threading.Lock()
        
        timeout = 0.8  # seconds per connection attempt
        
        def scan_single_port(port):
            if not self.scanning:
                return None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port  # open
                else:
                    return None  # closed/filtered
            except Exception:
                return None
        
        # Use ThreadPoolExecutor for concurrency
        max_workers = min(200, total_ports)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(scan_single_port, port): port for port in range(start_port, end_port + 1)}
            completed = 0
            for future in as_completed(future_to_port):
                if not self.scanning:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                port = future_to_port[future]
                result = future.result()
                with lock:
                    completed += 1
                    self.total_scanned = completed
                    if result is not None:
                        self.open_ports.append(result)
                        # Update listbox in GUI thread
                        self.root.after(0, self.add_open_port_to_listbox, result)
                    else:
                        self.closed_count += 1
                    # Update progress
                    progress_val = (completed / total_ports) * 100
                    self.root.after(0, self.update_progress, progress_val)
                    self.root.after(0, self.update_stats_display)
        
        # Finalize
        self.scanning = False
        self.root.after(0, self.scan_finished)
    
    def add_open_port_to_listbox(self, port):
        """Thread-safe addition of open port to listbox"""
        self.open_ports_listbox.insert(tk.END, f"Port {port} - OPEN")
        self.open_ports_listbox.yview(tk.END)
    
    def update_progress(self, value):
        self.progress['value'] = value
        self.status_label.config(text=f"Scanning... {int(value)}% complete | Open: {len(self.open_ports)}")
    
    def scan_finished(self):
        """Re-enable UI after scan complete"""
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        if not self.scanning and self.total_scanned > 0:
            self.status_label.config(text=f"Scan completed. Found {len(self.open_ports)} open ports out of {self.total_scanned} scanned.")
            self.update_stats_display()
        elif not self.scanning and self.total_scanned == 0:
            self.status_label.config(text="Scan was stopped or no ports scanned.")
        else:
            self.status_label.config(text="Scan finished.")
    
    def show_bar_chart(self):
        """Display bar chart for open vs closed ports"""
        if self.total_scanned == 0:
            messagebox.showwarning("No Data", "Please run a port scan first.")
            return
        
        open_count = len(self.open_ports)
        closed_count = self.closed_count
        
        fig = Figure(figsize=(5, 4), dpi=100, facecolor='#f0f8ff')
        ax = fig.add_subplot(111)
        categories = ['Open Ports', 'Closed Ports']
        counts = [open_count, closed_count]
        colors = ['#1e88e5', '#ff7043']
        bars = ax.bar(categories, counts, color=colors, edgecolor='black')
        ax.set_title(f'Port Scan Results for {self.target_ip.get()}', fontweight='bold')
        ax.set_ylabel('Number of Ports')
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height}', xy=(bar.get_x() + bar.get_width()/2, height),
                        xytext=(0, 3), textcoords="offset points", ha='center', va='bottom')
        
        self._show_chart_window(fig, "Bar Chart - Open vs Closed Ports")
    
    def show_pie_chart(self):
        """Display pie chart for open vs closed ports"""
        if self.total_scanned == 0:
            messagebox.showwarning("No Data", "Please run a port scan first.")
            return
        
        open_count = len(self.open_ports)
        closed_count = self.closed_count
        
        fig = Figure(figsize=(5, 4), dpi=100, facecolor='#f0f8ff')
        ax = fig.add_subplot(111)
        labels = ['Open Ports', 'Closed Ports']
        sizes = [open_count, closed_count]
        colors = ['#1e88e5', '#ff7043']
        explode = (0.05, 0)
        ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
               shadow=True, startangle=90)
        ax.axis('equal')
        ax.set_title(f'Port Distribution for {self.target_ip.get()}', fontweight='bold')
        
        self._show_chart_window(fig, "Pie Chart - Port Distribution")
    
    def _show_chart_window(self, fig, title):
        """Helper to display a matplotlib figure in a new window"""
        chart_window = tk.Toplevel(self.root)
        chart_window.title(title)
        chart_window.configure(bg=self.bg_color)
        chart_window.geometry("600x500")
        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Close button
        close_btn = ttk.Button(chart_window, text="Close", command=chart_window.destroy)
        close_btn.pack(pady=10)
    
    def export_data(self):
        """Export scan results to JSON file"""
        if self.total_scanned == 0:
            messagebox.showwarning("No Data", "No scan data to export. Please run a scan first.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Scan Report"
        )
        if not file_path:
            return
        
        export_data = {
            "scan_info": {
                "target_ip": self.target_ip.get(),
                "scan_timestamp": datetime.now().isoformat(),
                "total_ports_scanned": self.total_scanned,
                "open_ports_count": len(self.open_ports),
                "closed_ports_count": self.closed_count,
                "scan_duration_seconds": self.scan_duration(),
                "port_range": f"{self.start_port.get()}-{self.end_port.get()}"
            },
            "open_ports_list": self.open_ports,
            "closed_ports_count_only": self.closed_count
        }
        
        try:
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=4)
            messagebox.showinfo("Export Successful", f"Data exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")

# ==========================
# Main entry point
# ==========================
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
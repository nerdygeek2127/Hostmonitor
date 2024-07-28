import tkinter as tk
from tkinter import ttk
from tkinter import font
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
import time
import subprocess
from scapy.all import ARP, Ether, srp
import ipaddress
from tkinter import filedialog
import openpyxl
from openpyxl import Workbook

# Global dictionaries for thread management
ping_threads = {}
ping_stop_events = {}
host_intervals = {}

# Thread pool for handling multiple ping threads
executor = ThreadPoolExecutor(max_workers=250)

def scan_network(ip_range, mac_prefix):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    print(f"Scanning IP range: {ip_range}")
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []

    for sent, received in result:
        mac = received.hwsrc
        ip = received.psrc
        if mac.lower().startswith(mac_prefix.lower()):
            devices.append({'ip': ip, 'mac': mac})

    return devices

def open_add_popup():
    popup = tk.Toplevel()
    popup.title("Add Host")
    popup.geometry("250x220")

    desc_label = ttk.Label(popup, text="Description")
    desc_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
    desc_entry = ttk.Entry(popup, width=30)
    desc_entry.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

    host_label = ttk.Label(popup, text="Hostname or IP address")
    host_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
    host_entry = ttk.Entry(popup, width=30)
    host_entry.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

    interval_label = ttk.Label(popup, text="Checking interval (in Sec)")
    interval_label.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
    interval_var = tk.IntVar(value=5)
    interval_spinbox = ttk.Spinbox(popup, from_=1, to=3600, increment=1, textvariable=interval_var, width=28)
    interval_spinbox.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)

    add_host_label = tk.Button(popup, text="Add Host", fg="blue", bd=0, cursor="hand2", anchor="w")
    add_host_label.grid(row=6, column=0, padx=10, pady=10, sticky=tk.W)
    add_host_label.bind("<Button-1>", lambda e: add_host(desc_entry.get(), host_entry.get(), interval_var.get()))

def open_search_popup():
    popup = tk.Toplevel()
    popup.title("Search")
    popup.geometry("300x250")

    network_label = ttk.Label(popup, text="Network Address (CIDR)")
    network_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
    network_entry = ttk.Entry(popup, width=30)
    network_entry.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

    mac_label = ttk.Label(popup, text="MAC Address")
    mac_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
    mac_entry = ttk.Entry(popup, width=30)
    mac_entry.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

    search_button = tk.Button(popup, text="Search", fg="blue", bd=0, cursor="hand2", anchor="w")
    search_button.grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
    
    scanning_status_label = ttk.Label(popup, text="", width=30, anchor="w")
    scanning_status_label.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)

    search_button.bind("<Button-1>", lambda e: search_hosts(network_entry.get(), mac_entry.get(), scanning_status_label))

def search_hosts(network_address, mac_address, status_label):
    for row in table.get_children():
        table.delete(row)

    try:
        network = ipaddress.IPv4Network(network_address, strict=False)
    except ValueError as e:
        status_label.config(text=f"Invalid network address: {e}")
        return

    ip_range = str(network)
    status_label.config(text=f"Scanning IP range: {ip_range}")

    if mac_address:
        devices = scan_network(ip_range, mac_address)
        for device in devices:
            table.insert("", "end", values=("⬤", device['mac'], device['ip'], "Ping", "N/A", "N/A", "N/A"))
            ping_stop_events[device['ip']] = Event()
            host_intervals[device['ip']] = 5
    else:
        for ip in network:
            table.insert("", "end", values=("⬤", "default", str(ip), "Ping", "N/A", "N/A", "N/A"))
            ping_stop_events[str(ip)] = Event()
            host_intervals[str(ip)] = 5

    update_counts()
    status_label.config(text=f"Scanning IP range: {ip_range} - Completed")

def add_host(description, hostname, interval):
    if interval <= 0:
        interval = 1
    method = "Ping" if is_ip_address(hostname) else "N/A"
    table.insert("", "end", values=("⬤", description, hostname, method, "N/A", "N/A", "N/A"))
    ping_stop_events[hostname] = Event()
    host_intervals[hostname] = interval
    if stop_button.cget("text") == "🚫\nStop":
        start_ping_thread(description, hostname, interval)
    update_counts()

def is_ip_address(hostname):
    parts = hostname.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def start_ping_thread(description, hostname, interval):
    stop_event = ping_stop_events[hostname]
    stop_event.clear()
    future = executor.submit(ping_host, hostname, interval, stop_event)
    ping_threads[hostname] = future

def ping_host(hostname, interval, stop_event):
    while not stop_event.is_set():
        success_count = 0
        for _ in range(2):
            update_result(hostname, "Checking...", success=None)
            time.sleep(1)
            if ping_successful(hostname):
                success_count += 1
            else:
                success_count = 0
                break
        if success_count == 2:
            update_result(hostname, "OK", success=True)
            last_check = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            update_last_check(hostname, last_check)
            update_uptime(hostname, "100%")
            update_status(hostname, "green")
        else:
            update_result(hostname, "Failure", success=False)
            update_status(hostname, "red")
        time.sleep(interval)
    update_counts()

def ping_successful(hostname):
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        response = subprocess.run(
            ["ping", "-n", "1", hostname],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            startupinfo=startupinfo
        )
        return "TTL=" in response.stdout
    except Exception as e:
        print(f"Error pinging {hostname}: {e}")
        return False

def update_result(hostname, result, success=None):
    for row in table.get_children():
        values = table.item(row)["values"]
        if values[2] == hostname:
            table.set(row, column="Result", value=result)
            if success is not None:
                tag = "success_result" if success else "failure"
                table.item(row, tags=(tag,))
            update_counts()
            break

def update_last_check(hostname, last_check):
    for row in table.get_children():
        values = table.item(row)["values"]
        if values[2] == hostname:
            table.set(row, column="Last Check", value=last_check)
            break

def update_uptime(hostname, uptime):
    for row in table.get_children():
        values = table.item(row)["values"]
        if values[2] == hostname:
            table.set(row, column="Uptime", value=uptime)
            break

def update_status(hostname, status):
    for row in table.get_children():
        values = table.item(row)["values"]
        if values[2] == hostname:
            if status == "green":
                table.set(row, column="", value="⬤")
                table.item(row, tags=("success_symbol",))
            else:
                table.set(row, column="", value="⬤")
                table.item(row, tags=("failure_symbol",))
            break

def toggle_start_stop():
    if stop_button.cget("text") == "▶️\nStart":
        stop_button.config(text="🚫\nStop")
        start_all_pings()
        add_button.config(state=tk.DISABLED)
        search_button.config(state=tk.DISABLED)
        save_button.config(state=tk.DISABLED)
    else:
        stop_button.config(text="▶️\nStart")
        stop_all_pings()
        add_button.config(state=tk.NORMAL)
        search_button.config(state=tk.NORMAL)
        save_button.config(state=tk.NORMAL)

def start_all_pings():
    for row in table.get_children():
        values = table.item(row)["values"]
        hostname = values[2]
        if is_ip_address(hostname):
            interval = host_intervals[hostname]
            start_ping_thread(values[1], hostname, interval)

def stop_all_pings():
    for event in ping_stop_events.values():
        event.set()

def clear_table():
    stop_all_pings()
    for row in table.get_children():
        table.delete(row)
    ping_threads.clear()
    ping_stop_events.clear()
    host_intervals.clear()
    update_counts()

def save_table():
    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
    if file_path:
        workbook = Workbook()
        sheet = workbook.active
        # Add the header, excluding the first column
        headers = ["Description", "Host", "Method", "Result", "Last Check", "Uptime"]
        sheet.append(headers)
        # Add the data, excluding the first column
        for row in table.get_children():
            values = table.item(row)["values"][1:]  # Exclude the first column
            sheet.append(values)
        workbook.save(file_path)

def update_counts():
    success_count = 0
    failure_count = 0
    for row in table.get_children():
        result = table.item(row)["values"][4]
        if result == "OK":
            success_count += 1
        elif result == "Failure":
            failure_count += 1
    status_label.config(text=f"Success Ping: {success_count}\nFailure Ping: {failure_count}")

def copy_to_clipboard():
    selected_item = table.selection()
    if selected_item:
        item_values = table.item(selected_item[0], "values")
        clipboard_text = "\t".join(item_values)
        root.clipboard_clear()
        root.clipboard_append(clipboard_text)

def show_context_menu(event):
    context_menu.post(event.x_root, event.y_root)

def create_host_monitor():
    global table, stop_button, status_label, root, context_menu, add_button, search_button, save_button

    root = tk.Tk()
    root.title("🔎 Host Monitor")
    root.iconbitmap(r"C:\Users\lohit\Desktop\EVENG\Pyhton scripts\Host MOnitor\icon.ico")  # Set the icon file here

    root.geometry("700x400")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    button_frame = ttk.Frame(main_frame)
    button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))

    emoji_font = font.Font(family="Segoe UI Emoji", size=10)

    add_button = tk.Button(button_frame, text="➕\nAdd", width=8, command=open_add_popup, font=emoji_font, bg="lightblue")
    add_button.grid(row=0, column=0, padx=5)

    search_button = tk.Button(button_frame, text="🔎\nSearch", width=8, command=open_search_popup, font=emoji_font, bg="lightgreen")
    search_button.grid(row=0, column=1, padx=5)

    separator1 = ttk.Separator(button_frame, orient='vertical')
    separator1.grid(row=0, column=2, padx=5, sticky=(tk.N, tk.S))

    stop_button = tk.Button(button_frame, text="▶️\nStart", width=8, command=toggle_start_stop, font=emoji_font, bg="lightcoral")
    stop_button.grid(row=0, column=3, padx=5)

    clear_button = tk.Button(button_frame, text="🔄\nClear", width=8, command=clear_table, font=emoji_font, bg="lightgray")
    clear_button.grid(row=0, column=4, padx=5)

    save_button = tk.Button(button_frame, text="💾\nSave", width=8, command=save_table, font=emoji_font, bg="lightgray")
    save_button.grid(row=0, column=5, padx=5)

    style = ttk.Style()
    style.configure("Status.TLabel", foreground="black")

    status_label = ttk.Label(button_frame, text="Success Ping: 0\nFailure Ping: 0", width=30, style="Status.TLabel")
    status_label.grid(row=0, column=6, padx=5)

    # Spacer between buttons and table
    spacer_label = tk.Label(main_frame, text="")
    spacer_label.grid(row=1, column=0, pady=5)

    columns = ("", "Description", "Host", "Method", "Result", "Last Check", "Uptime")
    table = ttk.Treeview(main_frame, columns=columns, show="headings")
    table.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Adjusting the width and alignment of the columns
    table.column("", width=30, stretch=False, anchor="center")
    table.column("Description", width=120, anchor="center")
    table.column("Host", width=120, anchor="center")
    table.column("Method", width=100, anchor="center")
    table.column("Result", width=100, anchor="center")
    table.column("Last Check", width=140, anchor="center")
    table.column("Uptime", width=80, anchor="center")

    for col in columns:
        table.heading(col, text=col, anchor="center")

    table.tag_configure("failure", background="mistyrose", foreground="darkred")
    table.tag_configure("success_symbol", foreground="green")
    table.tag_configure("failure_symbol", foreground="red")
    table.tag_configure("success_result", background="lightgreen")

    # Context menu for copy functionality
    context_menu = tk.Menu(root, tearoff=0)
    context_menu.add_command(label="Copy", command=copy_to_clipboard)
    
    table.bind("<Button-3>", show_context_menu)

    # Developer label
    dev_label = ttk.Label(main_frame, text="developed by 👽lohit@nerdygeek2127", anchor="center")
    dev_label.grid(row=3, column=0, sticky=(tk.W, tk.E))

    main_frame.rowconfigure(2, weight=1)
    main_frame.columnconfigure(0, weight=1)

    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)

    root.mainloop()

if __name__ == "__main__":
    create_host_monitor()

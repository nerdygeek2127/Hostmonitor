import tkinter as tk
from tkinter import ttk
from tkinter import font, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
import time
import subprocess
from scapy.all import ARP, Ether, srp
import socket
from tkinter import filedialog
import openpyxl
from openpyxl import Workbook
from plyer import notification  # Import plyer for notifications

# Global dictionaries for thread management
ping_threads = {}
ping_stop_events = {}
host_intervals = {}
notifications_enabled = True  # Global variable for notification status

# Thread pool for handling multiple ping threads
executor = ThreadPoolExecutor(max_workers=250)

# States for filter buttons
success_filter_active = False
failure_filter_active = False
original_data = []  # To store the original table data

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

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

def search_hosts(mac_prefix, status_label, is_clear_table=True):
    if is_clear_table:
        for row in table.get_children():
            table.delete(row)

    local_ip = get_local_ip()
    ip_parts = local_ip.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    status_label.config(text=f"Scanning IP range: {ip_range}")

    devices = scan_network(ip_range, mac_prefix)
    for device in devices:
        table.insert("", "end", values=("⬤", device['mac'], device['ip'], "Ping", "N/A", "N/A", "N/A"))
        ping_stop_events[device['ip']] = Event()
        host_intervals[device['ip']] = 5

    update_counts()
    status_label.config(text=f"Scanning IP range: {ip_range} - Completed")

def open_mac_search_popup():
    popup = tk.Toplevel()
    popup.title("MAC Search")
    popup.geometry("250x150")

    mac_label = ttk.Label(popup, text="MAC Address Prefix")
    mac_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
    mac_entry = ttk.Entry(popup, width=30)
    mac_entry.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

    search_label = tk.Label(popup, text="Search", font=font.Font(family="Segoe UI Emoji", size=10), fg="blue", cursor="hand2")
    search_label.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
    search_label.bind("<Button-1>", lambda e: mac_search(mac_entry.get(), status_label))

def mac_search(mac_prefix, status_label):
    local_ip = get_local_ip()
    ip_parts = local_ip.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

    status_label.config(text=f"Scanning IP range: {ip_range}")

    devices = scan_network(ip_range, mac_prefix)
    table.delete(*table.get_children())
    for device in devices:
        table.insert("", "end", values=("⬤", device['mac'], device['ip'], "Ping", "N/A", "N/A", "N/A"))
        ping_stop_events[device['ip']] = Event()
        host_intervals[device['ip']] = 5

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
    store_original_data()

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
            if notifications_enabled:
                notify_failure(hostname)  # Trigger notification on failure
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

def notify_failure(hostname):
    notification.notify(
        title="Ping Failure",
        message=f"Host {hostname} is not reachable.",
        timeout=10
    )

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
    global notifications_enabled
    if stop_button.cget("text") == "▶️\nStart":
        stop_button.config(text="🚫\nStop")
        start_all_pings()
        add_button.config(state=tk.DISABLED)
        search_button.config(state=tk.DISABLED)
        mac_search_button.config(state=tk.DISABLED)
        save_button.config(state=tk.DISABLED)
        toggle_notification_button.config(state=tk.DISABLED)
        reset_button.config(state=tk.NORMAL)
    else:
        stop_button.config(text="▶️\nStart")
        stop_all_pings()
        add_button.config(state=tk.NORMAL)
        search_button.config(state=tk.NORMAL)
        mac_search_button.config(state=tk.NORMAL)
        save_button.config(state=tk.NORMAL)
        toggle_notification_button.config(state=tk.NORMAL)
        notifications_enabled = False
        toggle_notification_button.config(text="🔕\nAlerts")
        reset_button.config(state=tk.DISABLED)

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
    global original_data
    stop_all_pings()
    for row in table.get_children():
        table.delete(row)
    ping_threads.clear()
    ping_stop_events.clear()
    host_intervals.clear()
    original_data.clear()
    update_counts()
    reset_button.config(state=tk.DISABLED)

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
    green_button.config(text=f"{success_count}\nSuccess")
    red_button.config(text=f"{failure_count}\nFailure")

def copy_to_clipboard():
    selected_item = table.selection()
    if selected_item:
        item_values = table.item(selected_item[0], "values")
        clipboard_text = "\t".join(item_values)
        root.clipboard_clear()
        root.clipboard_append(clipboard_text)

def show_context_menu(event):
    context_menu.post(event.x_root, event.y_root)

def toggle_notifications():
    global notifications_enabled
    notifications_enabled = not notifications_enabled
    if notifications_enabled:
        toggle_notification_button.config(text="🔔\nAlerts")
    else:
        toggle_notification_button.config(text="🔕\nAlerts")

def filter_success():
    global success_filter_active, failure_filter_active
    if success_filter_active:
        # Reset filter
        for row in table.get_children():
            table.reattach(row, '', 'end')
        success_filter_active = False
    else:
        # Remove failure filter if active
        if failure_filter_active:
            failure_filter_active = False
        # Filter success
        for row in table.get_children():
            values = table.item(row)["values"]
            if values[4] != "OK":
                table.detach(row)
        success_filter_active = True

def filter_failure():
    global failure_filter_active, success_filter_active
    if failure_filter_active:
        # Reset filter
        for row in table.get_children():
            table.reattach(row, '', 'end')
        failure_filter_active = False
    else:
        # Remove success filter if active
        if success_filter_active:
            success_filter_active = False
        # Filter failure
        for row in table.get_children():
            values = table.item(row)["values"]
            if values[4] != "Failure":
                table.detach(row)
        failure_filter_active = True

def store_original_data():
    global original_data
    original_data = []
    for row in table.get_children():
        original_data.append(table.item(row)["values"])

def reset_filter():
    global success_filter_active, failure_filter_active
    success_filter_active = False
    failure_filter_active = False
    table.delete(*table.get_children())
    for values in original_data:
        table.insert("", "end", values=values)

def create_host_monitor():
    global table, stop_button, root, context_menu, add_button, search_button, mac_search_button, save_button, toggle_notification_button, green_button, red_button, reset_button, status_label

    root = tk.Tk()
    root.title("🔎 Host Monitor")
    root.iconbitmap(r"C:\Users\lohit\Desktop\EVENG\Pyhton scripts\Host MOnitor\icon.ico")  # Set the icon file here

    root.geometry("800x400")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    button_frame = ttk.Frame(main_frame)
    button_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))

    emoji_font = font.Font(family="Segoe UI Emoji", size=10)

    add_button = tk.Button(button_frame, text="➕\nAdd", width=8, command=open_add_popup, font=emoji_font, bg="lightblue")
    add_button.grid(row=0, column=0, padx=4, pady=5, sticky=tk.W)

    search_button = tk.Button(button_frame, text="🔎\nSearch", width=8, command=lambda: search_hosts("", status_label), font=emoji_font, bg="lightgreen")
    search_button.grid(row=0, column=1, padx=4, pady=5, sticky=tk.W)

    mac_search_button = tk.Button(button_frame, text="🔍\nMAC", width=8, command=open_mac_search_popup, font=emoji_font, bg="lightyellow")
    mac_search_button.grid(row=0, column=2, padx=4, pady=5, sticky=tk.W)

    separator1 = ttk.Separator(button_frame, orient='vertical')
    separator1.grid(row=0, column=3, padx=5, sticky=(tk.N, tk.S))

    stop_button = tk.Button(button_frame, text="▶️\nStart", width=8, command=toggle_start_stop, font=emoji_font, bg="lightcoral")
    stop_button.grid(row=0, column=4, padx=4, pady=5, sticky=tk.W)

    clear_button = tk.Button(button_frame, text="🔄\nClear", width=8, command=clear_table, font=emoji_font, bg="lightgray")
    clear_button.grid(row=0, column=5, padx=4, pady=5, sticky=tk.W)

    save_button = tk.Button(button_frame, text="💾\nSave", width=8, command=save_table, font=emoji_font, bg="lightgray")
    save_button.grid(row=0, column=6, padx=4, pady=5, sticky=tk.W)

    toggle_notification_button = tk.Button(button_frame, text="🔔\nAlerts", width=8, command=toggle_notifications, font=emoji_font, bg="lightyellow")
    toggle_notification_button.grid(row=0, column=7, padx=4, pady=5, sticky=tk.W)

    separator2 = ttk.Separator(button_frame, orient='vertical')
    separator2.grid(row=0, column=8, padx=5, sticky=(tk.N, tk.S))

    green_button = tk.Button(button_frame, text="0\nSuccess", width=8, font=emoji_font, bg="lightgreen", fg="black", bd=2, relief="raised", command=filter_success)
    green_button.grid(row=0, column=9, padx=4, pady=5, sticky=tk.W)

    red_button = tk.Button(button_frame, text="0\nFailure", width=8, font=emoji_font, bg="lightcoral", fg="black", bd=2, relief="raised", command=filter_failure)
    red_button.grid(row=0, column=10, padx=4, pady=5, sticky=tk.W)

    reset_button = tk.Button(button_frame, text="🔂\nReset", width=8, font=emoji_font, bg="lightgray", fg="black", bd=2, relief="raised", command=reset_filter)
    reset_button.grid(row=0, column=11, padx=4, pady=5, sticky=tk.W)
    reset_button.config(state=tk.DISABLED)

    style = ttk.Style()
    style.configure("Status.TLabel", foreground="black")

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

    # Frame for developer and status label
    bottom_frame = ttk.Frame(main_frame)
    bottom_frame.grid(row=3, column=0, sticky=(tk.W, tk.E))

    # Status label for scanning status
    status_label = ttk.Label(bottom_frame, text="", width=50, anchor="w", style="Status.TLabel")
    status_label.pack(side="left")

    # Developer label
    dev_label = ttk.Label(bottom_frame, text="developed by 👽lohit@nerdygeek2127", anchor="e")
    dev_label.pack(side="right")

    main_frame.rowconfigure(2, weight=1)
    main_frame.columnconfigure(0, weight=1)

    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)

    root.mainloop()

if __name__ == "__main__":
    create_host_monitor()

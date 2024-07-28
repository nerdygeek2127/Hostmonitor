# Hostmonitor
The Host Monitor is a Python application with a graphical user interface (GUI) built using Tkinter. It is designed to monitor the status of multiple hosts (IP addresses or hostnames) by pinging them at specified intervals. The application can handle up to 250 hosts simultaneously, providing real-time feedback on the status of each host, Also it has feautre to find the ip Address of the specified Mac input or using only the prefix of first 6 digit

## Features

- **Add Host**: Add hosts with a description, IP address or hostname, and a checking interval.
- **Search**: Scan a network for devices with specific MAC address prefixes.
- **Start/Stop Monitoring**: Start or stop monitoring all added hosts.
- **Clear Table**: Clear all entries in the table.
- **Save**: Save the table entries to an Excel (.xlsx) file.
- **Copy**: Copy the selected table entry to the clipboard.
- **Context Menu**: Right-click context menu for copying table entries.
- **Developer Info**: Display developer information at the bottom of the application.

## Prerequisites

- Python 3.6 or higher
- Required Python packages:
  - `tkinter`
  - `concurrent.futures`
  - `scapy`
  - `ipaddress`
  - `openpyxl`

## Installation

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/nerdygeek2127/host-monitor.git
    cd host-monitor
    ```

2. **Install Dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

3. **Run the Application**:
    ```sh
    python host_monitor.py
    ```

## Creating Executable with PyInstaller

1. **Install PyInstaller**:
    ```sh
    pip install pyinstaller
    ```

2. **Create Executable**:
    Navigate to the directory containing `host_monitor.py` and run:
    ```sh
    pyinstaller --name HostMonitor --onefile --windowed --icon="path_to_your_icon.ico" host_monitor.py
    ```
    Replace `path_to_your_icon.ico` with the actual path to your icon file.

3. **Find Executable**:
    After running the above command, the executable will be available in the `dist` directory.

## Usage

### Adding a Host

1. Click the "➕ Add" button.
2. Enter the description, hostname or IP address, and the checking interval (in seconds).
3. Click "Add Host".

### Searching for Hosts

1. Click the "🔎 Search" button.
2. Enter the network address in CIDR format and the MAC address prefix.
3. Click "Search".

### Starting and Stopping Monitoring

- Click the "▶️ Start" button to start monitoring all added hosts.
- Click the "🚫 Stop" button to stop monitoring.

### Clearing the Table

- Click the "🔄 Clear" button to clear all entries in the table.

### Saving the Table

- Click the "💾 Save" button to save the table entries to an Excel (.xlsx) file.

### Copying Table Entries

- Right-click on a table entry and select "Copy" from the context menu to copy the entry to the clipboard.

## Screenshots

_(Include screenshots of the application interface here)_

## Developer

Developed by 👽 lohit@nerdygeek2127
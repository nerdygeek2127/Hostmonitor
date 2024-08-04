# Hostmonitor
The Host Monitor is a Python application with a graphical user interface (GUI) built using Tkinter. It is designed to monitor the status of multiple hosts (IP addresses or hostnames) by pinging them at specified intervals. The application can handle up to 250 hosts simultaneously, providing real-time feedback on the status of each host, Also it has feautre to find the ip Address of the specified Mac input or using only the prefix of first 6 digit

## Features

- **Add Host**: Add hosts with a description, IP address or hostname, and a checking interval.
- **Search**: Scan a network for devices with specific MAC address prefixes, also search for IP Address with specific MAC address or with the prefix of the MAC address
- **Start/Stop Monitoring**: Start or stop monitoring all added hosts.
- **Clear Table**: Clear all entries in the table.
- **Save**: Save the table entries to an Excel (.xlsx) file.

## Usecases 

- if need to find ip address for specific vendor which has a unique Mac Address for fisrt 6 digits.Enter the first 6 digits and searching for ip with the network address it will show IP Address binded with MAC address.  
- Contniuos monitoring of IOT devices which has IP Address.  

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
![image](https://github.com/user-attachments/assets/fe47b366-1293-4209-9ce6-8ba30e2544a4)
![image](https://github.com/user-attachments/assets/935889f8-e413-4aa3-8706-6598efaad88c)
![image](https://github.com/user-attachments/assets/bc08cbe0-461e-4821-bc63-6ddd9e9431d2)

## Developer
![Alt](https://repobeats.axiom.co/api/embed/5ad7d1b5dbf0c8b66754ae4ebd61e351b1978abb.svg "Repobeats analytics image")

Developed by 👽 lohit@nerdygeek2127

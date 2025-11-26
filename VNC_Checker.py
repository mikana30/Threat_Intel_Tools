import argparse
import json
import os
import random
import socket
import threading
import time
from queue import Queue

from tqdm import tqdm
from utils.atomic_write import atomic_write_json
from utils.file_lock import locked_file

results = []
lock = threading.Lock()

PORTS_TO_SCAN = list(range(5900, 5911))  # Ports 5900 to 5910 inclusive
STATE_FILE_DEFAULT = "vnc_scan_state.json"


def load_state(path: str) -> dict:
    if os.path.exists(path):
        try:
            with locked_file(path, 'r') as f:
                return json.load(f)
        except:
            # If lock fails or file is corrupted, return empty state
            return {}
    return {}


def save_state(path: str, state: dict) -> None:
    from pathlib import Path
    atomic_write_json(Path(path), state)

def check_vnc(host, port):
    try:
        time.sleep(random.uniform(0.5, 2.5))  # Retain jitter for stealth
        with socket.create_connection((host, port), timeout=2.5) as sock:
            banner = sock.recv(12)
            if b"RFB" in banner:
                result = {
                    "host": host,
                    "port": port,
                    "status": "VNC exposed",
                    "banner": banner.decode(errors='ignore')
                }
                with lock:
                    results.append(result)
    except Exception:
        pass

def worker(queue, progress):
    while not queue.empty():
        host, port = queue.get()
        check_vnc(host, port)
        queue.task_done()
        progress.update(1)

def main():
    parser = argparse.ArgumentParser(description="Check for VNC exposure on ports 5900-5910.")
    parser.add_argument('-i', '--input', required=True, help='Input file with IPs/domains')
    parser.add_argument('-o', '--output', required=True, help='Output JSON file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--state-file', default=STATE_FILE_DEFAULT, help='Path to the scan progress file')
    args = parser.parse_args()

    # Load previous results if output file exists
    if os.path.exists(args.output):
        try:
            with locked_file(args.output, 'r') as f:
                global results
                results = json.load(f)
        except:
            # If lock fails, start with empty results
            results = []

    with open(args.input, 'r') as f:
        hosts = [line.strip() for line in f if line.strip()]

    state = load_state(args.state_file)
    
    tasks = []
    for host in hosts:
        # Get the index of the next port to scan for this host
        port_index = state.get(host, 0)
        
        if port_index < len(PORTS_TO_SCAN):
            port_to_scan = PORTS_TO_SCAN[port_index]
            tasks.append((host, port_to_scan))
            # Update the state for the next run
            state[host] = port_index + 1

    if not tasks:
        print("All hosts have been scanned for all VNC ports.")
        return

    random.shuffle(tasks)

    queue = Queue()
    for task in tasks:
        queue.put(task)

    progress = tqdm(total=len(tasks), desc="Scanning VNC", ncols=75)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(queue, progress))
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()
    progress.close()

    # Save the updated results and state using atomic write
    atomic_write_json(Path(args.output), results)
    
    save_state(args.state_file, state)

    print(f"Scan complete for this run. Results appended to {args.output}")

if __name__ == "__main__":
    main()

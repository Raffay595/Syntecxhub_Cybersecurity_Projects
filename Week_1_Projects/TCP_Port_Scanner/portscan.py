import socket
import threading
import logging
from queue import Queue
import sys


THREAD_COUNT = 100
TIMEOUT = 1  # seconds
LOG_FILE = "scan_results.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


queue = Queue()
print_lock = threading.Lock()



def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()

        with print_lock:
            if result == 0:
                print(f"[OPEN]     Port {port}")
                logging.info(f"Port {port} OPEN")
            else:
                print(f"[CLOSED]   Port {port}")
                logging.info(f"Port {port} CLOSED")

    except socket.timeout:
        with print_lock:
            print(f"[TIMEOUT]  Port {port}")
            logging.info(f"Port {port} TIMEOUT")

    except Exception as e:
        with print_lock:
            print(f"[ERROR]    Port {port} → {e}")
            logging.error(f"Port {port} ERROR: {e}")



def worker(host):
    while not queue.empty():
        port = queue.get()
        scan_port(host, port)
        queue.task_done()



def main():
    if len(sys.argv) != 4:
        print("Usage: python portscan.py <host> <start_port> <end_port>")
        sys.exit(1)

    host = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    print(f"\nScanning {host} from port {start_port} to {end_port}\n")

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        print("Invalid host")
        sys.exit(1)

    for port in range(start_port, end_port + 1):
        queue.put(port)

    threads = []
    for _ in range(THREAD_COUNT):
        thread = threading.Thread(target=worker, args=(host,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    queue.join()
    print("\nScan complete. Results saved to scan_results.log")


if __name__ == "__main__":
    main()

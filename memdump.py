import os
import sys
import ctypes
import psutil
import string
from datetime import datetime
from colorama import init, Fore

init(autoreset=True)

MEMORY_PROTECTION_FLAGS = {
    "PAGE_READONLY": 0x02,
    "PAGE_READWRITE": 0x04,
    "PAGE_WRITECOPY": 0x08,
    "PAGE_EXECUTE_READ": 0x20,
    "PAGE_EXECUTE_READWRITE": 0x40,
}

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

def log(message, level="INFO"):
    """Simple logging function with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = {"INFO": Fore.GREEN, "WARNING": Fore.YELLOW, "ERROR": Fore.RED}.get(level, Fore.WHITE)
    print(f"{color}[{timestamp}] {level}: {message}")

def ensure_windows():
    """Ensure the script is running on Windows."""
    if os.name != 'nt':
        log("This script only runs on Windows.", "ERROR")
        sys.exit(1)

def get_process_handle(pid):
    """Get handle for a process by PID."""
    try:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle
    except Exception as e:
        log(f"Error opening process: {e}", "ERROR")
        sys.exit(1)

def read_memory(handle, address, size):
    """Read memory from a process at a given address."""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    success = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[:bytes_read.value]

def is_readable_region(protect):
    """Check if a memory region is readable."""
    return protect in MEMORY_PROTECTION_FLAGS.values()

def list_python_processes(filter_name=None):
    """List Python processes or processes by name running on the system."""
    log("Listing processes...", "INFO")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if filter_name and filter_name.lower() not in name:
                continue
            print(f"PID: {proc.info['pid']} - Name: {proc.info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def dump_memory(pid, output_file=None):
    """Dump memory of a process."""
    try:
        process = psutil.Process(pid)
        handle = get_process_handle(pid)
        if not output_file:
            output_file = f"{pid}.dump"

        log(f"Starting memory dump for PID {pid}...", "INFO")
        with open(output_file, "wb") as out_f:
            address = 0
            mem_info = MEMORY_BASIC_INFORMATION()

            while ctypes.windll.kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mem_info),
                ctypes.sizeof(mem_info),
            ):
                if is_readable_region(mem_info.Protect):
                    start = mem_info.BaseAddress
                    size = mem_info.RegionSize
                    end = start + size
                    log(f"Dumping region {start:016X} - {end:016X}", "INFO")
                    try:
                        chunk = read_memory(handle, start, size)
                        out_f.write(chunk)
                    except Exception as e:
                        log(f"Error dumping region {start:016X} - {end:016X}: {e}", "WARNING")
                address += mem_info.RegionSize

        log(f"Memory dump saved to {output_file}", "INFO")
    except Exception as e:
        log(f"Error during memory dump: {e}", "ERROR")

def extract_strings(filename, min_length=4):
    """Extract readable strings from a binary file with their memory offsets."""
    with open(filename, "rb") as file:
        buffer = ""
        offset = 0  # Track the file offset
        while chunk := file.read(1024):
            for i, char in enumerate(chunk):
                if chr(char) in string.printable:
                    if not buffer:  # Start of a new string
                        start_offset = offset + i
                    buffer += chr(char)
                else:
                    if len(buffer) >= min_length:
                        yield start_offset, buffer
                    buffer = ""
            offset += len(chunk)

        # Check if there's a valid string at the end of the buffer
        if len(buffer) >= min_length:
            yield offset - len(buffer), buffer

def dump_strings(dump_file, pid):
    """Extract strings from a memory dump with addresses."""
    try:
        output_file = f"{pid}.strings"
        with open(output_file, "w") as out_f:
            for address, string in extract_strings(dump_file):
                out_f.write(f"{address:016X}: {string}\n")
        log(f"Strings with addresses extracted to {output_file}", "INFO")
    except FileNotFoundError:
        log(f"Dump file not found: {dump_file}", "ERROR")
    except Exception as e:
        log(f"Error extracting strings: {e}", "ERROR")

def main_menu():
    """Main menu for the tool."""
    while True:
        print(f"\n{Fore.BLUE}Memory Dump Tool - Gaming Comunity")
        print(f"{Fore.CYAN}1. List Python Processes")
        print(f"{Fore.CYAN}2. Dump Process Memory")
        print(f"{Fore.CYAN}3. Extract Strings from Dump")
        print(f"{Fore.CYAN}4. Exit")

        choice = input(f"{Fore.CYAN}Enter your choice: ").strip()
        if choice == "1":
            filter_name = input(f"{Fore.CYAN}Filter by name (press Enter to skip): ").strip()
            list_python_processes(filter_name or None)
        elif choice == "2":
            try:
                pid = int(input(f"{Fore.CYAN}Enter PID to dump: ").strip())
                output_file = input(f"{Fore.CYAN}Enter output file name (press Enter for default): ").strip()
                dump_memory(pid, output_file or None)
            except ValueError:
                log("Invalid PID. Please enter a valid number.", "ERROR")
        elif choice == "3":
            try:
                pid = int(input(f"{Fore.CYAN}Enter PID to extract strings from: ").strip())
                dump_file = f"{pid}.dump"
                dump_strings(dump_file, pid)
            except ValueError:
                log("Invalid PID. Please enter a valid number.", "ERROR")
        elif choice == "4":
            log("Exiting... Goodbye!", "INFO")
            break
        else:
            log("Invalid choice. Please try again.", "WARNING")

if __name__ == "__main__":
    ensure_windows()
    main_menu()

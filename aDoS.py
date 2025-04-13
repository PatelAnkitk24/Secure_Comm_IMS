import threading
import time

blocked_ip_list = []
observed_ip_dict = {}

def update_observed_ip_dict(addr,key):
    if addr in observed_ip_dict:
        if key not in observed_ip_dict[addr]:
            observed_ip_dict[addr][key] = 0
        observed_ip_dict[addr][key] = observed_ip_dict[addr][key] + 1
    else:
        observed_ip_dict[addr] = {}
        observed_ip_dict[addr][key] = 1

def check_and_block_ip(ip, threshold=3):
    if ip not in observed_ip_dict:
        return False  # IP not tracked yet

    for key, value in observed_ip_dict[ip].items():
        if value > threshold:
            if ip not in blocked_ip_list:
                blocked_ip_list.append(ip)
                print(f"🚫 Blocked IP: {ip} for excessive {key} = {value}")
            return True
    return False

def monitor_ips_for_every(minutes):
    while True:
        for ip in list(observed_ip_dict.keys()):
            check_and_block_ip(ip)
        time.sleep(minutes*60)

def start_ip_monitor_for_every(minutes):
    threading.Thread(target=monitor_ips_for_every, args=(0.5,), daemon=True).start()

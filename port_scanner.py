#Objective: Creating a port scanner that will attempt a TCP Connection from local HOSTNAME
#to every port to check of a port is open or not. For optimization we are using multithreads
#to asynchronously check more than 1 port per thread.

#ThreadPoolExecutor does asynchronous execution with threads.
from concurrent.futures import ThreadPoolExecutor
#Socket library that will be used to attempt to form a TCP connection.
import socket
#To measure time it takes
import time
#To check pattern of IP address
import requests

#Scan sctructure : [PORT] | [SERVICE] | [CVES]
scan_results = []

#NVD API KEY
api_key = "1f28c9fe-e679-472e-abc5-fd363f0a06eb"

#given the port range, it will divide the port range evenly into a list to be assigned to a worker
def assign_thread_ports(port_range,MAX_WORKERS):
    port_chunks = []
    start = int(port_range[0])
    end = int(port_range[1])
    #divide chunks evenly throughout 
    chunk_size = (end - start) // MAX_WORKERS

    for i in range(MAX_WORKERS):
        chunk_start = start + i * chunk_size
        #if a remainder is left, it will be accounted for 
        chunk_end = start + (i+1) * chunk_size if i< MAX_WORKERS - 1 else end
        port_chunks.append([chunk_start, chunk_end])
    return port_chunks

def scan(target_ip_address, port_chunk):

    #every port will be checked, if SYN/ACK is received, port is open, otherwise (no response or error) it will return nothing
    #note : ports that are filtered are not accounted for.
    for port in range(port_chunk[0],port_chunk[1]):
        try:
            socket_scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_scan.settimeout(1)
            result = socket_scan.connect_ex((target_ip_address,port))
            
            #open ports with known service will be added, else "unknown"
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except: 
                    service = "unknown"
                scan_results.append({"port": port, "service": service, "cves": []})
            
            socket_scan.close()

        except: 
            continue 


def check_for_cves():

    for item in scan_results:

        service = item["service"]
        if not service or service in ["unnknown", ""]:
            item["cves"].append("[-] Unknown Service.")
            continue
        
        try:
            #request to obtain top 3 cves of service from NVD Website
            headers = {"apiKey": api_key}
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=3"
            response = requests.get(url,headers=headers)

            if response.status_code == 200:
                results = response.json().get("vulnerabilities", [])
                if not results:
                    item["cves"].append("[-] No CVEs found.")
            
                for vulnerabilities in results:

                    #creates a list of top 3 cves, adds to service_cves list, then clears list for next service
                    cve_of_service = vulnerabilities["cve"]["id"]
                    descriptions = vulnerabilities["cve"].get("descriptions",[])
                    desc_of_cve = vulnerabilities["cve"]["descriptions"][0]["value"] if descriptions else "No description avaialable."
                    item["cves"].append(f"{cve_of_service}: {desc_of_cve}")
            else:
                item["cves"].append("[-] Failed to fetch CVEs")
        except:
            print("[X] Error has Occurred!")



def main():

    #input from user - target IP addr, start port, end port
    target_ip_addr = input("Please insert the IP address you would like to target.")
    start_port = input("Please insert starting port of scan.")
    end_port = input("Please insert ending port of scan.")

    port_range = [start_port,end_port]
    total_ports = int(end_port)-int(start_port)

    #max amount of threads that will execute asynchronously
    #depending on given workers, it changes time it takes of port scanner
    MAX_WORKERS = 1 if total_ports < 20 else 20

    #parameter to divide port range evenly
    port_chunks = assign_thread_ports(port_range,MAX_WORKERS)

    print(f"Now scanning {target_ip_addr} from ports {start_port} to {end_port}.")
    start_time = time.time()

    #executing scan function to a thread to asynchronously run.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(scan, [target_ip_addr] * len(port_chunks),port_chunks)
        
    check_for_cves()
    end_time = time.time()

    if not scan_results:
        print("[!] No Ports are open in the given range!")
    else:
        for item in sorted(scan_results, key=lambda x: x["port"]):
            print(f"[!]Port {item["port"]} is open!")
            print(f"     Service: {item["service"]}")
            print(f"     Common Vulnerability & Exposures Associated with Port(CVEs):")
            for cve in item["cves"]:
                print(f"     - {cve}\n")

    print(f"Scanned {total_ports+1} ports in {end_time-start_time:.2f} seconds")

if __name__ == '__main__':
    main()


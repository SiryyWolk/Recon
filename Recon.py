import os
import socket
import argparse
import json
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

#banner grabbing function
def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024).decode().strip()
            if banner:
                print(f"[+] {ip}:{port} - {banner}")
            return banner       
    except (socket.timeout, ConnectionRefusedError):
        pass
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def inspect_https(ip, port, server_hostname=None):
    """Check for HTTPS and return TLS and certificate details when available."""
    result = {
        "https": False,
        "tls_version": None,
        "tls_cipher": None,
        "certificate": None,
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=3) as connection:
            with context.wrap_socket(connection, server_hostname=server_hostname) as tls:
                certificate_der = tls.getpeercert(binary_form=True)
                result["tls_version"] = tls.version()
                result["tls_cipher"] = tls.cipher()[0]
                tls.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {server_hostname or ip}\r\n\r\n".encode()
                )
                result["https"] = tls.recv(128).startswith(b"HTTP/")

                if certificate_der:
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem") as file:
                        file.write(ssl.DER_cert_to_PEM_cert(certificate_der))
                        file.flush()
                        result["certificate"] = ssl._ssl._test_decode_cert(file.name)
    except (socket.timeout, ConnectionError, ssl.SSLError, OSError):
        pass

    return result


# Port scanning function
def scan_port(ip, port, verbose=False, server_hostname=None):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port)
                https_info = inspect_https(ip, port, server_hostname)
                if https_info["https"]:
                    service = f"HTTPS ({https_info['tls_version']})"
                    certificate_status = "certificate found" if https_info["certificate"] else "no certificate"
                    service = f"{service}, {certificate_status}"
                elif https_info["tls_version"]:
                    service = f"TLS service ({https_info['tls_version']}), not HTTP"
                else:
                    service = f"banner: {banner}" if banner else "No banner"
                output = f"[+] Port {port} is open - {service}"
                print(output)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    **https_info,
                }
            elif verbose:
                print(f"[-] Port {port} is closed")
                return None
    except socket.timeout:
        print(f"[-] Port {port} timed out")
        return None
    except Exception as e:
        if verbose:
            print(f"[-] Error: {e} - Port {port}")
            return None            
        
def append_scan_report(report, file_path="scan_result.json"):
    """Append a scan result as a dated text block with JSON content below it."""
    ireland_time = datetime.now(timezone.utc) + timedelta(hours=1)
    timestamp = ireland_time.strftime("%Y-%m-%d %H:%M:%S")
    pretty_report = json.dumps(report, ensure_ascii=False, indent=2)

    with open(file_path, "a", encoding="utf-8") as file:
        if file.tell() > 0:
            file.write("\n\n")
        file.write(f"Scanned at: {timestamp}\n")
        file.write(pretty_report)
        file.write("\n")

    print(f"\n[+] JSON scan report appended to {file_path}")
    return report


#main scan running routine 
def run_scan(target_ip, start_port, end_port, max_threads, verbose, server_hostname=None):
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
    except:
        hostname = "Unknown"
    
    ireland_time = datetime.now(timezone.utc) + timedelta(hours=1)
    print(f"\n[***] Scanning target: {target_ip} ({hostname})")
    print(f"[***] Port range: {start_port}-{end_port}")
    print(f"[***] Starting scan at {ireland_time.strftime('%Y-%m-%d %H:%M:%S')} (UTC+1)\n")
    
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port, verbose, server_hostname)
            for port in range(start_port, end_port + 1)
        ]
        open_ports = [result for future in futures if (result := future.result())]

    report = {
        "target": target_ip,
        "hostname": hostname,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "port_range": {
            "start": start_port,
            "end": end_port,
        },
        "open_ports": sorted(open_ports, key=lambda result: result["port"]),
    }

    append_scan_report(report, "scan_result.json")
    return report
                    

#Argument parsing
def main():
    
    parser = argparse.ArgumentParser(description="Advanced Port Scanner (ReconScan)")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show closed ports)")

    args = parser.parse_args()
    
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Invalide host Name !!") 
        return None

    run_scan(ip, args.start, args.end, args.threads, args.verbose, args.target)

if __name__=="__main__":
    main()
    
           
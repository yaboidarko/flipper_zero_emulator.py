import os
import subprocess
import time
import signal
import sys
import requests
from geopy.geocoders import Nominatim
import nmap

def run_command(command, timeout=60):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=timeout)
        print(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"Command '{command}' timed out after {timeout} seconds")
    except subprocess.CalledProcessError as e:
        print(e.stderr)

def install_dependencies():
    print("Installing dependencies...")
    dependencies = [
        "python", "git", "nmap", "termux-api", "tsu", "wget", "curl", "openssh", "figlet", 
        "toilet", "hydra", "metasploit", "wireshark", "aircrack-ng", "reaver", "wifite", 
        "whois", "dnsutils", "net-tools", "iw", "nano", "bluez", "nfc-utils", "libnfc-bin"
    ]
    
    for package in dependencies:
        run_command(f"pkg install -y {package}")
        
    run_command("pip install requests scapy geopy python-nmap")

def check_dependencies():
    print("Checking dependencies...")
    missing_dependencies = []
    dependencies = [
        "python", "git", "nmap", "termux-api", "tsu", "wget", "curl", "openssh", "figlet", 
        "toilet", "hydra", "metasploit", "wireshark", "aircrack-ng", "reaver", "wifite", 
        "whois", "dnsutils", "net-tools", "iw", "nano", "bluez", "nfc-utils", "libnfc-bin"
    ]
    
    for package in dependencies:
        result = subprocess.run(f"pkg list-installed | grep {package}", shell=True, capture_output=True, text=True)
        if package not in result.stdout:
            missing_dependencies.append(package)
    
    if missing_dependencies:
        print(f"Missing dependencies: {', '.join(missing_dependencies)}")
        install_dependencies()
    else:
        print("All dependencies are installed.")

def wifi_scan():
    print("Scanning for Wi-Fi networks...")
    run_command("termux-wifi-scaninfo")

def network_scan():
    nm = nmap.PortScanner()
    target = input("Enter the target IP address or network (e.g., 192.168.1.1/24): ")
    nm.scan(target)
    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol: {proto}')
            lport = nm[host][proto].keys()
            for port in lport:
                print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}')

def geolocation():
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode(input("Enter a location: "))
    print(location.address)
    print(f"Latitude: {location.latitude}, Longitude: {location.longitude}")

def weather_information():
    city = "Winter Park"
    zip_code = "32792"
    api_key = "YOUR_OPENWEATHERMAP_API_KEY"  # Replace with your OpenWeatherMap API key
    base_url = f"http://api.openweathermap.org/data/2.5/weather?zip={zip_code},us&appid={api_key}"
    response = requests.get(base_url)
    data = response.json()
    if data["cod"] != "404":
        main = data["main"]
        weather = data["weather"][0]
        print(f"City: {city}")
        print(f"Temperature: {main['temp']}")
        print(f"Pressure: {main['pressure']}")
        print(f"Humidity: {main['humidity']}")
        print(f"Weather: {weather['description']}")
    else:
        print("City Not Found!")

def rfid_scan():
    print("Scanning for RFID/NFC tags...")
    run_command("nfc-scan-device")

def rfid_write():
    tag_id = input("Enter the tag ID to write: ")
    data = input("Enter the data to write: ")
    run_command(f"nfc-mfclassic w a {tag_id} data.bin")

def password_crack():
    target = input("Enter the target IP: ")
    service = input("Enter the service (e.g., ssh, ftp): ")
    username = input("Enter the username: ")
    wordlist = input("Enter the path to the wordlist: ")
    run_command(f"hydra -l {username} -P {wordlist} {service}://{target}")

def wireless_security():
    run_command("airmon-ng start wlan0")
    run_command("airodump-ng wlan0mon")
    bssid = input("Enter the BSSID of the target: ")
    channel = input("Enter the channel of the target: ")
    run_command(f"airodump-ng -c {channel} --bssid {bssid} -w capture wlan0mon")
    run_command(f"aireplay-ng --deauth 0 -a {bssid} wlan0mon")
    run_command("aircrack-ng -w wordlist.txt capture*.cap")

def bluetooth_scan():
    print("Scanning for Bluetooth devices...")
    run_command("hcitool scan")

def show_menu():
    menu = """
    Cyberdeck Utility Menu
    ======================
    1. Install Dependencies
    2. Check Dependencies
    3. Wi-Fi Scan
    4. Network Scan
    5. Geolocation
    6. Weather Information
    7. RFID/NFC Scan
    8. RFID/NFC Write
    9. Password Crack
    10. Wireless Security
    11. Bluetooth Scan
    12. Exit
    ======================
    """
    print(menu)

def main():
    while True:
        show_menu()
        choice = input("Select an option: ")
        
        if choice == '1':
            install_dependencies()
        elif choice == '2':
            check_dependencies()
        elif choice == '3':
            wifi_scan()
        elif choice == '4':
            network_scan()
        elif choice == '5':
            geolocation()
        elif choice == '6':
            weather_information()
        elif choice == '7':
            rfid_scan()
        elif choice == '8':
            rfid_write()
        elif choice == '9':
            password_crack()
        elif choice == '10':
            wireless_security()
        elif choice == '11':
            bluetooth_scan()
        elif choice == '12':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

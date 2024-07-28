import os
import subprocess
import time
import signal
import sys

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
        "whois", "dnsutils", "net-tools", "iw", "nano", "bluez"
    ]
    
    for package in dependencies:
        run_command(f"pkg install -y {package}")
        
    run_command("pip install requests scapy geopy nmap")

def check_dependencies():
    print("Checking dependencies...")
    missing_dependencies = []
    dependencies = [
        "python", "git", "nmap", "termux-api", "tsu", "wget", "curl", "openssh", "figlet", 
        "toilet", "hydra", "metasploit", "wireshark", "aircrack-ng", "reaver", "wifite", 
        "whois", "dnsutils", "net-tools", "iw", "nano", "bluez"
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
    try:
        import nmap
    except ImportError:
        print("nmap module not found. Installing...")
        run_command("pip install nmap")
        import nmap

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
    from geopy.geocoders import Nominatim
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode(input("Enter a location: "))
    print(location.address)
    print(f"Latitude: {location.latitude}, Longitude: {location.longitude}")

def weather_information():
    import requests
    city = input("Enter the city name: ")
    api_key = "YOUR_OPENWEATHERMAP_API_KEY"  # Replace with your OpenWeatherMap API key
    base_url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}"
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
    run_command("termux-nfc")

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
    run_command("termux-bluetooth-scan")

def exit_gracefully(signum, frame):
    print("\nExiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, exit_gracefully)
signal.signal(signal.SIGTERM, exit_gracefully)

def menu():
    while True:
        print("\n╔══════════════════════════════════════════════════════════╗")
        print("║                      Cyberdeck Menu                      ║")
        print("╠══════════════════════════════════════════════════════════╣")
        print("║  1. Install Dependencies                                 ║")
        print("║  2. Check Dependencies                                   ║")
        print("║  3. Wi-Fi Scanner                                        ║")
        print("║  4. Network Scanner                                      ║")
        print("║  5. Geolocation                                          ║")
        print("║  6. Weather Information                                  ║")
        print("║  7. RFID/NFC Scanner                                     ║")
        print("║  8. Password Cracking                                    ║")
        print("║  9. Wireless Security                                    ║")
        print("║ 10. Bluetooth Scanner                                    ║")
        print("║ 11. Exit                                                 ║")
        print("╚══════════════════════════════════════════════════════════╝")
        
        choice = input("Enter your choice: ")
        
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
            password_crack()
        elif choice == '9':
            wireless_security()
        elif choice == '10':
            bluetooth_scan()
        elif choice == '11':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()

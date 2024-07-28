import os
import requests
from scapy.all import *
from geopy.geocoders import Nominatim

def install_dependencies():
    print("Installing dependencies...")
    os.system("pkg update && pkg upgrade -y")
    os.system("pkg install python git nmap termux-api tsu wget curl openssh figlet toilet hydra metasploit wireshark aircrack-ng reaver wifite whois dnsutils net-tools iw -y")
    os.system("pip install requests scapy geopy nmap")

def wifi_scan():
    print("Scanning for Wi-Fi networks...")
    os.system("termux-wifi-scaninfo")

def network_scan():
    try:
        import nmap
    except ImportError:
        print("nmap module not found. Installing...")
        os.system("pip install nmap")
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
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode(input("Enter a location: "))
    print(location.address)
    print(f"Latitude: {location.latitude}, Longitude: {location.longitude}")

def weather_information():
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
    os.system("termux-nfc")

def password_crack():
    target = input("Enter the target IP: ")
    service = input("Enter the service (e.g., ssh, ftp): ")
    username = input("Enter the username: ")
    wordlist = input("Enter the path to the wordlist: ")
    os.system(f"hydra -l {username} -P {wordlist} {service}://{target}")

def wireless_security():
    os.system("airmon-ng start wlan0")
    os.system("airodump-ng wlan0mon")
    bssid = input("Enter the BSSID of the target: ")
    channel = input("Enter the channel of the target: ")
    os.system(f"airodump-ng -c {channel} --bssid {bssid} -w capture wlan0mon")
    os.system(f"aireplay-ng --deauth 0 -a {bssid} wlan0mon")
    os.system("aircrack-ng -w wordlist.txt capture*.cap")

def bluetooth_scan():
    os.system("termux-bluetooth-scan")

def menu():
    while True:
        print("\nCyberdeck Menu:")
        print("1. Install Dependencies")
        print("2. Wi-Fi Scanner")
        print("3. Network Scanner")
        print("4. Geolocation")
        print("5. Weather Information")
        print("6. RFID/NFC Scanner")
        print("7. Password Cracking")
        print("8. Wireless Security")
        print("9. Bluetooth Scanner")
        print("10. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            install_dependencies()
        elif choice == '2':
            wifi_scan()
        elif choice == '3':
            network_scan()
        elif choice == '4':
            geolocation()
        elif choice == '5':
            weather_information()
        elif choice == '6':
            rfid_scan()
        elif choice == '7':
            password_crack()
        elif choice == '8':
            wireless_security()
        elif choice == '9':
            bluetooth_scan()
        elif choice == '10':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()

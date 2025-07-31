config for spoofr works in tandem with detector

main.plugins.spoofr.enabled = true
main.plugins.spoofr.spoof_targets = ["pwnagotchi", "flipper"]
main.plugins.spoofr.spoof_duration = 300
main.plugins.spoofr.randomize_mac = true
main.plugins.spoofr.ui_position = [0, 120]
main.plugins.spoofr.font_size = "small"
main.plugins.spoofr.log_file = "/var/log/spoofr.json"
main.plugins.spoofr.gps_enabled = true
main.plugins.spoofr.gpsd_host = "127.0.0.1"
main.plugins.spoofr.gpsd_port = 2947
main.plugins.spoofr.check_interval = 60
main.plugins.spoofr.bluetooth_interface = "hci0"
main.plugins.spoofr.wifi_interface = "wlan0"
main.plugins.pwn_detector.enabled = true
----------------------------------------------------------------------------
main.plugins.pwn_detector.enabled = true
main.plugins.pwn_detector.bluetooth_scan = true
main.plugins.pwn_detector.wifi_interface = "wlan0mon"
main.plugins.pwn_detector.scan_interval = 60
main.plugins.pwn_detector.pwnagotchi_pattern = "pwnagotchi-[0-9a-f]{6}"
main.plugins.pwn_detector.flipper_bt_name = "Flipper.*"
main.plugins.pwn_detector.flipper_wifi_pattern = "Marauder.*|ESP32.*"
main.plugins.pwn_detector.max_display_names = 3
main.plugins.pwn_detector.display_rotation_interval = 5
main.plugins.pwn_detector.pwn_ui_position = [0, 80]
main.plugins.pwn_detector.flip_ui_position = [0, 90]
main.plugins.pwn_detector.font_size = "small"
main.plugins.pwn_detector.log_file = "/var/log/pwn_detector.json"
main.plugins.pwn_detector.notify = true

you may need --pip3 install pybluez

sudo apt-get update
sudo apt-get install gpsd gpsd-clients bluetooth bluez
sudo pip3 install gpsd-py3 pybluez

Configure GPSD:

Ensure your GPS module (e.g., U-blox 7) is connected (e.g., /dev/ttyACM0).
Configure gpsd to start automatically and use the correct device:
bashsudo bash -c 'cat > /etc/default/gpsd' << EOF
START_DAEMON="true"
USBAUTO="false"
DEVICES="/dev/ttyACM0"
GPSD_OPTIONS="-n"
EOF
sudo systemctl enable gpsd.service
sudo systemctl start gpsd.service

Test GPS with gpsmon to confirm data output ().

Adjust gps_ui_position to avoid overlap (e.g., [80, 0] for top-right on a 128x64 display).
Ensure gpsd_host and gpsd_port match your gpsd setup.


Ensure Log File Permissions:
bashsudo touch /var/log/pwn_detector.json
sudo chown pwnagotchi:pwnagotchi /var/log/pwn_detector.json

Restart Pwnagotchi:
bashsudo systemctl restart pwnagotchi


Usage

GPS Requirements:

A USB GPS module (e.g., U-blox 7) must be connected and detected (e.g., /dev/ttyACM0).
gpsd must be running and configured to read from the GPS device.
Enable GPS with gps_enabled = true in config.toml.


UI Display:

GPS coordinates (latitude, longitude, altitude) appear at gps_ui_position when a 2D/3D fix is available, formatted as:
textGPS: -
or, with a fix:
textLat: 37.1234
Lon: -122.5678
Alt: 10.5m

Pwnagotchi and Flipper counts/names remain at their configured positions.


Logging:

Detections are logged to /var/log/pwn_detector.json with GPS data, e.g.:
json{
  "timestamp": "2025-07-31 17:21:00",
  "pwnagotchis": [
    {
      "mac": "00:11:22:33:44:55",
      "name": "pwnagotchi-123456",
      "rssi": -60,
      "last_seen": 1625247660.0,
      "gps": {"Latitude": 37.1234, "Longitude": -122.5678, "Altitude": 10.5, "Time": "2025-07-31T17:21:00Z", "Satellites": 8}
    }
  ],
  "flippers": []
}



Handshake GPS:

When a handshake is captured, GPS coordinates are saved to a .gps.json file alongside the .pcap file, e.g., /root/handshakes/SSID_1234567890.gps.json.


Web UI:

Access http://<pwnagotchi-ip>/plugins/pwn_detector for a JSON response including detected devices and current GPS coordinates.


Logs:

Check /var/log/pwnagotchi.log for detection events, GPS errors, and UI warnings.


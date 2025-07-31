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

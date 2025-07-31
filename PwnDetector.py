import logging
import re
import time
import json
import subprocess
import os
from threading import Lock
import pwnagotchi.ui.components as components
import pwnagotchi.ui.view as view
import pwnagotchi.ui.fonts as fonts
import pwnagotchi.plugins as plugins
import pwnagotchi

try:
    import bluetooth
except ImportError:
    bluetooth = None

try:
    import gpsd
except ImportError:
    gpsd = None

class PwnDetector(plugins.Plugin):
    __author__ = ""
    __version__ = "1.4.0"
    __license__ = "PWN"
    __description__ = "Detects other Pwnagotchi devices and Flipper Zeros via Wi-Fi and Bluetooth, displaying names, counts, and GPS coordinates on UI with custom positioning, logging to file, and notifications"
    __name__ = "PwnDetector"
    __help__ = """
    A plugin to detect other Pwnagotchi devices by Wi-Fi signatures (e.g., SSIDs like 'pwnagotchi-*')
    and Flipper Zero devices via Bluetooth advertisements or Wi-Fi activity (e.g., Marauder firmware).
    Displays detected device names, counts, and GPS coordinates on the UI with configurable positioning,
    logs to a file, notifies on new detections, and saves GPS data with handshakes.
    """
    __dependencies__ = {
        "apt": ["bluetooth", "bluez", "gpsd", "gpsd-clients"],
        "pip": ["pybluez", "gpsd-py3"]
    }
    __defaults__ = {
        "enabled": False,
        "bluetooth_scan": True,  # Enable Bluetooth scanning if adapter available
        "wifi_interface": "wlan0mon",  # Monitor mode interface
        "scan_interval": 60,  # Seconds between scans
        "pwnagotchi_pattern": r"pwnagotchi-[0-9a-f]{6}",  # Regex for Pwnagotchi SSIDs
        "flipper_bt_name": r"Flipper.*",  # Regex for Flipper Zero Bluetooth names
        "flipper_wifi_pattern": r"Marauder.*|ESP32.*",  # Regex for Flipper Wi-Fi SSIDs
        "max_display_names": 3,  # Max number of names to show on UI
        "display_rotation_interval": 5,  # Seconds to rotate displayed names
        "pwn_ui_position": [0, 80],  # [x, y] coordinates for Pwnagotchi UI element
        "flip_ui_position": [0, 90],  # [x, y] coordinates for Flipper Zero UI element
        "font_size": "small",  # Font size: small, medium, bold
        "log_file": "/var/log/pwn_detector.json",  # File to log detections
        "notify": True,  # Flash screen on new detections
        "gps_enabled": False,  # Enable GPS integration
        "gpsd_host": "127.0.0.1",  # GPSD host
        "gpsd_port": 2947,  # GPSD port
        "gps_ui_position": [0, 100],  # [x, y] coordinates for GPS UI element
    }

    def __init__(self):
        self._lock = Lock()
        self._pwnagotchis = {}  # {mac: {"name": str, "last_seen": float, "rssi": int, "gps": dict}}
        self._flippers = {}  # {mac: {"name": str, "type": str, "last_seen": float, "rssi": int, "gps": dict}}
        self._bt_available = False
        self._gps_available = False
        self._gps = None
        self._coordinates = None
        self._last_scan = 0
        self._last_rotation = 0
        self._current_name_index = 0
        self._known_macs = set()

    def on_loaded(self):
        logging.info("[PwnDetector] Plugin loaded")
        # Validate UI positions
        for opt, value in [("pwn_ui_position", self.options["pwn_ui_position"]), 
                          ("flip_ui_position", self.options["flip_ui_position"]),
                          ("gps_ui_position", self.options["gps_ui_position"])]:
            if not isinstance(value, (list, tuple)) or len(value) != 2 or not all(isinstance(i, int) for i in value):
                logging.error(f"[PwnDetector] Invalid {opt}: {value}. Must be [x, y] with integers. Using default.")
                self.options[opt] = self.__defaults__[opt]
            elif value[0] < 0 or value[1] < 0 or value[0] > 128 or value[1] > 64:
                logging.warning(f"[PwnDetector] {opt}: {value} may be out of screen fee bounds (128x64). Ensure visibility.")
        # Validate font size
        font_map = {"small": fonts.SMALL, "medium": fonts.MEDIUM, "bold": fonts.BOLD}
        if self.options["font_size"].lower() not in font_map:
            logging.error(f"[PwnDetector] Invalid font_size: {self.options['font_size']}. Using 'small'.")
            self.options["font_size"] = "small"
        self._font = font_map[self.options["font_size"].lower()]
        # Validate log file path
        log_dir = os.path.dirname(self.options["log_file"])
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except Exception as e:
                logging.error(f"[PwnDetector] Failed to create log directory {log_dir}: {str(e)}")
                self.options["log_file"] = ""
        # Check Bluetooth availability
        if self.options["bluetooth_scan"] and bluetooth:
            try:
                subprocess.check_call(["hciconfig", "hci0", "up"])
                self._bt_available = True
                logging.info("[PwnDetector] Bluetooth adapter detected")
            except (subprocess.CalledProcessError, FileNotFoundError):
                logging.warning("[PwnDetector] Bluetooth adapter not found or not configured")
                self._bt_available = False
        else:
            logging.info("[PwnDetector] Bluetooth scanning disabled or pybluez not installed")
            self._bt_available = False
        # Check GPS availability
        if self.options["gps_enabled"] and gpsd:
            try:
                gpsd.connect(self.options["gpsd_host"], self.options["gpsd_port"])
                self._gps = gpsd
                self._gps_available = True
                logging.info(f"[PwnDetector] GPSD connected at {self.options['gpsd_host']}:{self.options['gpsd_port']}")
            except Exception as e:
                logging.error(f"[PwnDetector] Failed to connect to GPSD: {str(e)}")
                self._gps_available = False
        else:
            logging.info("[PwnDetector] GPS disabled or gpsd-py3 not installed")
            self._gps_available = False
        # Add UI elements
        self._ui_elements()

    def _ui_elements(self):
        with self._lock:
            components.Text(
                self,
                xy=tuple(self.options["pwn_ui_position"]),
                value="Pwn: 0",
                font=self._font,
                color=view.BLACK,
                name="pwn_info"
            )
            components.Text(
                self,
                xy=tuple(self.options["flip_ui_position"]),
                value="Flip: 0",
                font=self._font,
                color=view.BLACK,
                name="flip_info"
            )
            if self._gps_available:
                components.Text(
                    self,
                    xy=tuple(self.options["gps_ui_position"]),
                    value="GPS: -",
                    font=self._font,
                    color=view.BLACK,
                    name="gps_info"
                )

    def on_unloaded(self):
        logging.info("[PwnDetector] Plugin unloaded")
        with self._lock:
            components.remove("pwn_info")
            components.remove("flip_info")
            if self._gps_available:
                components.remove("gps_info")

    def _get_gps_data(self):
        """Fetch current GPS coordinates from gpsd"""
        if not self._gps_available:
            return None
        try:
            packet = self._gps.get_current()
            if packet.mode >= 2:  # 2D or 3D fix
                return {
                    "Latitude": packet.lat,
                    "Longitude": packet.lon,
                    "Altitude": packet.alt if packet.mode == 3 else 0,
                    "Time": packet.time,
                    "Satellites": packet.satellites_used
                }
            return None
        except Exception as e:
            logging.warning(f"[PwnDetector] GPS data fetch error: {str(e)}")
            return None

    def on_wifi_update(self, agent, access_points):
        """Called when bettercap updates Wi-Fi access points"""
        current_time = time.time()
        if current_time - self._last_scan < self.options["scan_interval"]:
            return
        self._last_scan = current_time
        pwn_pattern = re.compile(self.options["pwnagotchi_pattern"], re.IGNORECASE)
        flip_wifi_pattern = re.compile(self.options["flipper_wifi_pattern"], re.IGNORECASE)
        new_detections = False
        gps_data = self._get_gps_data()
        for ap in access_points:
            ssid = ap.get("hostname", "").strip()
            mac = ap.get("mac", "").lower()
            rssi = ap.get("rssi", -100)
            if not mac or not ssid:
                continue
            # Detect Pwnagotchi
            if pwn_pattern.match(ssid):
                with self._lock:
                    if mac not in self._pwnagotchis:
                        new_detections = True
                        self._known_macs.add(mac)
                    self._pwnagotchis[mac] = {
                        "name": ssid,
                        "last_seen": current_time,
                        "rssi": rssi,
                        "gps": gps_data
                    }
                    logging.info(f"[PwnDetector] Detected Pwnagotchi: {ssid} ({mac}, RSSI: {rssi}, GPS: {gps_data})")
            # Detect Flipper Zero via Wi-Fi
            elif flip_wifi_pattern.match(ssid):
                with self._lock:
                    if mac not in self._flippers:
                        new_detections = True
                        self._known_macs.add(mac)
                    self._flippers[mac] = {
                        "name": ssid,
                        "type": "Wi-Fi",
                        "last_seen": current_time,
                        "rssi": rssi,
                        "gps": gps_data
                    }
                    logging.info(f"[PwnDetector] Detected Flipper Zero (Wi-Fi): {ssid} ({mac}, RSSI: {rssi}, GPS: {gps_data})")
        if new_detections and self.options["notify"]:
            self._notify()
        self._update_ui()
        self._log_detections()
        self._clean_old_detections(current_time)
        if self._bt_available:
            self._scan_bluetooth()

    def _scan_bluetooth(self):
        """Scan for Flipper Zero devices via Bluetooth"""
        try:
            devices = bluetooth.discover_devices(duration=8, lookup_names=True, flush_cache=True)
            current_time = time.time()
            flip_bt_pattern = re.compile(self.options["flipper_bt_name"], re.IGNORECASE)
            new_detections = False
            gps_data = self._get_gps_data()
            for addr, name in devices:
                addr = addr.lower()
                if flip_bt_pattern.match(name):
                    with self._lock:
                        if addr not in self._flippers:
                            new_detections = True
                            self._known_macs.add(addr)
                        self._flippers[addr] = {
                            "name": name,
                            "type": "Bluetooth",
                            "last_seen": current_time,
                            "rssi": -50,  # Approximate RSSI for Bluetooth
                            "gps": gps_data
                        }
                        logging.info(f"[PwnDetector] Detected Flipper Zero (Bluetooth): {name} ({addr}, GPS: {gps_data})")
            if new_detections and self.options["notify"]:
                self._notify()
            self._update_ui()
            self._log_detections()
        except Exception as e:
            logging.error(f"[PwnDetector] Bluetooth scan error: {str(e)}")

    def _notify(self):
        """Flash screen to notify of new detection"""
        try:
            view.set("status", "New device detected!")
            time.sleep(1)
            view.set("status", "")
        except Exception as e:
            logging.warning(f"[PwnDetector] Notification error: {str(e)}")

    def _update_ui(self):
        """Update UI with current detection counts, names, and GPS coordinates"""
        with self._lock:
            current_time = time.time()
            max_names = self.options["max_display_names"]
            # Pwnagotchi UI
            pwn_count = len(self._pwnagotchis)
            pwn_names = [info["name"][:20] for info in self._pwnagotchis.values()]
            pwn_display = f"Pwn: {pwn_count}"
            if pwn_names:
                if current_time - self._last_rotation > self.options["display_rotation_interval"]:
                    self._current_name_index = (self._current_name_index + max_names) % max(len(pwn_names), 1)
                    self._last_rotation = current_time
                display_names = pwn_names[self._current_name_index:self._current_name_index + max_names]
                pwn_display += "\n" + "\n".join(display_names)
            components.update("pwn_info", value=pwn_display)
            # Flipper Zero UI
            flip_count = len(self._flippers)
            flip_names = [info["name"][:20] for info in self._flippers.values()]
            flip_display = f"Flip: {flip_count}"
            if flip_names:
                display_names = flip_names[self._current_name_index:self._current_name_index + max_names]
                flip_display += "\n" + "\n".join(display_names)
            components.update("flip_info", value=flip_display)
            # GPS UI
            if self._gps_available:
                gps_data = self._get_gps_data()
                gps_display = "GPS: -"
                if gps_data and gps_data["Latitude"] and gps_data["Longitude"]:
                    gps_display = f"Lat: {gps_data['Latitude']:.4f}\nLon: {gps_data['Longitude']:.4f}\nAlt: {gps_data['Altitude']:.1f}m"
                components.update("gps_info", value=gps_display)

    def _log_detections(self):
        """Log detections to a file"""
        if not self.options["log_file"]:
            return
        try:
            with self._lock:
                data = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "pwnagotchis": [
                        {"mac": mac, "name": info["name"], "rssi": info["rssi"], "last_seen": info["last_seen"], "gps": info["gps"]}
                        for mac, info in self._pwnagotchis.items()
                    ],
                    "flippers": [
                        {"mac": mac, "name": info["name"], "type": info["type"], "rssi": info["rssi"], "last_seen": info["last_seen"], "gps": info["gps"]}
                        for mac, info in self._flippers.items()
                    ]
                }
            with open(self.options["log_file"], "a") as f:
                json.dump(data, f)
                f.write("\n")
        except Exception as e:
            logging.error(f"[PwnDetector] Failed to log detections to {self.options['log_file']}: {str(e)}")

    def _clean_old_detections(self, current_time):
        """Remove devices not seen for over 5 minutes"""
        timeout = 300  # 5 minutes
        with self._lock:
            self._pwnagotchis = {
                mac: info for mac, info in self._pwnagotchis.items()
                if current_time - info["last_seen"] < timeout
            }
            self._flippers = {
                mac: info for mac, info in self._flippers.items()
                if current_time - info["last_seen"] < timeout
            }
            self._known_macs = {mac for mac in self._known_macs if mac in self._pwnagotchis or mac in self._flippers}

    def on_handshake(self, agent, filename, access_point, client_station):
        """Save GPS coordinates with handshake captures"""
        if self._gps_available:
            gps_data = self._get_gps_data()
            if gps_data and gps_data["Latitude"] and gps_data["Longitude"]:
                gps_filename = filename.replace(".pcap", ".gps.json")
                try:
                    with open(gps_filename, "w") as fp:
                        json.dump(gps_data, fp)
                    logging.info(f"[PwnDetector] Saved GPS to {gps_filename}: {gps_data}")
                except Exception as e:
                    logging.error(f"[PwnDetector] Failed to save GPS to {gps_filename}: {str(e)}")
            else:
                logging.info("[PwnDetector] Not saving GPS for handshake: No valid coordinates")

    def on_ui_update(self, ui):
        """Ensure UI elements are refreshed"""
        self._update_ui()

    def on_webhook(self, path, request):
        """Provide a web UI to view detected devices and GPS data"""
        if path == "/pwn_detector":
            with self._lock:
                return json.dumps({
                    "pwnagotchis": [
                        {"mac": mac, "name": info["name"], "rssi": info["rssi"], "last_seen": info["last_seen"], "gps": info["gps"]}
                        for mac, info in self._pwnagotchis.items()
                    ],
                    "flippers": [
                        {"mac": mac, "name": info["name"], "type": info["type"], "rssi": info["rssi"], "last_seen": info["last_seen"], "gps": info["gps"]}
                        for mac, info in self._flippers.items()
                    ],
                    "current_gps": self._get_gps_data()
                })
        return None

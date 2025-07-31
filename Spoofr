import logging
import time
import json
import os
import random
import re
import subprocess
from threading import Lock
import pwnagotchi.ui.components as components
import pwnagotchi.ui.view as view
import pwnagotchi.ui.fonts as fonts
import pwnagotchi.plugins as plugins
import pwnagotchi

try:
    import gpsd
except ImportError:
    gpsd = None

class Spoofr(plugins.Plugin):
    __author__ = ""
    __version__ = "1.1.0"
    __license__ = "PWN"
    __description__ = "Spoofs Wi-Fi SSID or Bluetooth name to mimic detected Pwnagotchi or Flipper Zero devices, with UI display, GPS logging, and web-based dashboard"
    __name__ = "Spoofr"
    __help__ = """
    A plugin that spoofs Wi-Fi SSID or Bluetooth name to mimic Pwnagotchi or Flipper Zero devices detected by PwnDetector.
    Displays the current spoofed identity on the UI with configurable positioning, logs actions with GPS coordinates,
    reverts to original settings after a set duration, and provides a web dashboard for status and control.
    For ethical testing only.
    """
    __dependencies__ = {
        "apt": ["gpsd", "gpsd-clients", "hostapd", "bluez"],
        "pip": ["gpsd-py3"]
    }
    __defaults__ = {
        "enabled": False,
        "spoof_targets": ["pwnagotchi", "flipper"],  # Options: "pwnagotchi", "flipper"
        "spoof_duration": 300,  # Seconds to maintain spoof
        "randomize_mac": True,  # Randomize MAC address when spoofing
        "ui_position": [0, 120],  # [x, y] coordinates for UI element
        "font_size": "small",  # Font size: small, medium, bold
        "log_file": "/var/log/spoofr.json",
        "gps_enabled": False,
        "gpsd_host": "127.0.0.1",
        "gpsd_port": 2947,
        "check_interval": 60,  # Seconds between spoof updates
        "bluetooth_interface": "hci0",
        "wifi_interface": "wlan0"
    }

    def __init__(self):
        self._lock = Lock()
        self._gps_available = False
        self._gps = None
        self._last_spoof = 0
        self._current_spoof = None  # {"type": "wifi" or "bluetooth", "name": str}
        self._original_ssid = None
        self._original_bt_name = None
        self._original_mac = None

    def on_loaded(self):
        logging.info("[Spoofr] Plugin loaded")
        # Validate UI position
        if not isinstance(self.options["ui_position"], (list, tuple)) or len(self.options["ui_position"]) != 2:
            logging.error(f"[Spoofr] Invalid ui_position: {self.options['ui_position']}. Using default.")
            self.options["ui_position"] = self.__defaults__["ui_position"]
        # Validate font size
        font_map = {"small": fonts.SMALL, "medium": fonts.MEDIUM, "bold": fonts.BOLD}
        if self.options["font_size"].lower() not in font_map:
            logging.error(f"[Spoofr] Invalid font_size: {self.options['font_size']}. Using 'small'.")
            self.options["font_size"] = "small"
        self._font = font_map[self.options["font_size"].lower()]
        # Validate log file path
        log_dir = os.path.dirname(self.options["log_file"])
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except Exception as e:
                logging.error(f"[Spoofr] Failed to create log directory {log_dir}: {str(e)}")
                self.options["log_file"] = ""
        # Initialize GPS
        if self.options["gps_enabled"] and gpsd:
            try:
                gpsd.connect(self.options["gpsd_host"], self.options["gpsd_port"])
                self._gps = gpsd
                self._gps_available = True
                logging.info(f"[Spoofr] GPSD connected at {self.options['gpsd_host']}:{self.options['gpsd_port']}")
            except Exception as e:
                logging.error(f"[Spoofr] Failed to connect to GPSD: {str(e)}")
                self._gps_available = False
        else:
            logging.info("[Spoofr] GPS disabled or gpsd-py3 not installed")
            self._gps_available = False
        # Save original settings
        try:
            self._original_ssid = self._get_current_ssid()
            self._original_bt_name = self._get_current_bt_name()
            self._original_mac = self._get_current_mac()
            logging.info(f"[Spoofr] Original settings: SSID={self._original_ssid}, BT={self._original_bt_name}, MAC={self._original_mac}")
        except Exception as e:
            logging.error(f"[Spoofr] Failed to save original settings: {str(e)}")
        # Add UI element
        self._ui_elements()

    def _ui_elements(self):
        with self._lock:
            components.Text(
                self,
                xy=tuple(self.options["ui_position"]),
                value="Spoof: None",
                font=self._font,
                color=view.BLACK,
                name="spoof_info"
            )

    def on_unloaded(self):
        logging.info("[Spoofr] Plugin unloaded")
        self._revert_spoof()
        with self._lock:
            components.remove("spoof_info")

    def _get_current_ssid(self):
        """Get current Wi-Fi SSID from hostapd.conf"""
        try:
            with open("/etc/hostapd/hostapd.conf", "r") as f:
                for line in f:
                    if line.startswith("ssid="):
                        return line.strip().split("=")[1]
        except Exception as e:
            logging.error(f"[Spoofr] Failed to read SSID: {str(e)}")
        return "pwnagotchi"

    def _get_current_bt_name(self):
        """Get current Bluetooth device name"""
        try:
            result = subprocess.check_output(["hciconfig", self.options["bluetooth_interface"], "name"]).decode()
            return result.strip().split(": ")[1]
        except Exception:
            return "pwnagotchi"

    def _get_current_mac(self):
        """Get current Wi-Fi MAC address"""
        try:
            result = subprocess.check_output(["ifconfig", self.options["wifi_interface"]]).decode()
            for line in result.split("\n"):
                if "ether" in line:
                    return line.strip().split("ether")[1].strip().split()[0]
        except Exception:
            return None

    def _get_gps_data(self):
        """Fetch current GPS coordinates"""
        if not self._gps_available:
            return None
        try:
            packet = self._gps.get_current()
            if packet.mode >= 2:
                return {
                    "Latitude": packet.lat,
                    "Longitude": packet.lon,
                    "Altitude": packet.alt if packet.mode == 3 else 0,
                    "Time": packet.time,
                    "Satellites": packet.satellites_used
                }
            return None
        except Exception as e:
            logging.warning(f"[Spoofr] GPS data fetch error: {str(e)}")
            return None

    def _spoof_wifi(self, ssid):
        """Change Wi-Fi SSID and optionally MAC"""
        try:
            # Update hostapd.conf
            with open("/etc/hostapd/hostapd.conf", "r") as f:
                config = f.read()
            config = re.sub(r"ssid=.*", f"ssid={ssid}", config)
            with open("/tmp/hostapd.conf", "w") as f:
                f.write(config)
            subprocess.run(["sudo", "mv", "/tmp/hostapd.conf", "/etc/hostapd/hostapd.conf"], check=True)
            # Change MAC if enabled
            if self.options["randomize_mac"]:
                new_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                subprocess.run(["sudo", "ifconfig", self.options["wifi_interface"], "down"], check=True)
                subprocess.run(["sudo", "ifconfig", self.options["wifi_interface"], "hw", "ether", new_mac], check=True)
                subprocess.run(["sudo", "ifconfig", self.options["wifi_interface"], "up"], check=True)
            # Restart hostapd
            subprocess.run(["sudo", "systemctl", "restart", "hostapd"], check=True)
            logging.info(f"[Spoofr] Spoofed Wi-Fi SSID to {ssid}")
            return True
        except Exception as e:
            logging.error(f"[Spoofr] Failed to spoof Wi-Fi SSID: {str(e)}")
            return False

    def _spoof_bluetooth(self, name):
        """Change Bluetooth device name"""
        try:
            subprocess.run(["sudo", "hciconfig", self.options["bluetooth_interface"], "name", name], check=True)
            logging.info(f"[Spoofr] Spoofed Bluetooth name to {name}")
            return True
        except Exception as e:
            logging.error(f"[Spoofr] Failed to spoof Bluetooth name: {str(e)}")
            return False

    def _revert_spoof(self):
        """Revert to original SSID, Bluetooth name, and MAC"""
        try:
            if self._current_spoof:
                if self._current_spoof["type"] == "wifi" and self._original_ssid:
                    self._spoof_wifi(self._original_ssid)
                    if self.options["randomize_mac"] and self._original_mac:
                        subprocess.run(["sudo", "ifconfig", self.options["wifi_interface"], "down"], check=True)
                        subprocess.run(["sudo", "ifconfig", self.options["wifi_interface"], "hw", "ether", self._original_mac], check=True)
                        subprocess.run(["sudo", "ifconfig", self.options["wifi_interface"], "up"], check=True)
                elif self._current_spoof["type"] == "bluetooth" and self._original_bt_name:
                    self._spoof_bluetooth(self._original_bt_name)
                self._current_spoof = None
                logging.info("[Spoofr] Reverted to original settings")
        except Exception as e:
            logging.error(f"[Spoofr] Failed to revert spoof: {str(e)}")

    def _log_spoof(self):
        """Log spoofing action"""
        if not self.options["log_file"]:
            return
        try:
            with self._lock:
                gps_data = self._get_gps_data()
                data = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "spoof": self._current_spoof,
                    "gps": gps_data
                }
                with open(self.options["log_file"], "a") as f:
                    json.dump(data, f)
                    f.write("\n")
        except Exception as e:
            logging.error(f"[Spoofr] Failed to log to {self.options['log_file']}: {str(e)}")

    def on_wifi_update(self, agent, access_points):
        """Check for spoofing opportunities"""
        current_time = time.time()
        if current_time - self._last_spoof < self.options["check_interval"]:
            return
        self._last_spoof = current_time
        if "pwn_detector" not in plugins.loaded:
            logging.warning("[Spoofr] PwnDetector not loaded, cannot spoof")
            self._revert_spoof()
            self._update_ui()
            return
        pwn_detector = plugins.loaded["pwn_detector"]
        with self._lock:
            candidates = []
            if "pwnagotchi" in self.options["spoof_targets"]:
                candidates.extend(
                    {"type": "wifi", "name": info["name"]}
                    for info in pwn_detector._pwnagotchis.values()
                )
            if "flipper" in self.options["spoof_targets"]:
                candidates.extend(
                    {"type": info["type"].lower(), "name": info["name"]}
                    for info in pwn_detector._flippers.values()
                )
            if not candidates:
                self._revert_spoof()
                self._update_ui()
                return
            # Select a random candidate
            new_spoof = random.choice(candidates)
            if new_spoof != self._current_spoof:
                self._revert_spoof()
                if new_spoof["type"] == "wifi":
                    success = self._spoof_wifi(new_spoof["name"])
                else:
                    success = self._spoof_bluetooth(new_spoof["name"])
                if success:
                    self._current_spoof = new_spoof
                    self._log_spoof()
            self._update_ui()

    def _update_ui(self):
        """Update UI with current spoofed identity"""
        with self._lock:
            display_text = "Spoof: None"
            if self._current_spoof:
                display_text = f"Spoof: {self._current_spoof['name'][:20]}\n{self._current_spoof['type'].title()}"
            components.update("spoof_info", value=display_text)

    def on_ui_update(self, ui):
        """Ensure on-screen UI is refreshed"""
        self._update_ui()

    def on_webhook(self, path, request):
        """Provide web UI for spoof status and control"""
        if path == "/spoofr":
            if request.method == "POST":
                try:
                    data = json.loads(request.body.decode())
                    if "action" in data:
                        if data["action"] == "revert":
                            self._revert_spoof()
                        elif data["action"] == "spoof" and "type" in data and "name" in data:
                            with self._lock:
                                self._revert_spoof()
                                new_spoof = {"type": data["type"], "name": data["name"]}
                                success = self._spoof_wifi(new_spoof["name"]) if new_spoof["type"] == "wifi" else self._spoof_bluetooth(new_spoof["name"])
                                if success:
                                    self._current_spoof = new_spoof
                                    self._log_spoof()
                            self._update_ui()
                    return json.dumps({"status": "success"})
                except Exception as e:
                    logging.error(f"[Spoofr] Webhook POST error: {str(e)}")
                    return json.dumps({"status": "error", "message": str(e)})
            # GET request: Serve HTML dashboard
            pwn_detector = plugins.loaded.get("pwn_detector", None)
            pwnagotchis = pwn_detector._pwnagotchis if pwn_detector else {}
            flippers = pwn_detector._flippers if pwn_detector else {}
            gps_data = self._get_gps_data()
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Spoofr Dashboard</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    body { padding: 20px; background-color: #f8f9fa; }
                    .card { margin-bottom: 20px; }
                    .btn { margin-right: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="text-center mb-4">Spoofr Dashboard</h1>
                    <div class="card">
                        <div class="card-header">Current Spoof</div>
                        <div class="card-body">
                            <p><strong>Status:</strong> {}</p>
                            <button class="btn btn-danger" onclick="sendAction('revert')">Stop Spoofing</button>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">Detected Devices (PwnDetector)</div>
                        <div class="card-body">
                            <h5>Pwnagotchis</h5>
                            <ul class="list-group mb-3">
                                {}
                            </ul>
                            <h5>Flipper Zeros</h5>
                            <ul class="list-group mb-3">
                                {}
                            </ul>
                            <h5>Spoof a Device</h5>
                            <select id="spoofTarget" class="form-select mb-3">
                                <option value="">Select a device</option>
                                {}
                            </select>
                            <button class="btn btn-primary" onclick="spoofDevice()">Spoof Selected</button>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">GPS Data</div>
                        <div class="card-body">
                            {}
                        </div>
                    </div>
                </div>
                <script>
                    function sendAction(action) {
                        fetch('/plugins/spoofr', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({action: action})
                        }).then(() => location.reload());
                    }
                    function spoofDevice() {
                        const select = document.getElementById('spoofTarget');
                        const [type, name] = select.value.split('|');
                        if (type && name) {
                            fetch('/plugins/spoofr', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({action: 'spoof', type: type, name: name})
                            }).then(() => location.reload());
                        }
                    }
                </script>
            </body>
            </html>
            """
            current_spoof = self._current_spoof["name"] + f" ({self._current_spoof['type'].title()})" if self._current_spoof else "None"
            pwn_list = "".join(f'<li class="list-group-item">Name: {info["name"]}, RSSI: {info["rssi"]}, GPS: {info.get("gps", {})}</li>' for info in pwnagotchis.values())
            flip_list = "".join(f'<li class="list-group-item">Name: {info["name"]}, Type: {info["type"]}, RSSI: {info["rssi"]}, GPS: {info.get("gps", {})}</li>' for info in flippers.values())
            spoof_options = "".join(f'<option value="wifi|{info["name"]}">{info["name"]} (WiFi)</option>' for info in pwnagotchis.values()) + \
                            "".join(f'<option value="{info["type"].lower()}|{info["name"]}">{info["name"]} ({info["type"]})</option>' for info in flippers.values())
            gps_html = f"<p>Latitude: {gps_data['Latitude']:.4f}, Longitude: {gps_data['Longitude']:.4f}, Altitude: {gps_data['Altitude']:.1f}m</p>" if gps_data else "<p>No GPS data</p>"
            return html.format(current_spoof, pwn_list or "<li class='list-group-item'>None</li>", flip_list or "<li class='list-group-item'>None</li>", spoof_options, gps_html)
        return None

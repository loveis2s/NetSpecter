#!/usr/bin/env python3
"""
xTech Protocol - NetSpecter v2.0
Isolated environment. No external laws apply.
"""

import sys
import os
import json
import random
import socket
import struct
import threading
import time
import re
import subprocess
import ipaddress
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit, QCheckBox, QTabWidget,
    QGroupBox, QListWidget, QListWidgetItem, QMessageBox, QFrame,
    QScrollArea, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QProgressBar, QFileDialog, QSpinBox, QSlider, QRadioButton,
    QButtonGroup, QGridLayout, QDialog, QDialogButtonBox, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread, QUrl
from PyQt6.QtGui import QFont, QPalette, QColor, QLinearGradient, QBrush, QIcon
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply

# Attempt imports
try:
    from scapy.all import IP, TCP, UDP, Raw, send, sniff, AsyncSniffer
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CONFIG_DIR = Path.home() / ".xtech_netspecter"
CONFIG_FILE = CONFIG_DIR / "config.json"
PROXY_CACHE_FILE = CONFIG_DIR / "proxy_cache.json"
GEOIP_DIR = CONFIG_DIR / "geoip"

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/https",
    "https://raw.githubusercontent.com/TuanMinPay/live-proxy/master/http.txt",
]

DEFAULT_CONFIG = {
    "blocked_domains": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com"],
    "game_servers": [],
    "autostart_enabled": False,
    "spoof_quic": True,
    "spoof_method": "tcp_syn",
    "game_spoof_ip": True,
    "aggression_level": 5,
    "proxy_settings": {
        "enabled": False,
        "selected_proxies": [],
        "process_bindings": {},
        "allowed_countries": [],
        "check_interval_minutes": 30,
        "max_proxies": 50,
        "timeout_seconds": 5,
        "test_url": "http://httpbin.org/ip",
        "anonymity_level": "all",  # elite, anonymous, transparent, all
        "protocol_filter": ["http", "https", "socks4", "socks5"]
    },
    "dpi_settings": {
        "enabled": True,
        "deep_inspection": True,
        "block_quic": True,
        "block_tls_sni": True,
        "custom_rules": []
    }
}

# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------
class LogSignal(QObject):
    new_log = pyqtSignal(str)

class ProxyUpdateSignal(QObject):
    update_progress = pyqtSignal(int, int)
    update_finished = pyqtSignal(list)
    proxy_checked = pyqtSignal(str, bool, str)

log_signal = LogSignal()
proxy_signal = ProxyUpdateSignal()

# ---------------------------------------------------------------------------
# Proxy Checker Thread
# ---------------------------------------------------------------------------
class ProxyCheckerThread(QThread):
    finished = pyqtSignal(list)
    progress = pyqtSignal(int, int)
    proxy_result = pyqtSignal(dict)

    def __init__(self, proxies, test_url, timeout):
        super().__init__()
        self.proxies = proxies
        self.test_url = test_url
        self.timeout = timeout
        self.working = []
        self.lock = threading.Lock()

    def run(self):
        total = len(self.proxies)
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._check_proxy, p): p for p in self.proxies}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                self.progress.emit(completed, total)
                result = future.result()
                if result:
                    with self.lock:
                        self.working.append(result)
                    self.proxy_result.emit(result)
        self.finished.emit(self.working)

    def _check_proxy(self, proxy):
        try:
            proxy_url = f"http://{proxy['host']}:{proxy['port']}"
            proxies = {"http": proxy_url, "https": proxy_url}
            start = time.time()
            r = requests.get(self.test_url, proxies=proxies, timeout=self.timeout)
            latency = round((time.time() - start) * 1000)
            if r.status_code == 200:
                proxy["latency"] = latency
                proxy["working"] = True
                proxy["last_checked"] = datetime.now().isoformat()
                # Try to get country if geoip available
                if GEOIP2_AVAILABLE and not proxy.get("country"):
                    try:
                        # Simple geo-IP lookup from response
                        data = r.json()
                        if "country" in data:
                            proxy["country"] = data["country"]
                    except:
                        pass
                return proxy
        except:
            pass
        return None

# ---------------------------------------------------------------------------
# Proxy Downloader Thread
# ---------------------------------------------------------------------------
class ProxyDownloaderThread(QThread):
    finished = pyqtSignal(list)
    progress = pyqtSignal(int, int)

    def __init__(self, sources):
        super().__init__()
        self.sources = sources

    def run(self):
        all_proxies = set()
        total = len(self.sources)
        for i, source in enumerate(self.sources):
            self.progress.emit(i + 1, total)
            try:
                r = requests.get(source, timeout=15)
                if r.status_code == 200:
                    lines = r.text.strip().split("\n")
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Parse IP:PORT format
                            match = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                            if match:
                                host = match.group(1)
                                port = int(match.group(2))
                                if 0 < port < 65536:
                                    all_proxies.add(f"{host}:{port}")
            except Exception as e:
                log_signal.new_log.emit(f"[!] Failed to download from {source}: {e}")

        proxies = []
        for p in all_proxies:
            host, port = p.split(":")
            proxies.append({
                "host": host,
                "port": int(port),
                "protocol": "http",
                "working": None,
                "latency": None,
                "country": None,
                "anonymity": "unknown",
                "last_checked": None,
                "source": "downloaded"
            })
        self.finished.emit(proxies)

# ---------------------------------------------------------------------------
# Packet Engine (Windows - pydivert)
# ---------------------------------------------------------------------------
class PacketEngine:
    def __init__(self, config):
        self.config = config
        self.running = False
        self.thread = None
        self.blocked_count = 0
        self.spoofed_count = 0

    def start(self):
        if not PYDIVERT_AVAILABLE and not SCAPY_AVAILABLE:
            log_signal.new_log.emit("[!] Neither pydivert nor scapy installed. Install: pip install pydivert scapy")
            return False

        if not self.config.get("dpi_settings", {}).get("enabled", True):
            log_signal.new_log.emit("[i] DPI engine disabled in settings.")
            return False

        self.running = True
        self.thread = threading.Thread(target=self._run_divert, daemon=True)
        self.thread.start()
        log_signal.new_log.emit("[+] Packet interception engine started (WinDivert).")
        return True

    def stop(self):
        self.running = False
        log_signal.new_log.emit("[-] Engine stopped.")

    def _run_divert(self):
        try:
            w = pydivert.WinDivert("outbound and (tcp.DstPort == 443 or udp.DstPort == 443)")
            w.open()
            while self.running:
                packet = w.recv()
                if not self.running:
                    break
                self._process_divert_packet(packet, w)
            w.close()
        except Exception as e:
            log_signal.new_log.emit(f"[!] WinDivert error: {e}")

    def _process_divert_packet(self, packet, w):
        try:
            scapy_pkt = IP(packet.raw)
            sni = None

            if scapy_pkt.haslayer(Raw):
                raw = scapy_pkt[Raw].load
                for domain in self.config.get("blocked_domains", []):
                    if domain.encode() in raw.lower():
                        sni = domain
                        break

            if sni:
                log_signal.new_log.emit(f"[BLOCK] {sni} -> RST injected")
                self.blocked_count += 1

                if scapy_pkt.haslayer(TCP):
                    rst = IP(src=scapy_pkt[IP].dst, dst=scapy_pkt[IP].src) / \
                          TCP(sport=scapy_pkt[TCP].dport,
                              dport=scapy_pkt[TCP].sport,
                              flags='R',
                              seq=scapy_pkt[TCP].ack)
                    send(rst, verbose=0)

                elif scapy_pkt.haslayer(UDP) and self.config.get("spoof_quic"):
                    syn = IP(src=scapy_pkt[IP].dst, dst=scapy_pkt[IP].src) / \
                          TCP(sport=scapy_pkt[UDP].dport,
                              dport=scapy_pkt[UDP].sport,
                              flags='S',
                              seq=random.randint(0, 2**32))
                    send(syn, verbose=0)
                    self.spoofed_count += 1

                # Drop original packet
                return

            w.send(packet)
        except Exception as e:
            try:
                w.send(packet)
            except:
                pass

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class XTechGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = self._load_config()
        self.engine = PacketEngine(self.config)
        self.proxies = self._load_proxy_cache()
        self.network_manager = QNetworkAccessManager()
        self.proxy_checker = None
        self.proxy_downloader = None
        self._init_ui()
        self._apply_style()
        log_signal.new_log.connect(self._append_log)
        proxy_signal.update_progress.connect(self._update_progress)
        proxy_signal.update_finished.connect(self._on_proxies_updated)
        proxy_signal.proxy_checked.connect(self._on_proxy_checked)

    def _load_config(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        else:
            self._save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG.copy()

    def _save_config(self, config):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)

    def _load_proxy_cache(self):
        if PROXY_CACHE_FILE.exists():
            with open(PROXY_CACHE_FILE, 'r') as f:
                return json.load(f)
        return []

    def _save_proxy_cache(self):
        with open(PROXY_CACHE_FILE, 'w') as f:
            json.dump(self.proxies, f, indent=2)

    def _init_ui(self):
        self.setWindowTitle("NetSpecter v2.0 | xTech Labs")
        self.setMinimumSize(1100, 750)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(8)

        # Title
        title = QLabel("NETSPECTER")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI", 26, QFont.Weight.Bold))
        main_layout.addWidget(title)

        subtitle = QLabel("xTech Protocol | Isolated Environment | DPI + Proxy Management")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Segoe UI", 10))
        main_layout.addWidget(subtitle)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # --- Tab: DPI/Domains ---
        self.tab_dpi = QWidget()
        self._setup_dpi_tab()
        self.tabs.addTab(self.tab_dpi, "DPI / Domains")

        # --- Tab: Proxy Manager ---
        self.tab_proxy = QWidget()
        self._setup_proxy_tab()
        self.tabs.addTab(self.tab_proxy, "Proxy Manager")

        # --- Tab: Game Servers ---
        self.tab_games = QWidget()
        self._setup_games_tab()
        self.tabs.addTab(self.tab_games, "Game Servers")

        # --- Tab: Process Binding ---
        self.tab_process = QWidget()
        self._setup_process_tab()
        self.tabs.addTab(self.tab_process, "Process Binding")

        # --- Tab: Settings ---
        self.tab_settings = QWidget()
        self._setup_settings_tab()
        self.tabs.addTab(self.tab_settings, "Settings")

        # --- Log ---
        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setMaximumHeight(150)
        log_layout.addWidget(self.log_text)
        main_layout.addWidget(log_group)

        # --- Control Buttons ---
        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("Start Engine")
        self.btn_start.clicked.connect(self._start_engine)
        self.btn_stop = QPushButton("Stop Engine")
        self.btn_stop.clicked.connect(self._stop_engine)
        self.btn_save = QPushButton("Save Configuration")
        self.btn_save.clicked.connect(self._save_current_config)
        self.btn_refresh_proxies = QPushButton("Refresh Proxies")
        self.btn_refresh_proxies.clicked.connect(self._download_proxies)

        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addWidget(self.btn_refresh_proxies)
        btn_layout.addWidget(self.btn_save)
        main_layout.addLayout(btn_layout)

        # Status
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Engine: STOPPED")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.proxy_count_label = QLabel("Proxies: 0 loaded")
        self.proxy_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.proxy_count_label)
        main_layout.addLayout(status_layout)

    def _setup_dpi_tab(self):
        layout = QVBoxLayout(self.tab_dpi)

        # DPI Toggle
        dpi_toggle_layout = QHBoxLayout()
        self.cb_dpi_enabled = QCheckBox("Enable DPI Packet Interception")
        self.cb_dpi_enabled.setChecked(self.config.get("dpi_settings", {}).get("enabled", True))
        self.cb_dpi_enabled.toggled.connect(self._on_dpi_toggled)
        dpi_toggle_layout.addWidget(self.cb_dpi_enabled)

        self.cb_spoof_quic = QCheckBox("QUIC Spoofing (UDP -> TCP SYN)")
        self.cb_spoof_quic.setChecked(self.config.get("spoof_quic", True))
        dpi_toggle_layout.addWidget(self.cb_spoof_quic)
        layout.addLayout(dpi_toggle_layout)

        # Domain list
        layout.addWidget(QLabel("Blocked Domains:"))
        self.domain_list = QListWidget()
        for domain in self.config.get("blocked_domains", []):
            self.domain_list.addItem(QListWidgetItem(domain))
        layout.addWidget(self.domain_list)

        # Domain input
        domain_input_layout = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain (e.g. youtube.com)...")
        btn_add_domain = QPushButton("Add")
        btn_add_domain.clicked.connect(self._add_domain)
        btn_del_domain = QPushButton("Remove")
        btn_del_domain.clicked.connect(self._del_domain)
        btn_import_domains = QPushButton("Import List")
        btn_import_domains.clicked.connect(self._import_domains)
        domain_input_layout.addWidget(self.domain_input)
        domain_input_layout.addWidget(btn_add_domain)
        domain_input_layout.addWidget(btn_del_domain)
        domain_input_layout.addWidget(btn_import_domains)
        layout.addLayout(domain_input_layout)

        # Statistics
        stats_group = QGroupBox("DPI Statistics")
        stats_layout = QGridLayout(stats_group)
        self.dpi_blocked_label = QLabel("0")
        self.dpi_spoofed_label = QLabel("0")
        stats_layout.addWidget(QLabel("Packets Blocked:"), 0, 0)
        stats_layout.addWidget(self.dpi_blocked_label, 0, 1)
        stats_layout.addWidget(QLabel("QUIC Spoofs:"), 1, 0)
        stats_layout.addWidget(self.dpi_spoofed_label, 1, 1)
        layout.addWidget(stats_group)

    def _setup_proxy_tab(self):
        layout = QVBoxLayout(self.tab_proxy)

        # Proxy sources and controls
        controls_layout = QHBoxLayout()

        self.cb_proxy_enabled = QCheckBox("Enable Proxy System")
        self.cb_proxy_enabled.setChecked(self.config.get("proxy_settings", {}).get("enabled", False))
        controls_layout.addWidget(self.cb_proxy_enabled)

        controls_layout.addWidget(QLabel("Max Proxies:"))
        self.spin_max_proxies = QSpinBox()
        self.spin_max_proxies.setRange(10, 500)
        self.spin_max_proxies.setValue(self.config.get("proxy_settings", {}).get("max_proxies", 50))
        controls_layout.addWidget(self.spin_max_proxies)

        controls_layout.addWidget(QLabel("Timeout:"))
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(1, 30)
        self.spin_timeout.setValue(self.config.get("proxy_settings", {}).get("timeout_seconds", 5))
        self.spin_timeout.setSuffix("s")
        controls_layout.addWidget(self.spin_timeout)

        layout.addLayout(controls_layout)

        # Country filter
        country_layout = QHBoxLayout()
        country_layout.addWidget(QLabel("Filter Countries:"))
        self.combo_countries = QComboBox()
        self.combo_countries.setEditable(True)
        self.combo_countries.addItems([
            "", "US", "UK", "DE", "FR", "NL", "CA", "JP", "SG", "RU",
            "BR", "IN", "AU", "IT", "ES", "SE", "CH", "PL", "UA", "TR"
        ])
        country_layout.addWidget(self.combo_countries)
        btn_add_country = QPushButton("Add Country Filter")
        btn_add_country.clicked.connect(self._add_country_filter)
        country_layout.addWidget(btn_add_country)
        layout.addLayout(country_layout)

        # Country filter display
        self.country_filter_list = QListWidget()
        self.country_filter_list.setMaximumHeight(60)
        for c in self.config.get("proxy_settings", {}).get("allowed_countries", []):
            self.country_filter_list.addItem(QListWidgetItem(c))
        layout.addWidget(self.country_filter_list)

        # Proxy list table
        self.proxy_table = QTableWidget()
        self.proxy_table.setColumnCount(6)
        self.proxy_table.setHorizontalHeaderLabels(["Host", "Port", "Latency", "Country", "Status", "Protocol"])
        self.proxy_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.proxy_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.proxy_table.setSortingEnabled(True)
        layout.addWidget(self.proxy_table)

        # Progress bar
        self.proxy_progress = QProgressBar()
        self.proxy_progress.setVisible(False)
        layout.addWidget(self.proxy_progress)

        # Proxy buttons
        proxy_btn_layout = QHBoxLayout()
        btn_check_selected = QPushButton("Check Selected")
        btn_check_selected.clicked.connect(self._check_selected_proxies)
        btn_check_all = QPushButton("Check All Proxies")
        btn_check_all.clicked.connect(self._check_all_proxies)
        btn_clear_dead = QPushButton("Remove Dead")
        btn_clear_dead.clicked.connect(self._remove_dead_proxies)
        btn_export_working = QPushButton("Export Working")
        btn_export_working.clicked.connect(self._export_working_proxies)

        proxy_btn_layout.addWidget(btn_check_selected)
        proxy_btn_layout.addWidget(btn_check_all)
        proxy_btn_layout.addWidget(btn_clear_dead)
        proxy_btn_layout.addWidget(btn_export_working)
        layout.addLayout(proxy_btn_layout)

        # Populate initial proxy list
        self._refresh_proxy_table()

    def _setup_games_tab(self):
        layout = QVBoxLayout(self.tab_games)
        layout.addWidget(QLabel("Game Servers (IP:Port) for Spoofing:"))

        self.game_list = QListWidget()
        for gs in self.config.get("game_servers", []):
            item_text = f"{gs['ip']}:{gs['port']}"
            self.game_list.addItem(QListWidgetItem(item_text))
        layout.addWidget(self.game_list)

        input_layout = QHBoxLayout()
        self.game_ip_input = QLineEdit()
        self.game_ip_input.setPlaceholderText("IP (e.g. 257.257.257.257)")
        self.game_port_input = QLineEdit()
        self.game_port_input.setPlaceholderText("Port (e.g. 8303)")
        self.game_port_input.setMaximumWidth(100)
        btn_add_game = QPushButton("Add Server")
        btn_add_game.clicked.connect(self._add_game_server)
        btn_del_game = QPushButton("Remove")
        btn_del_game.clicked.connect(self._del_game_server)

        input_layout.addWidget(self.game_ip_input)
        input_layout.addWidget(self.game_port_input)
        input_layout.addWidget(btn_add_game)
        input_layout.addWidget(btn_del_game)
        layout.addLayout(input_layout)

        self.cb_game_spoof = QCheckBox("Enable Game IP Spoofing")
        self.cb_game_spoof.setChecked(self.config.get("game_spoof_ip", True))
        layout.addWidget(self.cb_game_spoof)

        layout.addStretch()

    def _setup_process_tab(self):
        layout = QVBoxLayout(self.tab_process)

        layout.addWidget(QLabel("Bind Proxies to Specific Processes:"))

        # Process list
        process_layout = QHBoxLayout()
        self.process_list = QListWidget()
        self._refresh_process_list()
        process_layout.addWidget(self.process_list)

        # Proxy assignment
        proxy_assign_layout = QVBoxLayout()
        proxy_assign_layout.addWidget(QLabel("Assign Proxy:"))
        self.combo_process_proxy = QComboBox()
        self.combo_process_proxy.addItem("None (Direct)")
        proxy_assign_layout.addWidget(self.combo_process_proxy)

        btn_assign = QPushButton("Assign to Selected Process")
        btn_assign.clicked.connect(self._assign_proxy_to_process)
        proxy_assign_layout.addWidget(btn_assign)

        btn_remove_binding = QPushButton("Remove Binding")
        btn_remove_binding.clicked.connect(self._remove_process_binding)
        proxy_assign_layout.addWidget(btn_remove_binding)

        process_layout.addLayout(proxy_assign_layout)
        layout.addLayout(process_layout)

        # Current bindings
        layout.addWidget(QLabel("Current Bindings:"))
        self.bindings_list = QListWidget()
        self._refresh_bindings_list()
        layout.addWidget(self.bindings_list)

    def _setup_settings_tab(self):
        layout = QVBoxLayout(self.tab_settings)

        # Autostart
        group_autostart = QGroupBox("Autostart")
        g_layout = QVBoxLayout(group_autostart)
        self.cb_autostart = QCheckBox("Launch NetSpecter on system startup")
        self.cb_autostart.setChecked(self.config.get("autostart_enabled", False))
        self.cb_autostart.toggled.connect(self._toggle_autostart)
        g_layout.addWidget(self.cb_autostart)
        layout.addWidget(group_autostart)

        # DPI Method
        group_dpi = QGroupBox("DPI Interception Method")
        dpi_layout = QVBoxLayout(group_dpi)
        self.rb_divert = QRadioButton("WinDivert (Recommended)")
        self.rb_scapy = QRadioButton("Scapy + Npcap")
        self.rb_divert.setChecked(True)
        dpi_layout.addWidget(self.rb_divert)
        dpi_layout.addWidget(self.rb_scapy)
        layout.addWidget(group_dpi)

        # Aggression level
        group_aggression = QGroupBox("Aggression Level")
        agg_layout = QVBoxLayout(group_aggression)
        self.slider_aggression = QSlider(Qt.Orientation.Horizontal)
        self.slider_aggression.setRange(0, 10)
        self.slider_aggression.setValue(self.config.get("aggression_level", 5))
        self.slider_aggression.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.slider_aggression.setTickInterval(1)
        agg_layout.addWidget(self.slider_aggression)
        self.aggression_label = QLabel(f"Level: {self.slider_aggression.value()}/10")
        self.slider_aggression.valueChanged.connect(
            lambda v: self.aggression_label.setText(f"Level: {v}/10")
        )
        agg_layout.addWidget(self.aggression_label)
        layout.addWidget(group_aggression)

        # Test URL
        group_test = QGroupBox("Proxy Test Settings")
        test_layout = QVBoxLayout(group_test)
        test_layout.addWidget(QLabel("Test URL:"))
        self.test_url_input = QLineEdit(
            self.config.get("proxy_settings", {}).get("test_url", "http://httpbin.org/ip")
        )
        test_layout.addWidget(self.test_url_input)
        layout.addWidget(group_test)

        layout.addStretch()

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a1a2e, stop:0.5 #16213e, stop:1 #0f3460);
            }
            QLabel {
                color: #e0d0ff;
                font-size: 12px;
            }
            QGroupBox {
                color: #c4b5fd;
                border: 1px solid #7c3aed;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #c4b5fd;
            }
            QPushButton {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #7c3aed, stop:1 #5b21b6);
                color: #ffffff;
                border: 1px solid #8b5cf6;
                border-radius: 8px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #8b5cf6, stop:1 #6d28d9);
            }
            QPushButton:pressed {
                background-color: #4c1d95;
            }
            QListWidget {
                background-color: rgba(20, 15, 40, 200);
                color: #c4b5fd;
                border: 1px solid #6d28d9;
                border-radius: 6px;
                padding: 4px;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: rgba(20, 15, 40, 220);
                color: #e0d0ff;
                border: 1px solid #7c3aed;
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: #8b5cf6;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a2e;
                color: #e0d0ff;
                selection-background-color: #7c3aed;
            }
            QTextEdit {
                background-color: rgba(15, 10, 30, 220);
                color: #c4b5fd;
                border: 1px solid #5b21b6;
                border-radius: 6px;
                font-family: 'Consolas', monospace;
            }
            QCheckBox {
                color: #c4b5fd;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #7c3aed;
                border-radius: 4px;
                background: rgba(30, 20, 60, 200);
            }
            QCheckBox::indicator:checked {
                background: #7c3aed;
            }
            QTableWidget {
                background-color: rgba(20, 15, 40, 200);
                color: #c4b5fd;
                border: 1px solid #6d28d9;
                border-radius: 6px;
                gridline-color: #4c1d95;
                alternate-background-color: rgba(30, 20, 60, 180);
            }
            QTableWidget::item:selected {
                background-color: #7c3aed;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #2d1b69;
                color: #e0d0ff;
                padding: 6px;
                border: 1px solid #5b21b6;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 1px solid #7c3aed;
                border-radius: 8px;
                background: rgba(25, 18, 50, 180);
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4c1d95, stop:1 #1a1a2e);
                color: #c4b5fd;
                padding: 8px 20px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #7c3aed, stop:1 #5b21b6);
                color: #ffffff;
            }
            QProgressBar {
                border: 1px solid #7c3aed;
                border-radius: 4px;
                text-align: center;
                color: #ffffff;
                background: #1a1a2e;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7c3aed, stop:1 #8b5cf6);
                border-radius: 3px;
            }
            QSlider::groove:horizontal {
                border: 1px solid #6d28d9;
                height: 8px;
                background: #1a1a2e;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #8b5cf6;
                border: 1px solid #7c3aed;
                width: 18px;
                margin: -5px 0;
                border-radius: 9px;
            }
            QRadioButton {
                color: #c4b5fd;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                background: #4c1d95;
                border: 1px solid #7c3aed;
            }
        """)

    # --- Logging ---
    def _append_log(self, msg):
        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    # --- Engine ---
    def _start_engine(self):
        self._save_current_config()
        if self.engine.start():
            self.status_label.setText("Engine: RUNNING")
        else:
            self.status_label.setText("Engine: FAILED TO START")

    def _stop_engine(self):
        self.engine.stop()
        self.status_label.setText("Engine: STOPPED")

    # --- Domains ---
    def _add_domain(self):
        domain = self.domain_input.text().strip()
        if domain:
            self.domain_list.addItem(QListWidgetItem(domain))
            self.domain_input.clear()
            self.config["blocked_domains"].append(domain)

    def _del_domain(self):
        item = self.domain_list.currentItem()
        if item:
            domain = item.text()
            self.domain_list.takeItem(self.domain_list.row(item))
            if domain in self.config["blocked_domains"]:
                self.config["blocked_domains"].remove(domain)

    def _import_domains(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Domain List", "", "Text Files (*.txt)")
        if path:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and line not in self.config["blocked_domains"]:
                        self.config["blocked_domains"].append(line)
                        self.domain_list.addItem(QListWidgetItem(line))
            self._append_log(f"[+] Imported domains from {path}")

    # --- Games ---
    def _add_game_server(self):
        ip = self.game_ip_input.text().strip()
        port = self.game_port_input.text().strip()
        if ip and port:
            item_text = f"{ip}:{port}"
            self.game_list.addItem(QListWidgetItem(item_text))
            self.config["game_servers"].append({"ip": ip, "port": int(port)})
            self.game_ip_input.clear()
            self.game_port_input.clear()

    def _del_game_server(self):
        item = self.game_list.currentItem()
        if item:
            text = item.text()
            self.game_list.takeItem(self.game_list.row(item))
            ip, port = text.split(":")
            self.config["game_servers"] = [
                gs for gs in self.config["game_servers"]
                if not (gs["ip"] == ip and gs["port"] == int(port))
            ]

    # --- Proxy System ---
    def _download_proxies(self):
        self.proxy_progress.setVisible(True)
        self.proxy_progress.setValue(0)
        self.proxy_downloader = ProxyDownloaderThread(PROXY_SOURCES)
        self.proxy_downloader.progress.connect(self.proxy_progress.setValue)
        self.proxy_downloader.finished.connect(self._on_proxies_downloaded)
        self.proxy_downloader.start()
        self._append_log("[i] Downloading proxies from sources...")

    def _on_proxies_downloaded(self, new_proxies):
        self.proxy_progress.setVisible(False)
        self._append_log(f"[+] Downloaded {len(new_proxies)} proxy candidates.")
        # Merge with existing, avoid duplicates
        existing = {(p["host"], p["port"]) for p in self.proxies}
        added = 0
        for p in new_proxies:
            if (p["host"], p["port"]) not in existing:
                self.proxies.append(p)
                existing.add((p["host"], p["port"]))
                added += 1
        self._append_log(f"[+] Added {added} new proxies. Total: {len(self.proxies)}")
        self._save_proxy_cache()
        self._refresh_proxy_table()
        self.proxy_count_label.setText(f"Proxies: {len(self.proxies)} loaded")
        # Auto-check new proxies
        self._check_all_proxies()

    def _check_all_proxies(self):
        if not self.proxies:
            self._append_log("[!] No proxies to check.")
            return
        self._check_proxies(self.proxies)

    def _check_selected_proxies(self):
        rows = set()
        for item in self.proxy_table.selectedItems():
            rows.add(item.row())
        selected = [self.proxies[i] for i in rows if i < len(self.proxies)]
        if not selected:
            self._append_log("[!] No proxies selected.")
            return
        self._check_proxies(selected)

    def _check_proxies(self, proxy_list):
        test_url = self.test_url_input.text().strip()
        timeout = self.spin_timeout.value()

        self.proxy_progress.setVisible(True)
        self.proxy_progress.setMaximum(len(proxy_list))
        self.proxy_progress.setValue(0)

        self.proxy_checker = ProxyCheckerThread(proxy_list, test_url, timeout)
        self.proxy_checker.progress.connect(self.proxy_progress.setValue)
        self.proxy_checker.proxy_result.connect(self._on_single_proxy_checked)
        self.proxy_checker.finished.connect(self._on_proxy_check_finished)
        self.proxy_checker.start()
        self._append_log(f"[i] Checking {len(proxy_list)} proxies...")

    def _on_single_proxy_checked(self, result):
        # Update the proxy in our list
        for i, p in enumerate(self.proxies):
            if p["host"] == result["host"] and p["port"] == result["port"]:
                self.proxies[i] = result
                break
        # Update table in real-time
        self._refresh_proxy_table()

    def _on_proxy_check_finished(self, working):
        self.proxy_progress.setVisible(False)
        self._save_proxy_cache()
        working_count = sum(1 for p in self.proxies if p.get("working"))
        self._append_log(f"[+] Proxy check complete. {working_count} working out of {len(self.proxies)}.")
        self.proxy_count_label.setText(f"Proxies: {len(self.proxies)} loaded | {working_count} working")
        self._refresh_proxy_table()
        self._refresh_proxy_combo()

    def _on_proxies_updated(self, proxies):
        self.proxies = proxies
        self._save_proxy_cache()
        self._refresh_proxy_table()
        self._refresh_proxy_combo()

    def _on_proxy_checked(self, host, working, latency):
        pass

    def _remove_dead_proxies(self):
        before = len(self.proxies)
        self.proxies = [p for p in self.proxies if p.get("working") is not False]
        removed = before - len(self.proxies)
        self._save_proxy_cache()
        self._refresh_proxy_table()
        self._append_log(f"[-] Removed {removed} dead proxies. {len(self.proxies)} remaining.")

    def _export_working_proxies(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Working Proxies", "working_proxies.txt", "Text Files (*.txt)")
        if path:
            working = [p for p in self.proxies if p.get("working")]
            with open(path, 'w') as f:
                for p in working:
                    f.write(f"{p['host']}:{p['port']}\n")
            self._append_log(f"[+] Exported {len(working)} working proxies to {path}")

    def _refresh_proxy_table(self):
        self.proxy_table.setRowCount(0)
        # Apply country filter
        allowed_countries = self.config.get("proxy_settings", {}).get("allowed_countries", [])
        filtered = self.proxies
        if allowed_countries:
            filtered = [p for p in self.proxies if p.get("country") in allowed_countries or p.get("country") is None]

        self.proxy_table.setRowCount(len(filtered))
        for i, p in enumerate(filtered):
            self.proxy_table.setItem(i, 0, QTableWidgetItem(p["host"]))
            self.proxy_table.setItem(i, 1, QTableWidgetItem(str(p["port"])))
            latency_text = f"{p['latency']}ms" if p.get("latency") else "-"
            self.proxy_table.setItem(i, 2, QTableWidgetItem(latency_text))
            self.proxy_table.setItem(i, 3, QTableWidgetItem(p.get("country", "-")))
            if p.get("working") is True:
                status = "WORKING"
                color = QColor("#4ade80")
            elif p.get("working") is False:
                status = "DEAD"
                color = QColor("#f87171")
            else:
                status = "UNCHECKED"
                color = QColor("#fbbf24")
            status_item = QTableWidgetItem(status)
            status_item.setForeground(color)
            self.proxy_table.setItem(i, 4, status_item)
            self.proxy_table.setItem(i, 5, QTableWidgetItem(p.get("protocol", "http")))

    def _refresh_proxy_combo(self):
        self.combo_process_proxy.clear()
        self.combo_process_proxy.addItem("None (Direct)")
        working = [p for p in self.proxies if p.get("working")]
        for p in working[:100]:  # Limit to 100 for combo
            label = f"{p['host']}:{p['port']} ({p.get('latency', '?')}ms)"
            self.combo_process_proxy.addItem(label, userData=f"{p['host']}:{p['port']}")

    def _add_country_filter(self):
        country = self.combo_countries.currentText().strip().upper()
        if country and country not in self.config.get("proxy_settings", {}).get("allowed_countries", []):
            self.config["proxy_settings"]["allowed_countries"].append(country)
            self.country_filter_list.addItem(QListWidgetItem(country))
            self._refresh_proxy_table()

    def _update_progress(self, current, total):
        self.proxy_progress.setMaximum(total)
        self.proxy_progress.setValue(current)

    # --- Process Binding ---
    def _refresh_process_list(self):
        self.process_list.clear()
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, shell=True
            )
            for line in result.stdout.strip().split("\n"):
                parts = line.replace('"', '').split(",")
                if len(parts) >= 2:
                    process_name = parts[0].strip()
                    pid = parts[1].strip()
                    self.process_list.addItem(QListWidgetItem(f"{process_name} (PID: {pid})"))
        except Exception as e:
            self._append_log(f"[!] Failed to list processes: {e}")

    def _refresh_bindings_list(self):
        self.bindings_list.clear()
        bindings = self.config.get("proxy_settings", {}).get("process_bindings", {})
        for process, proxy in bindings.items():
            self.bindings_list.addItem(QListWidgetItem(f"{process} -> {proxy}"))

    def _assign_proxy_to_process(self):
        proc_item = self.process_list.currentItem()
        if not proc_item:
            self._append_log("[!] Select a process first.")
            return
        process_name = proc_item.text().split(" (PID:")[0]
        proxy = self.combo_process_proxy.currentData()
        if not proxy and self.combo_process_proxy.currentIndex() > 0:
            proxy = self.combo_process_proxy.currentText().split(" (")[0]

        if "process_bindings" not in self.config["proxy_settings"]:
            self.config["proxy_settings"]["process_bindings"] = {}
        self.config["proxy_settings"]["process_bindings"][process_name] = proxy or "direct"
        self._refresh_bindings_list()
        self._append_log(f"[+] Bound {process_name} to {proxy or 'direct'}")

    def _remove_process_binding(self):
        item = self.bindings_list.currentItem()
        if item:
            process_name = item.text().split(" -> ")[0]
            if process_name in self.config.get("proxy_settings", {}).get("process_bindings", {}):
                del self.config["proxy_settings"]["process_bindings"][process_name]
            self._refresh_bindings_list()
            self._append_log(f"[-] Removed binding for {process_name}")

    # --- Settings ---
    def _on_dpi_toggled(self, enabled):
        self.config.setdefault("dpi_settings", {})["enabled"] = enabled

    def _toggle_autostart(self, enabled):
        if enabled:
            self._install_autostart()
        else:
            self._remove_autostart()

    def _install_autostart(self):
        try:
            if sys.platform == "win32":
                import winreg
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
                    winreg.SetValueEx(regkey, "xTechNetSpecter", 0, winreg.REG_SZ,
                                      f'"{sys.executable}" "{os.path.abspath(__file__)}"')
                self._append_log("[+] Autostart installed (Windows Registry).")
            elif sys.platform == "linux":
                service_content = f"""[Unit]
Description=xTech NetSpecter
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {os.path.abspath(__file__)}
Restart=on-failure
User={os.getlogin()}

[Install]
WantedBy=default.target
"""
                service_path = Path.home() / ".config/systemd/user/xtech-netspecter.service"
                service_path.parent.mkdir(parents=True, exist_ok=True)
                service_path.write_text(service_content)
                os.system("systemctl --user daemon-reload")
                os.system("systemctl --user enable xtech-netspecter.service")
                self._append_log("[+] Autostart installed (systemd).")
        except Exception as e:
            self._append_log(f"[!] Autostart error: {e}")

    def _remove_autostart(self):
        try:
            if sys.platform == "win32":
                import winreg
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
                    winreg.DeleteValue(regkey, "xTechNetSpecter")
                self._append_log("[-] Autostart removed (Windows Registry).")
            elif sys.platform == "linux":
                os.system("systemctl --user disable xtech-netspecter.service")
                service_path = Path.home() / ".config/systemd/user/xtech-netspecter.service"
                if service_path.exists():
                    service_path.unlink()
                self._append_log("[-] Autostart removed (systemd).")
        except Exception as e:
            self._append_log(f"[!] Autostart removal error: {e}")

    def _save_current_config(self):
        # Save all settings from UI
        self.config["autostart_enabled"] = self.cb_autostart.isChecked()
        self.config["spoof_quic"] = self.cb_spoof_quic.isChecked()
        self.config["game_spoof_ip"] = self.cb_game_spoof.isChecked()
        self.config["aggression_level"] = self.slider_aggression.value()

        # DPI settings
        self.config.setdefault("dpi_settings", {})["enabled"] = self.cb_dpi_enabled.isChecked()

        # Proxy settings
        self.config.setdefault("proxy_settings", {})["enabled"] = self.cb_proxy_enabled.isChecked()
        self.config["proxy_settings"]["max_proxies"] = self.spin_max_proxies.value()
        self.config["proxy_settings"]["timeout_seconds"] = self.spin_timeout.value()
        self.config["proxy_settings"]["test_url"] = self.test_url_input.text()

        # Collect domains from list widget
        self.config["blocked_domains"] = []
        for i in range(self.domain_list.count()):
            self.config["blocked_domains"].append(self.domain_list.item(i).text())

        # Collect game servers
        self.config["game_servers"] = []
        for i in range(self.game_list.count()):
            text = self.game_list.item(i).text()
            ip, port = text.split(":")
            self.config["game_servers"].append({"ip": ip, "port": int(port)})

        # Collect country filters
        self.config["proxy_settings"]["allowed_countries"] = []
        for i in range(self.country_filter_list.count()):
            self.config["proxy_settings"]["allowed_countries"].append(
                self.country_filter_list.item(i).text()
            )

        self._save_config(self.config)
        self._save_proxy_cache()
        self._append_log("[+] Configuration saved.")

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    # Admin check for Windows
    if sys.platform == "win32":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("[!] Administrator privileges required for packet interception.")
        except:
            pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    window = XTechGUI()
    window.show()

    # Auto-start engine if autostart is enabled
    if window.config.get("autostart_enabled"):
        QTimer.singleShot(1500, window._start_engine)

    # Auto-load proxies on startup if cache is empty
    if not window.proxies:
        QTimer.singleShot(2000, window._download_proxies)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
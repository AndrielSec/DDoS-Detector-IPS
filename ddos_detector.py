import os
import re
import json
import time
import threading
import argparse
import logging
import subprocess
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Set

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError as exc:
    raise SystemExit(f"[XƏTA] Scapy tapılmadı. Quraşdırmaq üçün: pip install scapy\n{exc}")

class Color:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    @staticmethod
    def alert(msg: str) -> str:
        return f"{Color.BOLD}{Color.RED}{msg}{Color.RESET}"

    @staticmethod
    def info(msg: str) -> str:
        return f"{Color.CYAN}{msg}{Color.RESET}"

    @staticmethod
    def ok(msg: str) -> str:
        return f"{Color.GREEN}{msg}{Color.RESET}"

    @staticmethod
    def warn(msg: str) -> str:
        return f"{Color.YELLOW}{msg}{Color.RESET}"

@dataclass
class DetectorConfig:
    interface       : str   = "eth0"
    threshold       : int   = 50
    window_seconds  : float = 1.0
    ban_duration    : float = 60.0
    log_file        : str   = "ddos_detector.log"
    stats_file      : str   = "banned_ips.json"
    dry_run         : bool  = False
    verbose         : bool  = False

class IptablesFirewall:
    _IPTABLES = "/usr/sbin/iptables"
    _IPV4_RE  = re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$")

    def __init__(self, dry_run: bool = False, logger: Optional[logging.Logger] = None):
        self._dry_run = dry_run
        self._log     = logger or logging.getLogger(__name__)
        self._applied: Set[str] = set()
        self._lock = threading.Lock()

    @classmethod
    def _validate_ip(cls, ip: str) -> bool:
        return bool(cls._IPV4_RE.match(ip))

    def _run(self, args: list[str]) -> bool:
        if self._dry_run:
            self._log.info(f"[DRY-RUN] iptables {' '.join(args[1:])}")
            return True
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                self._log.error(f"iptables xətası: {result.stderr.strip()} (əmr: {' '.join(args)})")
                return False
            return True
        except FileNotFoundError:
            self._log.error(f"iptables tapılmadı: {self._IPTABLES}. Kali/Debian: apt install iptables")
            return False
        except subprocess.TimeoutExpired:
            self._log.error("iptables əmri 5 saniyə ərzində cavab vermədi.")
            return False

    def block(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            self._log.warning(f"Etibarsız IP formatı bloklanmadı: {ip!r}")
            return False
        with self._lock:
            if ip in self._applied:
                return True
            ok = self._run([self._IPTABLES, "-A", "INPUT", "-s", ip, "-j", "DROP"])
            if ok:
                self._applied.add(ip)
                self._log.info(f"iptables: {ip} bloklandı (DROP əlavə edildi)")
            return ok

    def unblock(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            return False
        with self._lock:
            if ip not in self._applied:
                return True
            ok = self._run([self._IPTABLES, "-D", "INPUT", "-s", ip, "-j", "DROP"])
            if ok:
                self._applied.discard(ip)
                self._log.info(f"iptables: {ip} açıldı (DROP silindi)")
            return ok

    def flush_all(self) -> None:
        with self._lock:
            snapshot = list(self._applied)
        self._log.info(f"Təmizlik: {len(snapshot)} iptables qaydası silinir...")
        for ip in snapshot:
            self._run([self._IPTABLES, "-D", "INPUT", "-s", ip, "-j", "DROP"])
            with self._lock:
                self._applied.discard(ip)

    @property
    def active_rules(self) -> Set[str]:
        with self._lock:
            return set(self._applied)

@dataclass
class BanRecord:
    ip           : str
    first_seen   : str
    last_banned  : str
    ban_count    : int  = 1
    total_packets: int  = 0
    protocols    : list = field(default_factory=list)

class BanStatsRecorder:
    def __init__(self, filepath: str, logger: Optional[logging.Logger] = None):
        self._path   = Path(filepath)
        self._log    = logger or logging.getLogger(__name__)
        self._lock   = threading.Lock()
        self._data: Dict = self._load()

    def _load(self) -> dict:
        if self._path.exists():
            try:
                with self._path.open("r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                self._log.warning(f"JSON faylı oxunmadı, sıfırlanır: {exc}")
        return {"meta": {"last_updated": "", "total_bans": 0}, "records": {}}

    def _save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        try:
            self._data["meta"]["last_updated"] = _utcnow()
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
            tmp.replace(self._path)
        except OSError as exc:
            self._log.error(f"JSON faylına yazıla bilmədi: {exc}")
            tmp.unlink(missing_ok=True)

    def record_ban(self, ip: str, packet_count: int, protocol: str) -> None:
        now = _utcnow()
        with self._lock:
            records = self._data["records"]
            if ip in records:
                rec = records[ip]
                rec["ban_count"]    += 1
                rec["last_banned"]   = now
                rec["total_packets"] += packet_count
                if protocol not in rec["protocols"]:
                    rec["protocols"].append(protocol)
            else:
                records[ip] = {
                    "ip"           : ip,
                    "first_seen"   : now,
                    "last_banned"  : now,
                    "ban_count"    : 1,
                    "total_packets": packet_count,
                    "protocols"    : [protocol]
                }
            self._data["meta"]["total_bans"] += 1
            self._save()
        self._log.info(f"JSON statistika yeniləndi: {ip} | ban#{records[ip]['ban_count']} | {protocol}")

    def get_summary(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._data))

    def total_unique_ips(self) -> int:
        with self._lock:
            return len(self._data["records"])

class IPTracker:
    def __init__(self, window_seconds: float):
        self._timestamps: defaultdict[str, deque] = defaultdict(deque)
        self._window = window_seconds
        self._lock   = threading.Lock()

    def record(self, ip: str) -> int:
        now    = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            q = self._timestamps[ip]
            q.append(now)
            while q and q[0] < cutoff:
                q.popleft()
            return len(q)

    def clear(self, ip: str) -> None:
        with self._lock:
            self._timestamps.pop(ip, None)

class BanManager:
    def __init__(self, ban_duration: float, firewall: IptablesFirewall, stats: BanStatsRecorder, logger: Optional[logging.Logger] = None):
        self._duration = ban_duration
        self._firewall = firewall
        self._stats    = stats
        self._log      = logger or logging.getLogger(__name__)
        self._banned: Dict[str, tuple] = {}
        self._lock = threading.Lock()
        if ban_duration > 0:
            threading.Thread(target=self._auto_unban_loop, daemon=True, name="AutoUnbanThread").start()

    def ban(self, ip: str, packet_count: int = 0, protocol: str = "UNKNOWN") -> bool:
        with self._lock:
            if ip in self._banned:
                return False
            self._banned[ip] = (time.monotonic(), packet_count, protocol)
        fw_ok = self._firewall.block(ip)
        self._stats.record_ban(ip, packet_count, protocol)
        return fw_ok

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._banned

    def unban(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._banned:
                return False
            del self._banned[ip]
        ok = self._firewall.unblock(ip)
        self._log.info(f"Auto-unban: {ip} açıldı")
        return ok

    @property
    def banned_ips(self) -> Set[str]:
        with self._lock:
            return set(self._banned.keys())

    def _auto_unban_loop(self) -> None:
        while True:
            time.sleep(5)
            now     = time.monotonic()
            expired = []
            with self._lock:
                for ip, (ban_time, _, _) in list(self._banned.items()):
                    if (now - ban_time) >= self._duration:
                        expired.append(ip)
            for ip in expired:
                self.unban(ip)

class ProtocolHelper:
    @staticmethod
    def detect(pkt) -> str:
        if pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            if flags == 0x02:
                return "TCP/SYN"
            return f"TCP/0x{flags:02x}"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        return "OTHER"

class DDoSDetector:
    def __init__(self, config: DetectorConfig):
        self.config   = config
        self._logger  = self._setup_logger()
        self._running = False
        self.firewall = IptablesFirewall(dry_run=config.dry_run, logger=self._logger)
        self.stats_recorder = BanStatsRecorder(filepath=config.stats_file, logger=self._logger)
        self.tracker  = IPTracker(config.window_seconds)
        self.ban_mgr  = BanManager(ban_duration=config.ban_duration, firewall=self.firewall, stats=self.stats_recorder, logger=self._logger)
        self._total_pkts    = 0
        self._blocked_pkts  = 0
        self._attack_count  = 0

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("DDoSDetector")
        logger.setLevel(logging.DEBUG if self.config.verbose else logging.INFO)
        fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        fh = logging.FileHandler(self.config.log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        logger.addHandler(ch)
        return logger

    def _process_packet(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        self._total_pkts += 1
        if self.ban_mgr.is_banned(src_ip):
            self._blocked_pkts += 1
            if self.config.verbose:
                self._logger.debug(f"BLOCKED  {src_ip} | {ProtocolHelper.detect(pkt)}")
            return
        count = self.tracker.record(src_ip)
        proto = ProtocolHelper.detect(pkt)
        if self.config.verbose:
            self._logger.debug(f"PACKET   {src_ip} | {proto} | {count}pkt/s")
        if count > self.config.threshold:
            self._trigger_ban(src_ip, count, proto)

    def _trigger_ban(self, src_ip: str, count: int, proto: str) -> None:
        if self.ban_mgr.is_banned(src_ip):
            return
        banned = self.ban_mgr.ban(ip=src_ip, packet_count=count, protocol=proto)
        if not banned:
            return
        self.tracker.clear(src_ip)
        self._attack_count += 1
        sep    = Color.alert("═" * 62)
        mode   = "[DRY-RUN]" if self.config.dry_run else "[BLOCKED]"
        print(f"\n{sep}")
        print(Color.alert(f"  ⚠  [ALERT] DDoS Attack Detected!  {mode}"))
        print(Color.alert(f"  IP         : {src_ip}"))
        print(Color.warn( f"  Protocol  : {proto}"))
        print(Color.warn( f"  Rate      : {count} pkt/s  (limit: {self.config.threshold})"))
        print(Color.ok(   f"  iptables  : DROP qayda əlavə edildi"))
        print(Color.ok(   f"  Ban müddəti: {self.config.ban_duration}s  →  auto-unban"))
        print(Color.info( f"  JSON log  : {self.config.stats_file}"))
        print(f"{sep}\n")
        self._logger.warning(f"ATTACK src={src_ip} proto={proto} rate={count}pkt/s threshold={self.config.threshold} iptables={'DRY-RUN' if self.config.dry_run else 'APPLIED'}")

    def _stats_loop(self) -> None:
        while self._running:
            time.sleep(10)
            n_banned  = len(self.ban_mgr.banned_ips)
            n_unique  = self.stats_recorder.total_unique_ips()
            print(Color.info(f"[STATS] Cəmi: {self._total_pkts} pkt | Bloklandı: {self._blocked_pkts} pkt | Hücumlar: {self._attack_count} | Aktiv ban: {n_banned} IP | Tarixi unikal: {n_unique} IP"))

    def start(self) -> None:
        if os.geteuid() != 0 and not self.config.dry_run:
            raise SystemExit(Color.alert("[XƏTA] Bu skript root səlahiyyəti tələb edir.\n       sudo python3 ddos_detector.py\n       Yalnız test etmək üçün --dry-run əlavə edin."))
        self._running = True
        threading.Thread(target=self._stats_loop, daemon=True, name="StatsThread").start()
        print(Color.ok(f"\n{'─'*62}\n  DDoS Detektor — Aktiv\n  Interface  : {self.config.interface}\n  Threshold  : {self.config.threshold} pkt/s\n  Window     : {self.config.window_seconds}s\n  Ban müddəti: {self.config.ban_duration}s\n  Dry-run    : {self.config.dry_run}\n  Log        : {self.config.log_file}\n  JSON stats : {self.config.stats_file}\n  [Ctrl+C ilə dayandırın]\n{'─'*62}\n"))
        self._logger.info(f"Başladı | iface={self.config.interface} threshold={self.config.threshold} dry_run={self.config.dry_run}")
        try:
            sniff(iface=self.config.interface, filter="ip", prn=self._process_packet, store=False, stop_filter=lambda _: not self._running)
        except PermissionError:
            raise SystemExit(Color.alert("[XƏTA] Scapy paket tutmaq üçün root tələb edir."))
        except OSError as exc:
            raise SystemExit(Color.alert(f"[XƏTA] İnterfeys açılmadı ({self.config.interface}): {exc}"))
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self._running = False
        print(Color.warn("\n[STOP] Bağlanılır..."))
        self.firewall.flush_all()
        summary = self.stats_recorder.get_summary()
        print(Color.warn(f"\n{'─'*62}\n  Son statistika\n  Cəmi paket      : {self._total_pkts}\n  Bloklanmış pkt  : {self._blocked_pkts}\n  Hücum hadisəsi  : {self._attack_count}\n  Unikal ban IP   : {summary['meta']['total_bans']}\n  JSON faylı      : {self.config.stats_file}\n{'─'*62}\n"))
        self._logger.info(f"Dayandırıldı | total_pkts={self._total_pkts} attacks={self._attack_count}")

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_args() -> DetectorConfig:
    p = argparse.ArgumentParser(description="DDoS Tespiti — iptables + JSON statistika", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--iface",     default="eth0",               help="Şəbəkə interfeysi")
    p.add_argument("--threshold", type=int,   default=50,       help="pkt/s həddi")
    p.add_argument("--window",    type=float, default=1.0,      help="Sürüşən pəncərə (s)")
    p.add_argument("--ban-dur",   type=float, default=60.0,     help="Ban müddəti saniyə (0=daimi)")
    p.add_argument("--log",       default="ddos_detector.log",  help="Log faylı")
    p.add_argument("--stats",     default="banned_ips.json",    help="JSON statistika faylı")
    p.add_argument("--dry-run",   action="store_true",          help="iptables çağırmadan test et")
    p.add_argument("--verbose",   action="store_true",          help="Debug çıxışı")
    a = p.parse_args()
    return DetectorConfig(interface=a.iface, threshold=a.threshold, window_seconds=a.window, ban_duration=a.ban_dur, log_file=a.log, stats_file=a.stats, dry_run=a.dry_run, verbose=a.verbose)

if __name__ == "__main__":
    cfg      = parse_args()
    detector = DDoSDetector(cfg)
    detector.start()

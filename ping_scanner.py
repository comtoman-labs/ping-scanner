"""간단한 IP 핑 스캐너 (PySide6)

사용 예 (IP 범위 입력):
    192.168.0.1-254
    192.168.0.1-192.168.1.50
    192.168.0.0/24
    192.168.0.1, 192.168.0.10-20, 10.0.0.1
"""
import csv
import ctypes
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import (
    QObject, QSortFilterProxyModel, Qt, QThread, Signal,
)
from PySide6.QtGui import (
    QAction, QColor, QIcon, QPainter, QPalette, QPixmap, QStandardItem, QStandardItemModel,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
    QProgressBar, QPushButton, QSpinBox, QStatusBar, QTableView, QToolBar,
    QVBoxLayout, QWidget,
)

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

# EXE(PyInstaller)로 실행 시 리소스는 임시 폴더(_MEIPASS)에 풀림
BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
ICON_PATH = os.path.join(BASE_DIR, "icon.ico")

COLUMNS = ["상태", "이름", "IP", "응답(ms)", "TTL", "MAC 주소", "의견"]
COL_STATUS, COL_NAME, COL_IP, COL_TIME, COL_TTL, COL_MAC, COL_NOTE = range(len(COLUMNS))

SORT_ROLE = Qt.UserRole + 1
ALIVE_ROLE = Qt.UserRole + 2


# ---------------------------------------------------------------- 유틸리티
def parse_targets(text: str) -> list[str]:
    """IP 범위 문자열을 IP 목록으로 변환."""
    ips: list[str] = []
    for part in re.split(r"[,\s;]+", text.strip()):
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            ips.extend(str(h) for h in hosts)
        elif "-" in part:
            start_s, end_s = part.split("-", 1)
            start = ipaddress.IPv4Address(start_s)
            if "." in end_s:
                end = ipaddress.IPv4Address(end_s)
            else:  # 172.16.10.1-254 형식
                end = ipaddress.IPv4Address(".".join(start_s.split(".")[:3] + [end_s]))
            if int(end) < int(start):
                raise ValueError(f"범위가 잘못되었습니다: {part}")
            ips.extend(str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1))
        else:
            ips.append(str(ipaddress.IPv4Address(part)))
    # 중복 제거 (순서 유지)
    return list(dict.fromkeys(ips))


def default_range() -> str:
    """현재 PC의 IP 기준 /24 대역."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        return ".".join(ip.split(".")[:3]) + ".1-254"
    except OSError:
        return "192.168.0.1-254"


def ping(ip: str, timeout_ms: int) -> tuple[bool, int | None, int | None]:
    """ping 1회. (응답여부, 응답시간ms, TTL)"""
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout_ms / 1000 + 3,
            creationflags=CREATE_NO_WINDOW,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False, None, None
    out = proc.stdout.decode("mbcs" if sys.platform == "win32" else "utf-8", errors="ignore")
    ttl_m = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
    if not ttl_m:  # "대상 호스트에 연결할 수 없습니다" 같은 경우 제외
        return False, None, None
    time_m = re.search(r"[=<]\s*(\d+(?:\.\d+)?)\s*ms", out)
    ms = round(float(time_m.group(1))) if time_m else None
    return True, ms, int(ttl_m.group(1))


def get_mac(ip: str) -> str:
    """같은 서브넷 장비의 MAC 주소 (Windows SendARP). 실패 시 빈 문자열."""
    if sys.platform != "win32":
        return ""
    try:
        dest = struct.unpack("<I", socket.inet_aton(ip))[0]
        buf = (ctypes.c_ubyte * 8)()
        size = ctypes.c_ulong(6)
        if ctypes.windll.iphlpapi.SendARP(dest, 0, buf, ctypes.byref(size)) != 0:
            return ""
        return ":".join(f"{b:02X}" for b in buf[: size.value])
    except Exception:
        return ""


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def make_dot_icon(color: str) -> QIcon:
    pm = QPixmap(14, 14)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(QColor(color).darker(140))
    p.drawEllipse(1, 1, 12, 12)
    p.end()
    return QIcon(pm)


def light_palette() -> QPalette:
    # Windows가 다크 모드여도 항상 흰색 톤이 되도록 모든 색을 직접 지정
    pal = QPalette()
    colors = {
        QPalette.Window: "#f0f0f0",
        QPalette.WindowText: "#000000",
        QPalette.Base: "#ffffff",
        QPalette.AlternateBase: "#f7f7f7",
        QPalette.ToolTipBase: "#ffffdc",
        QPalette.ToolTipText: "#000000",
        QPalette.PlaceholderText: "#8a8a8a",
        QPalette.Text: "#000000",
        QPalette.Button: "#f5f5f5",
        QPalette.ButtonText: "#000000",
        QPalette.BrightText: "#ff0000",
        QPalette.Link: "#0066cc",
        QPalette.Highlight: "#cce8ff",
        QPalette.HighlightedText: "#000000",
        QPalette.Light: "#ffffff",
        QPalette.Midlight: "#e3e3e3",
        QPalette.Mid: "#a0a0a0",
        QPalette.Dark: "#a0a0a0",
        QPalette.Shadow: "#696969",
    }
    for role, c in colors.items():
        pal.setColor(role, QColor(c))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        pal.setColor(QPalette.Disabled, role, QColor("#a0a0a0"))
    return pal


def dark_palette() -> QPalette:
    pal = QPalette()
    colors = {
        QPalette.Window: "#2b2b2b",
        QPalette.WindowText: "#e6e6e6",
        QPalette.Base: "#1e1e1e",
        QPalette.AlternateBase: "#262626",
        QPalette.ToolTipBase: "#3c3c3c",
        QPalette.ToolTipText: "#e6e6e6",
        QPalette.PlaceholderText: "#8a8a8a",
        QPalette.Text: "#e6e6e6",
        QPalette.Button: "#353535",
        QPalette.ButtonText: "#e6e6e6",
        QPalette.BrightText: "#ff5555",
        QPalette.Link: "#4ea1f3",
        QPalette.Highlight: "#264f78",
        QPalette.HighlightedText: "#ffffff",
        QPalette.Light: "#4a4a4a",
        QPalette.Midlight: "#3f3f3f",
        QPalette.Mid: "#303030",
        QPalette.Dark: "#1a1a1a",
        QPalette.Shadow: "#000000",
    }
    for role, c in colors.items():
        pal.setColor(role, QColor(c))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        pal.setColor(QPalette.Disabled, role, QColor("#6e6e6e"))
    return pal


# ---------------------------------------------------------------- 스캔 스레드
class ScanWorker(QThread):
    # ip, 상태(0=꺼짐,1=켜짐,2=ARP만 응답), 이름, 응답ms, TTL, MAC
    result = Signal(str, int, str, object, object, str)

    def __init__(self, ips, timeout_ms, threads, use_arp, resolve_name):
        super().__init__()
        self.ips = ips
        self.timeout_ms = timeout_ms
        self.threads = threads
        self.use_arp = use_arp
        self.resolve_name = resolve_name
        self._stop = threading.Event()
        self._run = threading.Event()
        self._run.set()

    def stop(self):
        self._stop.set()
        self._run.set()  # 일시정지 중이면 깨워서 종료

    def set_paused(self, paused: bool):
        self._run.clear() if paused else self._run.set()

    def _scan_one(self, ip):
        self._run.wait()
        if self._stop.is_set():
            return
        alive, ms, ttl = ping(ip, self.timeout_ms)
        mac = get_mac(ip) if self.use_arp and not self._stop.is_set() else ""
        state = 1 if alive else (2 if mac else 0)
        name = get_hostname(ip) if state and self.resolve_name else ""
        if not self._stop.is_set():
            self.result.emit(ip, state, name, ms, ttl, mac)

    def run(self):
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            for ip in self.ips:
                pool.submit(self._scan_one, ip)
        # with 블록 종료 시 모든 작업 완료 대기 (정지 시 남은 작업은 즉시 반환)


class ResultSignal(QObject):
    """'다시 핑' 결과를 메인 스레드로 전달하기 위한 시그널 홀더."""
    result = Signal(str, int, str, object, object, str)


# ---------------------------------------------------------------- 필터 모델
class FilterProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.only_alive = True
        self.text = ""
        self.setSortRole(SORT_ROLE)

    def set_only_alive(self, v: bool):
        self.only_alive = v
        self.invalidateFilter()

    def set_text(self, t: str):
        self.text = t.strip().lower()
        self.invalidateFilter()

    def lessThan(self, left, right):
        a, b = left.data(SORT_ROLE), right.data(SORT_ROLE)
        if a is None or b is None:  # 의견 등 편집 가능한 열은 표시 텍스트로 정렬
            return str(left.data() or "").lower() < str(right.data() or "").lower()
        return a < b

    def filterAcceptsRow(self, row, parent):
        m = self.sourceModel()
        if self.only_alive and not m.index(row, COL_STATUS, parent).data(ALIVE_ROLE):
            return False
        if self.text:
            return any(
                self.text in str(m.index(row, c, parent).data() or "").lower()
                for c in range(m.columnCount())
            )
        return True


# ---------------------------------------------------------------- 메인 윈도우
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ping Scanner")
        self.resize(1100, 720)

        self.icons = {
            0: make_dot_icon("#9e9e9e"),
            1: make_dot_icon("#2e9d3a"),
            2: make_dot_icon("#f0a020"),
        }
        self.worker: ScanWorker | None = None
        self.rows: dict[str, int] = {}
        self.total = self.done = self.on = self.off = 0
        self._notes: dict[str, str] = {}
        self._reping_signal = ResultSignal()
        self._reping_signal.result.connect(self._set_row)

        self._build_ui()

    # ---------- UI
    def _build_ui(self):
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        self.btn_start = QPushButton("▶ 스캔")
        self.btn_start.setMinimumSize(90, 34)
        self.btn_start.clicked.connect(self.toggle_scan)
        tb.addWidget(self.btn_start)

        self.btn_pause = QPushButton("❚❚ 일시정지")
        self.btn_pause.setCheckable(True)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setMinimumHeight(34)
        self.btn_pause.toggled.connect(self.toggle_pause)
        tb.addWidget(self.btn_pause)
        tb.addSeparator()

        tb.addWidget(QLabel(" 타임아웃(ms) "))
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(100, 10000)
        self.spin_timeout.setSingleStep(100)
        self.spin_timeout.setValue(1000)
        tb.addWidget(self.spin_timeout)

        tb.addWidget(QLabel("  스레드 "))
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, 256)
        self.spin_threads.setValue(64)
        tb.addWidget(self.spin_threads)
        tb.addSeparator()

        self.chk_arp = QCheckBox("MAC 조회")
        self.chk_arp.setChecked(True)
        self.chk_arp.setToolTip("같은 서브넷이면 ARP로 MAC 주소 조회 (핑 차단 장비도 검출)")
        tb.addWidget(self.chk_arp)
        self.chk_name = QCheckBox("이름 조회")
        self.chk_name.setChecked(True)
        tb.addWidget(self.chk_name)
        self.chk_alive = QCheckBox("켜진 장비만 보기")
        self.chk_alive.setChecked(True)
        self.chk_alive.toggled.connect(lambda v: self.proxy.set_only_alive(v))
        tb.addWidget(self.chk_alive)
        tb.addSeparator()

        act_csv = QAction("CSV 저장", self)
        act_csv.triggered.connect(self.export_csv)
        tb.addAction(act_csv)

        # 범위 / 검색
        self.edit_range = QLineEdit(default_range())
        self.edit_range.setPlaceholderText("예: 172.16.10.1-254, 10.0.0.0/24")
        self.edit_range.returnPressed.connect(self.toggle_scan)
        self.edit_search = QLineEdit()
        self.edit_search.setPlaceholderText("검색")
        self.edit_search.setClearButtonEnabled(True)
        self.edit_search.setFixedWidth(220)
        self.edit_search.textChanged.connect(lambda t: self.proxy.set_text(t))
        top = QHBoxLayout()
        top.addWidget(self.edit_range, 1)
        top.addWidget(self.edit_search)

        self.btn_theme = QPushButton()
        self.btn_theme.setCheckable(True)
        self.btn_theme.setToolTip("라이트 / 다크 모드 전환")
        self.btn_theme.toggled.connect(self.apply_theme)
        top.addWidget(self.btn_theme)

        # 결과 테이블
        self.model = QStandardItemModel(0, len(COLUMNS))
        self.model.setHorizontalHeaderLabels(COLUMNS)
        self.proxy = FilterProxy()
        self.proxy.setSourceModel(self.model)

        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.sortByColumn(COL_IP, Qt.AscendingOrder)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.view.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed)
        self.view.verticalHeader().hide()
        self.view.verticalHeader().setDefaultSectionSize(22)
        self.view.setShowGrid(False)
        self.view.setAlternatingRowColors(True)
        hh = self.view.horizontalHeader()
        hh.setHighlightSections(False)
        for col, w in zip(range(len(COLUMNS)), [50, 200, 130, 80, 50, 150, 200]):
            self.view.setColumnWidth(col, w)
        hh.setSectionResizeMode(COL_NOTE, QHeaderView.Stretch)
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self.show_menu)

        central = QWidget()
        lay = QVBoxLayout(central)
        lay.setContentsMargins(6, 6, 6, 0)
        lay.addLayout(top)
        lay.addWidget(self.view)
        self.setCentralWidget(central)

        # 상태 표시줄
        sb = QStatusBar()
        self.lbl_status = QLabel("준비")
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(16)
        sb.addWidget(self.lbl_status)
        sb.addWidget(self.progress, 1)
        self.setStatusBar(sb)

    # ---------- 테마
    def apply_theme(self, dark: bool):
        app = QApplication.instance()
        hints = app.styleHints()
        if hasattr(hints, "setColorScheme"):  # Qt 6.8+: 제목 표시줄 색도 함께 변경
            hints.setColorScheme(Qt.ColorScheme.Dark if dark else Qt.ColorScheme.Light)
        app.setPalette(dark_palette() if dark else light_palette())
        # 현재 모드를 표시
        self.btn_theme.setText("🌙 Dark" if dark else "☀ Light")

    # ---------- 스캔 제어
    def toggle_scan(self):
        if self.worker and self.worker.isRunning():
            self.btn_start.setEnabled(False)
            self.btn_start.setText("정지 중...")
            self.worker.stop()
            return
        try:
            ips = parse_targets(self.edit_range.text())
        except ValueError as e:
            QMessageBox.warning(self, "입력 오류", f"IP 범위를 확인하세요.\n{e}")
            return
        if not ips:
            return
        if len(ips) > 65536:
            QMessageBox.warning(self, "입력 오류", "한 번에 65536개 이하로 스캔하세요.")
            return

        notes = self._collect_notes()
        self.model.removeRows(0, self.model.rowCount())
        self.rows.clear()
        self._notes = notes
        self.total, self.done, self.on, self.off = len(ips), 0, 0, 0
        self.progress.setRange(0, self.total)
        self.progress.setValue(0)
        self.view.setSortingEnabled(False)  # 스캔 중 정렬로 인한 행 이동 방지

        self.worker = ScanWorker(
            ips, self.spin_timeout.value(), self.spin_threads.value(),
            self.chk_arp.isChecked(), self.chk_name.isChecked(),
        )
        self.worker.result.connect(self.on_result)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

        self.btn_start.setText("■ 정지")
        self.btn_pause.setEnabled(True)
        self.edit_range.setEnabled(False)
        self._update_status()

    def toggle_pause(self, paused: bool):
        if self.worker:
            self.worker.set_paused(paused)
        self.btn_pause.setText("▶ 계속" if paused else "❚❚ 일시정지")
        self._update_status()

    def on_finished(self):
        self.btn_start.setEnabled(True)
        self.btn_start.setText("▶ 스캔")
        self.btn_pause.blockSignals(True)
        self.btn_pause.setChecked(False)
        self.btn_pause.setText("❚❚ 일시정지")
        self.btn_pause.blockSignals(False)
        self.btn_pause.setEnabled(False)
        self.edit_range.setEnabled(True)
        self.view.setSortingEnabled(True)
        self._update_status(finished=True)

    def on_result(self, ip, state, name, ms, ttl, mac):
        self.done += 1
        if state:
            self.on += 1
        else:
            self.off += 1
        self._set_row(ip, state, name, ms, ttl, mac)
        self.progress.setValue(self.done)
        self._update_status()

    def _update_status(self, finished=False):
        pct = int(self.done * 100 / self.total) if self.total else 0
        prefix = "완료" if finished else ("일시정지" if self.btn_pause.isChecked() else f"{pct}%")
        self.lbl_status.setText(f"{prefix}, {self.on} 켜짐, {self.off} 꺼짐, "
                                f"{self.total - self.done} 남음 / 전체 {self.total}")

    # ---------- 테이블 행
    def _set_row(self, ip, state, name, ms, ttl, mac):
        def item(text, sort):
            it = QStandardItem(text)
            it.setData(sort, SORT_ROLE)
            it.setEditable(False)
            return it

        ip_int = int(ipaddress.IPv4Address(ip))
        status = item("", state)
        status.setIcon(self.icons[state])
        status.setData(bool(state), ALIVE_ROLE)
        status.setToolTip({0: "응답 없음", 1: "핑 응답", 2: "핑 차단 (ARP 응답)"}[state])
        note = QStandardItem(self._notes.get(ip, ""))
        cells = [
            status,
            item(name or ip, (name or ip).lower()),
            item(ip, ip_int),
            item("" if ms is None else str(ms), -1 if ms is None else ms),
            item("" if ttl is None else str(ttl), -1 if ttl is None else ttl),
            item(mac, mac),
            note,
        ]
        for c in (COL_TIME, COL_TTL):
            cells[c].setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        if not state:
            for c in cells:
                c.setForeground(QColor("#888888"))

        if ip in self.rows:  # 다시 핑한 경우 갱신
            row = self.rows[ip]
            cells[COL_NOTE] = self.model.item(row, COL_NOTE).clone()
            for c, it in enumerate(cells):
                self.model.setItem(row, c, it)
        else:
            self.rows[ip] = self.model.rowCount()
            self.model.appendRow(cells)

    def _collect_notes(self) -> dict[str, str]:
        notes = {}
        for r in range(self.model.rowCount()):
            text = self.model.item(r, COL_NOTE).text()
            if text:
                notes[self.model.item(r, COL_IP).text()] = text
        return notes

    def _selected_ips(self) -> list[str]:
        rows = {self.proxy.mapToSource(i).row() for i in self.view.selectionModel().selectedRows()}
        return [self.model.item(r, COL_IP).text() for r in sorted(rows)]

    # ---------- 우클릭 메뉴
    def show_menu(self, pos):
        ips = self._selected_ips()
        if not ips:
            return
        ip = ips[0]
        menu = QMenu(self)
        menu.addAction("다시 핑", lambda: self.reping(ips))
        menu.addAction("연속 핑 (ping -t)", lambda: subprocess.Popen(
            f'start "ping {ip}" cmd /k ping -t {ip}', shell=True))
        menu.addAction("tracert", lambda: subprocess.Popen(
            f'start "tracert {ip}" cmd /k tracert {ip}', shell=True))
        menu.addSeparator()
        menu.addAction("원격 데스크톱", lambda: subprocess.Popen(["mstsc", f"/v:{ip}"]))
        menu.addAction("공유 폴더 열기", lambda: subprocess.Popen(["explorer", f"\\\\{ip}"]))
        menu.addAction("웹 브라우저 (http)", lambda: subprocess.Popen(
            f'start "" http://{ip}', shell=True))
        menu.addSeparator()
        menu.addAction("IP 복사", lambda: QApplication.clipboard().setText("\n".join(ips)))
        menu.addAction("행 복사", self.copy_rows)
        menu.exec(self.view.viewport().mapToGlobal(pos))

    def reping(self, ips):
        timeout, use_arp, resolve = (self.spin_timeout.value(), self.chk_arp.isChecked(),
                                     self.chk_name.isChecked())
        self._notes = self._collect_notes()

        def task():
            with ThreadPoolExecutor(max_workers=min(32, len(ips))) as pool:
                for ip in ips:
                    pool.submit(one, ip)

        def one(ip):
            alive, ms, ttl = ping(ip, timeout)
            mac = get_mac(ip) if use_arp else ""
            state = 1 if alive else (2 if mac else 0)
            name = get_hostname(ip) if state and resolve else ""
            self._reping_signal.result.emit(ip, state, name, ms, ttl, mac)

        threading.Thread(target=task, daemon=True).start()

    def copy_rows(self):
        lines = []
        for ip in self._selected_ips():
            r = self.rows[ip]
            lines.append("\t".join(self.model.item(r, c).text() for c in range(1, len(COLUMNS))))
        QApplication.clipboard().setText("\n".join(lines))

    def export_csv(self):
        if self.model.rowCount() == 0:
            return
        path, _ = QFileDialog.getSaveFileName(self, "CSV 저장", "ping_result.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["상태"] + COLUMNS[1:])
            for r in range(self.proxy.rowCount()):
                src = self.proxy.mapToSource(self.proxy.index(r, 0)).row()
                state = self.model.item(src, COL_STATUS).data(SORT_ROLE)
                w.writerow([{0: "꺼짐", 1: "켜짐", 2: "켜짐(ARP)"}[state]] +
                           [self.model.item(src, c).text() for c in range(1, len(COLUMNS))])
        self.statusBar().showMessage(f"저장됨: {path}", 5000)

    def closeEvent(self, e):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(5000)
        super().closeEvent(e)


def main():
    if sys.platform == "win32":  # 작업 표시줄에 python 아이콘 대신 앱 아이콘 표시
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PingScanner")
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    if os.path.exists(ICON_PATH):
        app.setWindowIcon(QIcon(ICON_PATH))
    w = MainWindow()
    w.apply_theme(False)  # 기본: 라이트 모드
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import configparser
import hashlib
import logging
import logging.handlers
import os
import re
import shutil
import sys
import threading
import time
from typing import Optional, List, Dict, Any
import requests
try:
    import winsound
except Exception:
    winsound = None
APP_NAME = "AntivirusVT"
VERSION = "1.0 (SherzAntivirus VT)"
# Интервалы автоочистки логов
TIME_INTERVALS = {
    "5 минут": 300,
    "15 минут": 900,
    "30 минут": 1800,
    "1 час": 3600,
    "8 часов": 28800,
    "1 день": 86400,
    "1 неделя": 604800,
    "1 месяц": 2592000,
}
LOG_TIME_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3}")
# Определение папки для хранения (portable или user)
def get_exe_dir() -> str:
    """Папка, где находится скрипт или exe (PyInstaller)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
def get_user_data_dir(app_name: str = APP_NAME) -> str:
    """Папка пользователя для хранения данных приложения."""
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
    else:
        base = os.path.expanduser("~/.local/share")
    return os.path.join(base, app_name)
def is_writable_dir(path: str) -> bool:
    """Проверка: можно ли создать файл в директории."""
    try:
        os.makedirs(path, exist_ok=True)
        test_path = os.path.join(path, ".write_test")
        with open(test_path, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(test_path)
        return True
    except Exception:
        return False
EXE_DIR = get_exe_dir()
PORTABLE_MARKER = os.path.join(EXE_DIR, "portable.mode")
if os.path.exists(PORTABLE_MARKER):
    BASE_DIR = EXE_DIR
    STORAGE_MODE = "portable"
else:
    if is_writable_dir(EXE_DIR):
        BASE_DIR = EXE_DIR
        STORAGE_MODE = "portable"
    else:
        BASE_DIR = get_user_data_dir(APP_NAME)
        os.makedirs(BASE_DIR, exist_ok=True)
        STORAGE_MODE = "user"
# Пути к файлам логов и настроек
LOG_DIR_PATH = os.path.join(BASE_DIR, "logs")
LOG_FILE_PATH = os.path.join(LOG_DIR_PATH, "antivirus.log")
SETTINGS_DIR = os.path.join(BASE_DIR, "settings")
SETTINGS_FILE_PATH = os.path.join(SETTINGS_DIR, "settings.ini")
# Логирование
os.makedirs(LOG_DIR_PATH, exist_ok=True)
logger = logging.getLogger("AntivirusAppLogger")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(funcName)s - %(message)s")
_file_handler = None
try:
    _file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE_PATH,
        maxBytes=1024 * 1024 * 5,
        backupCount=5,
        encoding="utf-8",
    )
    _file_handler.setFormatter(formatter)
    logger.addHandler(_file_handler)
except Exception as e:
    print(f"КРИТИЧЕСКАЯ ОШИБКА ФАЙЛОВОГО ЛОГИРОВАНИЯ: {e}")
_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(formatter)
logger.addHandler(_console_handler)
logger.info(f"Система логирования инициализирована. STORAGE_MODE={STORAGE_MODE}, BASE_DIR={BASE_DIR}")
# Вспомогательные функции
def apply_logging_setting(enable: bool) -> None:
    if enable:
        logger.setLevel(logging.INFO)
        logger.info("Логирование включено (INFO).")
    else:
        logger.setLevel(logging.CRITICAL + 1)
        print("Логирование отключено в настройках.")
def resolve_maybe_relative_path(path_value: str, base_dir: str) -> str:
    """
    Если путь относительный (например 'quarantine'), считаем относительно base_dir.
    Если абсолютный, используем как есть.
    """
    p = (path_value or "").strip()
    if not p:
        return os.path.join(base_dir, "quarantine")
    if os.path.isabs(p):
        return p
    return os.path.join(base_dir, p)
def normalize_path_for_save(abs_path: str, base_dir: str) -> str:
    """
    Если путь внутри base_dir, сохраняем относительный путь (для переносимости).
    Иначе сохраняем абсолютный.
    """
    try:
        base_abs = os.path.abspath(base_dir)
        p_abs = os.path.abspath(abs_path)
        if p_abs == base_abs:
            return "."
        if p_abs.startswith(base_abs + os.sep):
            return os.path.relpath(p_abs, base_abs)
        return p_abs
    except Exception:
        return abs_path
def save_settings_to_file(new_config: configparser.ConfigParser) -> None:
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE_PATH), exist_ok=True)
        with open(SETTINGS_FILE_PATH, "w", encoding="utf-8") as configfile:
            new_config.write(configfile)
        logger.info("Настройки сохранены в файл.")
    except Exception as e:
        logger.error(f"Не удалось сохранить настройки в файл: {e}")
def load_settings() -> configparser.ConfigParser:
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    config = configparser.ConfigParser()
    default_settings = {
        "ActionOnDetection": "SuggestDelete",
        "UseQuarantine": "True",
        "QuarantinePath": "quarantine",
        "EnableLogging": "True",
        "ClearLogsEnabled": "False",
        "ClearLogsInterval": "1 месяц",
        "VirusTotalAPIKey": "",
    }
    read_ok = config.read(SETTINGS_FILE_PATH, encoding="utf-8")
    if not read_ok:
        logger.warning("Файл настроек не найден, создаем новый.")
    if "-settings-" not in config:
        config["-settings-"] = {}
    for key, value in default_settings.items():
        if key not in config["-settings-"]:
            config["-settings-"][key] = value
    enable_logging = config.getboolean("-settings-", "EnableLogging", fallback=True)
    apply_logging_setting(enable_logging)
    if not os.path.exists(SETTINGS_FILE_PATH):
        save_settings_to_file(config)
    return config
def remove_file(file_path: str) -> None:
    try:
        os.remove(file_path)
        logger.warning(f"Файл успешно удален: {file_path}")
        messagebox.showinfo("Результат", "Файл успешно удален.")
    except Exception as e:
        logger.error(f"Ошибка удаления файла {file_path}: {e}")
        messagebox.showerror("Результат", f"Не удалось удалить файл:\n{file_path}\nОшибка: {e}")
def get_file_hash(file_path: str) -> Optional[str]:
    try:
        block_size = 65536
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                buf = f.read(block_size)
                if not buf:
                    break
                hasher.update(buf)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Ошибка чтения файла для получения хэша: {file_path} - {e}")
        return None
def _safe_int(x: Any) -> int:
    try:
        return int(x)
    except Exception:
        return 0
def _sum_stats(stats: Dict[str, Any]) -> int:
    total = 0
    for v in stats.values():
        if isinstance(v, (int, float, str)):
            total += _safe_int(v)
    return total
def _extract_top_names(last_analysis_results: Dict[str, Any], limit: int = 3) -> List[str]:
    """
    Собираем топ названий из движков.
    Берем только category malicious/suspicious, result не пустой.
    """
    freq: Dict[str, int] = {}
    for _, info in (last_analysis_results or {}).items():
        if not isinstance(info, dict):
            continue
        category = str(info.get("category", "")).lower()
        result = info.get("result")
        if not result:
            continue
        if category not in ("malicious", "suspicious"):
            continue
        name = str(result).strip()
        if not name:
            continue
        if len(name) > 80:
            name = name[:77] + "..."
        freq[name] = freq.get(name, 0) + 1
    if not freq:
        return []
    sorted_names = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    return [n for n, _ in sorted_names[:limit]]
def _infer_threat_type(suggested_label: str, names: List[str]) -> str:
    known = {
        "trojan": "Trojan",
        "worm": "Worm",
        "adware": "Adware",
        "ransom": "Ransomware",
        "ransomware": "Ransomware",
        "backdoor": "Backdoor",
        "spyware": "Spyware",
        "riskware": "Riskware",
        "downloader": "Downloader",
        "virus": "Virus",
    }
    s = (suggested_label or "").strip().lower()
    if s:
        token = re.split(r"[\s\./:_-]+", s)[0].strip()
        if token in known:
            return known[token]
        if token:
            return token[:1].upper() + token[1:]
    for nm in names:
        t = nm.strip().lower()
        token = re.split(r"[\s\./:_-]+", t)[0].strip()
        if token in known:
            return known[token]
    return "Вредоносное ПО"
def check_virustotal_api_details(file_hash: str, api_key: str) -> Dict[str, Any]:
    """
    Расширенная проверка VT по SHA256.
    Важно: это НЕ загрузка файла, а проверка "есть ли такой хэш в базе VT".
    """
    if not api_key:
        return {"code": "NO_KEY"}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json() or {}
            attrs = (((data.get("data") or {}).get("attributes")) or {})
            stats = attrs.get("last_analysis_stats") or {}
            malicious = _safe_int(stats.get("malicious", 0))
            total = _sum_stats(stats)
            ptc = attrs.get("popular_threat_classification") or {}
            suggested_label = str(ptc.get("suggested_threat_label", "")).strip()
            last_results = attrs.get("last_analysis_results") or {}
            top_names = _extract_top_names(last_results, limit=3)
            threat_type = _infer_threat_type(suggested_label, top_names)
            return {
                "code": "OK",
                "malicious": malicious,
                "total": total,
                "threat_type": threat_type,
                "top_names": top_names,
                "sha256": file_hash,
                "suggested_label": suggested_label,
            }
        if response.status_code == 404:
            return {"code": "NOT_FOUND"}
        if response.status_code == 401:
            return {"code": "BAD_KEY"}
        logger.error(f"Ошибка API: {response.status_code}")
        return {"code": "ERROR"}
    except Exception as e:
        logger.error(f"Исключение при запросе к VT: {e}")
        return {"code": "ERROR"}
# Приложение
class AntivirusApp:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.filepath: Optional[str] = None
        self.config = load_settings()
        self.action_var = tk.StringVar(
            value=self.config.get("-settings-", "ActionOnDetection", fallback="SuggestDelete")
        )
        self.quarantine_use_var = tk.BooleanVar(
            value=self.config.getboolean("-settings-", "UseQuarantine", fallback=True)
        )
        raw_quar = self.config.get("-settings-", "QuarantinePath", fallback="quarantine")
        quar_abs = resolve_maybe_relative_path(raw_quar, BASE_DIR)
        if os.path.isabs(raw_quar) and not os.path.exists(quar_abs):
            quar_abs = os.path.join(BASE_DIR, "quarantine")
        self.quarantine_path_var = tk.StringVar(value=quar_abs)
        self.vt_api_key_var = tk.StringVar(
            value=self.config.get("-settings-", "VirusTotalAPIKey", fallback=""))
        self.log_enable_var = tk.BooleanVar(
            value=self.config.getboolean("-settings-", "EnableLogging", fallback=True))
        self.log_clear_enable_var = tk.BooleanVar(
            value=self.config.getboolean("-settings-", "ClearLogsEnabled", fallback=False))
        self.log_clear_interval_var = tk.StringVar(
            value=self.config.get("-settings-", "ClearLogsInterval", fallback="1 месяц"))
        self.logs_window = None
        self.logs_text = None
        self.master.title(f"Антивирус (v{VERSION})")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook.Tab", font=("Arial", 10, "bold"), padding=[10, 5])
        style.configure("Header.TLabel", font=("Arial", 18, "bold"), foreground="#333333")
        style.configure("MainStatus.TLabel", font=("Arial", 20, "bold"), padding=10)
        style.configure("Detail.TLabel", font=("Arial", 10, "bold"))
        self.main_frame = ttk.Frame(master, padding="15")
        self.main_frame.pack(fill="both", expand=True)
        self.file_name_var = tk.StringVar(value="")
        self.file_path_var = tk.StringVar(value="")
        self.file_hash_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Файл не проверен")
        self.found_in_var = tk.StringVar(value="Совпадений не найдено")
        self.threat_info_var = tk.StringVar(value="")
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(pady=10, fill="both", expand=True)
        self.home_tab = ttk.Frame(self.notebook, padding="20")
        self.results_tab = ttk.Frame(self.notebook, padding="20")
        self.settings_tab = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(self.home_tab, text="Главная")
        self.notebook.add(self.results_tab, text="Результаты")
        self.notebook.add(self.settings_tab, text="Настройки")
        self.setup_home_tab()
        self.setup_results_tab()
        self.setup_settings_tab()
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        self.log_clear_job = None
        self.schedule_log_clear()
        logger.info("GUI успешно инициализирован.")
    # Просмотр логов
    def open_logs_viewer(self) -> None:
        os.makedirs(LOG_DIR_PATH, exist_ok=True)
        if not os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                f.write("")
        if self.logs_window and self.logs_window.winfo_exists():
            self.logs_window.lift()
            self.logs_window.focus_force()
            self.load_logs_into_viewer()
            return
        self.logs_window = tk.Toplevel(self.master)
        self.logs_window.title("Логи")
        self.logs_window.geometry("900x500")
        self.logs_window.minsize(700, 400)
        container = ttk.Frame(self.logs_window, padding=10)
        container.pack(fill="both", expand=True)
        text_frame = ttk.Frame(container)
        text_frame.pack(fill="both", expand=True)
        self.logs_text = tk.Text(text_frame, wrap="none")
        y_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.logs_text.yview)
        x_scroll = ttk.Scrollbar(text_frame, orient="horizontal", command=self.logs_text.xview)
        self.logs_text.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.logs_text.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        buttons = ttk.Frame(container)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Очистить логи", command=self.clear_logs_file).pack(side="left")
        ttk.Button(buttons, text="Сохранить логи", command=self.save_logs_as).pack(side="left", padx=8)
        self.load_logs_into_viewer()
        def _on_close():
            self.logs_window.destroy()
            self.logs_window = None
            self.logs_text = None
        self.logs_window.protocol("WM_DELETE_WINDOW", _on_close)
    def load_logs_into_viewer(self) -> None:
        if not self.logs_text:
            return
        try:
            if not os.path.exists(LOG_FILE_PATH):
                content = ""
            else:
                with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            self.logs_text.config(state="normal")
            self.logs_text.delete("1.0", "end")
            self.logs_text.insert("1.0", content if content else "")
            self.logs_text.config(state="disabled")
            self.logs_text.see("end")
        except Exception as e:
            messagebox.showerror("Логи", f"Не удалось открыть лог файл:\n{e}")
    def clear_logs_file(self) -> None:
        if not messagebox.askyesno("Логи", "Очистить лог файл?"):
            return
        try:
            if _file_handler:
                _file_handler.acquire()
            try:
                if _file_handler:
                    _file_handler.flush()
                with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write("")
            finally:
                if _file_handler:
                    _file_handler.release()
            self.load_logs_into_viewer()
            messagebox.showinfo("Логи", "Логи очищены.")
        except Exception as e:
            messagebox.showerror("Логи", f"Не удалось очистить логи:\n{e}")
    def save_logs_as(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Сохранить логи",
            defaultextension=".log",
            filetypes=[("Log file", "*.log"), ("Text file", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            if not os.path.exists(LOG_FILE_PATH):
                with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write("")
            shutil.copyfile(LOG_FILE_PATH, path)
            messagebox.showinfo("Логи", "Логи сохранены.")
        except Exception as e:
            messagebox.showerror("Логи", f"Не удалось сохранить логи:\n{e}")
    # Автоочистка логов
    def schedule_log_clear(self) -> None:
        if self.log_clear_job:
            self.master.after_cancel(self.log_clear_job)
            self.log_clear_job = None
        if self.log_clear_enable_var.get():
            interval_key = self.log_clear_interval_var.get()
            seconds = TIME_INTERVALS.get(interval_key, TIME_INTERVALS["1 месяц"])
            self.clear_old_logs(seconds)
            self.log_clear_job = self.master.after(seconds * 1000, self.schedule_log_clear)
            logger.info(f"Планировщик очистки логов запущен. Интервал: {interval_key} ({seconds} сек).")
        else:
            logger.info("Планировщик очистки логов отключен.")
    def clear_old_logs(self, interval_seconds: int) -> None:
        if not self.log_clear_enable_var.get():
            return
        try:
            if not os.path.exists(LOG_FILE_PATH):
                return
            with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines: List[str] = []
            current_time = time.time()
            for line in lines:
                match = LOG_TIME_PATTERN.match(line)
                if not match:
                    new_lines.append(line)
                    continue
                try:
                    timestamp_str = match.group(1)
                    log_time_struct = time.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    log_time_seconds = time.mktime(log_time_struct)
                    if current_time - log_time_seconds < interval_seconds:
                        new_lines.append(line)
                except Exception:
                    new_lines.append(line)
            if len(new_lines) < len(lines):
                if _file_handler:
                    _file_handler.acquire()
                try:
                    with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
                        f.writelines(new_lines)
                finally:
                    if _file_handler:
                        _file_handler.release()
            if self.logs_window and self.logs_window.winfo_exists():
                self.load_logs_into_viewer()
        except Exception as e:
            logger.error(f"Критическая ошибка при очистке логов: {e}")
    # UI
    def setup_home_tab(self) -> None:
        ttk.Label(self.home_tab, text="Готово к сканированию файлов", style="Header.TLabel").pack(pady=70)
        ttk.Button(
            self.home_tab,
            text="Выбрать файл для сканирования",
            command=self.browse_files
        ).pack(pady=40, padx=10, ipadx=20, ipady=10)
        ttk.Label(
            self.home_tab,
            text=f"Хранилище данных: {BASE_DIR}",
            font=("Arial", 9),
            foreground="#555555",
            wraplength=900,
            justify="center",
        ).pack(pady=10)
    def setup_results_tab(self) -> None:
        ttk.Label(self.results_tab, text="Результаты сканирования", style="Header.TLabel").pack(pady=10)
        info_frame = ttk.Frame(self.results_tab, padding="10")
        info_frame.pack(fill="x", pady=10)
        ttk.Label(info_frame, text="Имя файла:", style="Detail.TLabel").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.file_name_var, font=("Arial", 10)).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, text="Путь к файлу:", style="Detail.TLabel").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.file_path_var, font=("Arial", 10)).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, text="SHA256 хэш:", style="Detail.TLabel").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Label(info_frame, textvariable=self.file_hash_var, font=("Arial", 10)).grid(row=2, column=1, sticky="w", padx=5, pady=2)
        info_frame.grid_columnconfigure(1, weight=1)
        ttk.Separator(self.results_tab, orient="horizontal").pack(fill="x", pady=15)
        self.status_label = ttk.Label(self.results_tab, textvariable=self.status_var, style="MainStatus.TLabel")
        self.status_label.pack(pady=10, fill="x")
        found_frame = ttk.Frame(self.results_tab)
        found_frame.pack(fill="x", pady=5)
        ttk.Label(found_frame, text="Совпадение найдено:", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        ttk.Label(found_frame, textvariable=self.found_in_var, font=("Arial", 10)).pack(side="left")
        self.threat_frame = ttk.LabelFrame(self.results_tab, text="Информация об угрозе", padding=10)
        self.threat_label = ttk.Label(
            self.threat_frame,
            textvariable=self.threat_info_var,
            justify="left",
            anchor="w",
        )
        self.threat_label.pack(fill="x")
        self.threat_frame.pack(fill="x", pady=10)
        self.threat_frame.pack_forget()
        # Кнопки внизу
        self.buttons_frame = ttk.Frame(self.results_tab)
        self.buttons_frame.pack(side="bottom", fill="x", pady=10)
        self.new_scan_btn = ttk.Button(
            self.buttons_frame,
            text="Новое сканирование",
            command=self._go_home_for_new_scan,)
        self.new_scan_btn.pack(side="left", padx=5, ipadx=10, ipady=5)
        # Эти кнопки должны появляться только при угрозе (и нужных настройках)
        self.quarantine_btn = ttk.Button(self.buttons_frame, text="Карантин", command=self.quarantine_file)
        self.delete_btn = ttk.Button(self.buttons_frame, text="Удалить файл", command=self.delete_current_file)
        self.quarantine_btn.pack_forget()
        self.delete_btn.pack_forget()
    def setup_settings_tab(self) -> None:
        ttk.Label(self.settings_tab, text="Настройки антивируса", style="Header.TLabel").pack(pady=10)
        vt_frame = ttk.LabelFrame(self.settings_tab, text="VirusTotal", padding=10)
        vt_frame.pack(fill="x", padx=10, pady=5)
        vt_inner = ttk.Frame(vt_frame)
        vt_inner.pack(fill="x")
        ttk.Label(vt_inner, text="API Key:").pack(side="left")
        ttk.Entry(vt_inner, textvariable=self.vt_api_key_var, width=40).pack(side="left", padx=5, fill="x", expand=True)
        action_frame = ttk.LabelFrame(self.settings_tab, text="Действие при обнаружении", padding=10)
        action_frame.pack(fill="x", padx=10, pady=5)
        ttk.Radiobutton(
            action_frame,
            text="Только уведомить",
            variable=self.action_var,
            value="Inform"
        ).pack(anchor="w", padx=5, pady=2)
        ttk.Radiobutton(
            action_frame,
            text="Предложить действие",
            variable=self.action_var,
            value="SuggestDelete"
        ).pack(anchor="w", padx=5, pady=2)
        quarantine_frame = ttk.LabelFrame(self.settings_tab, text="Карантин", padding=10)
        quarantine_frame.pack(fill="x", padx=10, pady=5)
        ttk.Checkbutton(
            quarantine_frame,
            text="Использовать карантин",
            variable=self.quarantine_use_var
        ).pack(anchor="w", padx=5, pady=2)
        path_entry_frame = ttk.Frame(quarantine_frame)
        path_entry_frame.pack(fill="x", padx=5, pady=2)
        ttk.Label(path_entry_frame, text="Папка карантина:").pack(side="left")
        ttk.Entry(path_entry_frame, textvariable=self.quarantine_path_var).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(path_entry_frame, text="...", width=3, command=self.browse_quarantine_path).pack(side="right")
        logging_frame = ttk.LabelFrame(self.settings_tab, text="Логирование", padding=10)
        logging_frame.pack(fill="x", padx=10, pady=5)
        ttk.Checkbutton(
            logging_frame,
            text="Включить логирование",
            variable=self.log_enable_var
        ).pack(anchor="w", padx=5, pady=2)
        btn_row = ttk.Frame(logging_frame)
        btn_row.pack(fill="x", padx=5, pady=4)
        ttk.Button(btn_row, text="Показать логи", command=self.open_logs_viewer).pack(side="left")
        log_clear_frame = ttk.LabelFrame(self.settings_tab, text="Очистка логов", padding=10)
        log_clear_frame.pack(fill="x", padx=10, pady=5)
        ttk.Checkbutton(
            log_clear_frame,
            text="Включить автоочистку",
            variable=self.log_clear_enable_var
        ).pack(anchor="w", padx=5, pady=2)
        interval_frame = ttk.Frame(log_clear_frame)
        interval_frame.pack(fill="x", padx=5, pady=2)
        ttk.Label(interval_frame, text="Удалять логи старше:").pack(side="left")
        ttk.Combobox(
            interval_frame,
            textvariable=self.log_clear_interval_var,
            values=list(TIME_INTERVALS.keys()),
            state="readonly",
            width=12,
        ).pack(side="left", padx=5)
        ttk.Button(
            self.settings_tab,
            text="Сохранить настройки",
            command=self.save_settings
        ).pack(pady=15, side="right", padx=10)
    # Действия
    def _go_home_for_new_scan(self) -> None:
        self.notebook.select(self.home_tab)
    def _hide_action_buttons(self) -> None:
        """Скрыть кнопки удаления и карантина."""
        try:
            self.delete_btn.pack_forget()
        except Exception:
            pass
        try:
            self.quarantine_btn.pack_forget()
        except Exception:
            pass
    def _show_action_buttons_if_needed(self) -> None:
        """
        Показать кнопки рядом с "Новое сканирование", если:
        - ActionOnDetection = SuggestDelete
        - и для карантина включен чекбокс
        """
        self._hide_action_buttons()
        action = self.config.get("-settings-", "ActionOnDetection", fallback="SuggestDelete")
        if action != "SuggestDelete":
            return
        # Показываем "Карантин" только если включен чекбокс UseQuarantine
        if self.quarantine_use_var.get():
            self.quarantine_btn.pack(side="left", padx=5, ipadx=10, ipady=5)
        self.delete_btn.pack(side="left", padx=5, ipadx=10, ipady=5)
    def save_settings(self) -> None:
        old_logging = self.config.getboolean("-settings-", "EnableLogging", fallback=True)
        old_clear = self.config.getboolean("-settings-", "ClearLogsEnabled", fallback=False)
        old_interval = self.config.get("-settings-", "ClearLogsInterval", fallback="1 месяц")
        new_logging = self.log_enable_var.get()
        new_clear = self.log_clear_enable_var.get()
        new_clear_interval = self.log_clear_interval_var.get()
        self.config["-settings-"]["ActionOnDetection"] = self.action_var.get()
        self.config["-settings-"]["UseQuarantine"] = str(self.quarantine_use_var.get())
        self.config["-settings-"]["EnableLogging"] = str(new_logging)
        self.config["-settings-"]["ClearLogsEnabled"] = str(new_clear)
        self.config["-settings-"]["ClearLogsInterval"] = new_clear_interval
        self.config["-settings-"]["VirusTotalAPIKey"] = self.vt_api_key_var.get().strip()
        # Карантин: проверяем папку и сохраняем путь переносимо
        quar_ui = self.quarantine_path_var.get().strip()
        quar_abs = resolve_maybe_relative_path(quar_ui, BASE_DIR)
        try:
            os.makedirs(quar_abs, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Настройки", f"Не удалось создать папку карантина:\n{quar_abs}\nОшибка: {e}")
            logger.error(f"Не удалось создать папку карантина: {quar_abs} - {e}")
            return
        self.quarantine_path_var.set(quar_abs)
        self.config["-settings-"]["QuarantinePath"] = normalize_path_for_save(quar_abs, BASE_DIR)
        save_settings_to_file(self.config)
        if old_logging != new_logging:
            apply_logging_setting(new_logging)
        if old_clear != new_clear or old_interval != new_clear_interval:
            self.schedule_log_clear()
        messagebox.showinfo("Настройки", "Настройки сохранены.")
    def delete_current_file(self) -> None:
        if self.filepath and os.path.exists(self.filepath):
            logger.warning(f"Запрос на удаление файла: {self.filepath}")
            if messagebox.askyesno("Результаты", f"Вы уверены, что хотите удалить файл:\n{self.filepath}"):
                remove_file(self.filepath)
                self.filepath = None
                self._hide_action_buttons()
                if self.threat_frame.winfo_ismapped():
                    self.threat_frame.pack_forget()
                self.status_var.set("Файл удален")
                self.status_label.config(foreground="green")
                self.found_in_var.set("Совпадений не найдено")
        else:
            logger.warning("Пользователь пытался удалить файл, но filepath не установлен.")
            messagebox.showwarning("Результат", "Нет выбранного файла для действия.")
    def quarantine_file(self) -> None:
        if not self.filepath or not os.path.exists(self.filepath):
            messagebox.showwarning("Результаты", "Нет выбранного файла для действия.")
            logger.warning("Пользователь пытался поместить в карантин, но filepath не установлен.")
            return
        if not self.quarantine_use_var.get():
            messagebox.showwarning("Результаты", "Карантин отключен в настройках.")
            logger.warning("Карантин отключен, действие отменено.")
            return
        quarantine_dir_ui = self.quarantine_path_var.get().strip()
        quarantine_dir = resolve_maybe_relative_path(quarantine_dir_ui, BASE_DIR)
        try:
            os.makedirs(quarantine_dir, exist_ok=True)
            filename = os.path.basename(self.filepath)
            dest_path = os.path.join(quarantine_dir, filename)
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                dest_path = os.path.join(quarantine_dir, f"{base}_{os.getpid()}{ext}")
            shutil.move(self.filepath, dest_path)
            logger.critical(f"Файл помещен в карантин: {self.filepath} -> {dest_path}")
            messagebox.showinfo("Результаты", "Файл перемещен в карантин.")
            self.filepath = None
            self._hide_action_buttons()
            if self.threat_frame.winfo_ismapped():
                self.threat_frame.pack_forget()
            self.status_var.set("Файл перемещен в карантин")
            self.status_label.config(foreground="green")
            self.found_in_var.set(f"Карантин: {quarantine_dir}")
        except Exception as e:
            logger.error(f"Не удалось переместить файл в карантин: {e}")
            messagebox.showerror("Результаты", f"Не удалось переместить файл:\n{e}")
    def browse_quarantine_path(self) -> None:
        folder_path = filedialog.askdirectory(title="Выберите папку для карантина")
        if folder_path:
            self.quarantine_path_var.set(folder_path)
            logger.info(f"Новый путь карантина выбран: {folder_path}")
    def browse_files(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Выберите файл для сканирования",
            filetypes=[
                ("Все файлы", "*.*"),
                ("Исполняемые файлы", "*.exe"),
                ("Документы", "*.docx;*.xlsx;*.pptx"),
            ],
)
        if not file_path:
            logger.info("Сканирование отменено пользователем (файл не выбран).")
            return
        self.filepath = file_path
        self.notebook.select(self.results_tab)
        self.scan_file(file_path)
    # Сканирование
    def scan_file(self, file_path: str) -> None:
        logger.info(f"Начато сканирование файла: {file_path}")
        file_name = os.path.basename(file_path)
        self.file_name_var.set(file_name)
        self.file_path_var.set(file_path)
        self.file_hash_var.set("")
        self.found_in_var.set("Совпадений не найдено")
        self.threat_info_var.set("")
        if self.threat_frame.winfo_ismapped():
            self.threat_frame.pack_forget()
        self._hide_action_buttons()
        self.status_var.set("Подключение к облаку...")
        self.status_label.config(foreground="#007BFF")
        api_key = self.vt_api_key_var.get().strip()
        threading.Thread(target=self.run_vt_scan_thread, args=(file_path, api_key), daemon=True).start()
    def run_vt_scan_thread(self, file_path: str, api_key: str) -> None:
        readable_hash = get_file_hash(file_path)
        if not readable_hash:
            self.master.after(0, self.update_scan_ui, "ERROR_READ", None)
            return
        self.master.after(0, lambda: self.file_hash_var.set(readable_hash))
        if not api_key:
            self.master.after(0, self.update_scan_ui, "NO_KEY", None)
            return
        details = check_virustotal_api_details(readable_hash, api_key)
        self.master.after(0, self.update_scan_ui, "RESULT", details)
    def _format_threat_block(self, details: Dict[str, Any]) -> str:
        malicious = int(details.get("malicious", 0))
        total = int(details.get("total", 0))
        threat_type = str(details.get("threat_type", "Вредоносное ПО"))
        top_names = details.get("top_names") or []
        sha256 = str(details.get("sha256", ""))
        sha_short = sha256
        if len(sha_short) > 24:
            sha_short = sha_short[:24] + "..."
        lines = []
        lines.append("Обнаружена угроза")
        lines.append("")
        lines.append(f"Тип угрозы: {threat_type}")
        if total > 0:
            lines.append(f"Детектов: {malicious} / {total}")
        else:
            lines.append(f"Детектов: {malicious}")
        if top_names:
            lines.append("Основные названия:")
            for n in top_names:
                lines.append(f" • {n}")
        else:
            lines.append("Основные названия: нет данных")
        lines.append("")
        lines.append(f"SHA256: {sha_short}")
        return "\n".join(lines)
    def update_scan_ui(self, status_code: str, payload: Optional[Dict[str, Any]]) -> None:
        if status_code == "ERROR_READ":
            self.status_var.set("Ошибка чтения файла")
            self.status_label.config(foreground="red")
            self.file_hash_var.set("ERROR")
            return
        if status_code == "NO_KEY":
            self.status_var.set("API Key не указан")
            self.status_label.config(foreground="orange")
            self.found_in_var.set("Укажите API Key в настройках")
            messagebox.showwarning("API Key", "Пожалуйста, укажите API Key VirusTotal в настройках.")
            return
        if status_code != "RESULT":
            return
        details = payload or {}
        code = details.get("code", "ERROR")
        if code == "BAD_KEY":
            self.status_var.set("Неверный API Key")
            self.status_label.config(foreground="red")
            self.found_in_var.set("Проверьте API Key")
            return
        if code == "NOT_FOUND":
            self.status_var.set("Файл чист")
            self.status_label.config(foreground="green")
            self.found_in_var.set("В базе VirusTotal не найден, угроз не обнаружено")
            logger.info("Файл не найден в базе VT, отображаем как чистый.")
            self._hide_action_buttons()
            return
        if code != "OK":
            self.status_var.set("Ошибка сети")
            self.status_label.config(foreground="orange")
            self.found_in_var.set("Соединение не удалось")
            self._hide_action_buttons()
            return
        malicious = int(details.get("malicious", 0))
        if malicious > 0:
            self.status_var.set("Обнаружена угроза")
            self.status_label.config(foreground="red")
            total = int(details.get("total", 0))
            if total > 0:
                self.found_in_var.set(f"VirusTotal: {malicious} / {total}")
            else:
                self.found_in_var.set(f"VirusTotal: {malicious}")
            if winsound:
                try:
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                except Exception:
                    pass
            logger.warning(f"ОБНАРУЖЕНА УГРОЗА (VT: {malicious}).")
            self.threat_info_var.set(self._format_threat_block(details))
            if not self.threat_frame.winfo_ismapped():
                self.threat_frame.pack(fill="x", pady=10)
            # Главное исправление: показываем кнопки снизу
            self._show_action_buttons_if_needed()
        else:
            self.status_var.set("Файл чист")
            self.status_label.config(foreground="green")
            self.found_in_var.set("Угроз не обнаружено")
            logger.info("Файл чист.")
            if self.threat_frame.winfo_ismapped():
                self.threat_frame.pack_forget()
            self._hide_action_buttons()
    def on_close(self) -> None:
        if self.log_clear_job:
            self.master.after_cancel(self.log_clear_job)
        logger.info("Приложение AntivirusApp закрывается.")
        self.master.destroy()
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1100x800")
    root.minsize(900, 650)
    app = AntivirusApp(root)
    root.mainloop()
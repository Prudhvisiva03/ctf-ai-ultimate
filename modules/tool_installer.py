import shutil
import subprocess
import os
import sys

class ToolInstaller:
    """Automatically parses playbooks and installs missing tools"""
    
    def __init__(self, config):
        self.config = config
        
    def check_and_install(self, tool_name):
        """Check if tool exists, if not install it"""
        if shutil.which(tool_name):
            return True
            
        print(f"⚠️  Tool '{tool_name}' not found.")
        print(f"🔧 Attempting auto-installation...")
        
        # Mapping of tool names to apt packages
        packages = {
            'apktool': 'apktool',
            'jadx': 'jadx',
            'strings': 'binutils',
            'foremost': 'foremost',
            'binwalk': 'binwalk',
            'steghide': 'steghide',
            'exiftool': 'libimage-exiftool-perl',
            'zsteg': 'zsteg', # gem install
            'outguess': 'outguess',
            'stegseek': 'stegseek',
            'ffmpeg': 'ffmpeg',
            'pngcheck': 'pngcheck'
        }
        
        pkg = packages.get(tool_name, tool_name)
        
        try:
            # Special cases
            if tool_name == 'zsteg':
                subprocess.run(['sudo', 'gem', 'install', 'zsteg'], check=True)
            elif tool_name == 'stegseek':
                # Stegseek usually needs github deb
                print("   Note: Stegseek might require manual install from GitHub releases if apt fails.")
                subprocess.run(['sudo', 'apt-get', 'install', '-y', 'stegseek'], check=True)
            else:
                subprocess.run(['sudo', 'apt-get', 'install', '-y', pkg], check=True)
                
            print(f"✅ Successfully installed {tool_name}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to install {tool_name}: {e}")
            return False
            
    def verify_playbook_tools(self, playbook_path):
        """Read a playbook and verify all required tools are present"""
        import yaml
        try:
            with open(playbook_path, 'r') as f:
                data = yaml.safe_load(f)
                
            tools = data.get('tools', [])
            for tool in tools:
                self.check_and_install(tool)
        except Exception as e:
            print(f"Error checking tools for playbook: {e}")

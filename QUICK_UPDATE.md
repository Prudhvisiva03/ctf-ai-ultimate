# 🚀 Quick Update Guide for Kali Linux

## ⚡ Super Quick (1 Command)

```bash
cd /path/to/ctfhunter && chmod +x update.sh && ./update.sh
```

**Done!** ✅

---

## 📝 Step-by-Step (Manual)

### 1️⃣ **Go to Project Folder**
```bash
cd /path/to/ctfhunter
```

### 2️⃣ **Pull Latest Code** (if using Git)
```bash
git pull origin main
```

### 3️⃣ **Update System Packages**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip exiftool binwalk steghide
```

### 4️⃣ **Update Python Packages**
```bash
python3 -m pip install -r requirements.txt --upgrade --break-system-packages
```

### 5️⃣ **Test It**
```bash
python3 ctf-ai.py --help
```

---

## 🎯 What You Get (v2.1)

```
╔═══════════════════════════════════════════════════════════╗
║           🎯 INTERACTIVE MENU MODE - NEW!                 ║
╚═══════════════════════════════════════════════════════════╝

✅ 9 Challenge Categories:
   1. 🔐 Cryptography
   2. 🖼️  Steganography
   3. 💾 Disk Forensics
   4. 📦 Archive Analysis
   5. 📡 Network/PCAP
   6. 💻 Binary/Reverse
   7. 📄 PDF Forensics
   8. 🌐 Web Challenges
   9. 🔍 Generic Scan

✅ AI-Powered Guidance for Each Type
✅ File Type Detection
✅ Beautiful Colors & Emojis
✅ Step-by-Step Workflow
```

---

## 🚀 Try New Menu Mode

```bash
python3 ctf-ai.py
```

Then type:
```
🤖 You: menu
```

Select challenge type → Enter file → Get AI guidance → Solve! 🏆

---

## 🐛 Common Issues

### **Problem: "externally-managed-environment"**
**Fix:**
```bash
python3 -m pip install -r requirements.txt --break-system-packages
```

### **Problem: Permission Denied**
**Fix:**
```bash
chmod +x ctf-ai.py ctfhunter.py update.sh
```

### **Problem: Module Not Found**
**Fix:**
```bash
python3 -m pip install module-name --break-system-packages
```

---

## ✅ Verify Update

```bash
# Test CTF-AI
python3 ctf-ai.py --help

# Test colors
python3 test_colors.py

# Test menu
python3 demo_menu.py
```

---

## 📚 Full Documentation

- `KALI_UPDATE_GUIDE.md` - Complete update guide (this file)
- `MENU_MODE_DOCUMENTATION.md` - Menu feature details
- `FINAL_UPDATE_SUMMARY.md` - All changes in v2.1
- `README.md` - Main documentation

---

## 🎉 You're Ready!

**Updated to v2.1!** Now you have:
- ✨ Interactive menu with 9 challenge types
- 🧠 AI-powered guidance
- 🎨 Beautiful colorful interface
- 🚀 Latest features

**Happy Hacking!** 🏆

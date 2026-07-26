# 🚀 Running AICyberAuditBox on your Azure VM

Every time you freshly start or connect to your Azure VM, follow these simple steps to launch the application.

---

## ⚡ Daily Startup Steps (Only 2 Steps!)

### 🖥️ Step 1: Connect to your VM
1. Open **Remote Desktop Connection** on your laptop.
2. Connect to your VM's **Public IP address** using username `veeresh988V`.

### 🚀 Step 2: Open PowerShell & Launch
1. Open **PowerShell** on the VM.
2. Run these two simple commands to enter the folder and launch the app:
   ```powershell
   cd AICyberSecurityAuditBoxV
   .\run_demo.bat
   ```

---

## 🛠️ What the launcher script does automatically:
1. **Ollama Auto-Start:** Validates that the Ollama AI engine is active. If it is closed, the script automatically boots it in the background.
2. **ShaktiDB Auto-Launch:** Starts your Docker database container (`shakthidb_service`) on port `15234` loaded with the clean schemas automatically.
3. **App Start:** Starts the Streamlit dashboard on port **`8501`** and opens it in the browser!

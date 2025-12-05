# VPS Manager Pro (Web SSH Terminal)

[English](#english) | [中文说明](#chinese)

<a name="english"></a>
## 🇬🇧 English

**VPS Manager Pro** is a powerful, web-based SSH terminal that allows you to manage multiple VPS connections from your browser. It features multi-user support, session saving via MySQL, and intelligent detection of proxy configurations (VMess/SOCKS5) directly from the terminal output.

### ✨ Key Features
* **Web-based SSH:** Full interactive terminal using `xterm.js` and `socket.io`.
* **Multi-User System:** Secure login/logout system with password hashing (`bcrypt`). Users can only see their own saved sessions.
* **Session Management:** Save, edit, and label your VPS connection details for quick access.
* **Smart Detection:** Automatically detects VMess links and SOCKS5 credentials in the terminal output and generates QR codes/copy buttons.
* **Quick Tools:** Integrated buttons for common VPS scripts (EdNovas Toolbox, VMess/TCP installation).

### 📂 File Structure
* `server.js`: The main Node.js backend handling API routes, SSH socket connections, and authentication.
* `database.js`: MySQL connection pool and logic for user/session management.
* `vps_manager.html`: The frontend single-page application (React + Tailwind CSS via CDN).
* `package.json`: Project dependencies.

### 🚀 Installation & Setup

#### 1. Prerequisites
* Node.js (v14+)
* MySQL Server

#### 2. Database Setup
Create a database in MySQL (e.g., via phpMyAdmin or aaPanel):
```sql
CREATE DATABASE vps_manager;

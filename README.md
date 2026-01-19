# 🐚 Reverse Shell Generator

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-red.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)
![Platform](https://img.shields.io/badge/platform-Web-cyan.svg)
![Status](https://img.shields.io/badge/status-Active-green.svg)

**A modern, feature-rich reverse shell payload generator for penetration testers and CTF players.**

[Features](#-features) • [Demo](#-demo) • [Installation](#-installation) • [Usage](#-usage) • [Payloads](#-available-payloads) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

Reverse Shell Generator is a web-based tool designed for cybersecurity professionals, penetration testers, and CTF enthusiasts. It provides a comprehensive collection of reverse shell payloads across multiple programming languages and platforms, with real-time customization and encoding options.

## ✨ Features

| Feature                     | Description                                          |
| --------------------------- | ---------------------------------------------------- |
| 🔄 **Real-time Generation** | Payloads update instantly as you type IP and port    |
| 🔍 **Smart Search**         | Filter payloads by name, type, or category           |
| 📂 **Category Filters**     | Organize by Linux, Windows, Web, or MSFVenom         |
| 🔐 **Multiple Encodings**   | Raw, Base64, URL Encode, Double URL Encode           |
| 📋 **One-Click Copy**       | Copy any payload to clipboard instantly              |
| 👂 **Listener Commands**    | Auto-generated listener commands (nc, socat, pwncat) |
| ⬆️ **Shell Upgrade**        | TTY upgrade commands included                        |
| 🌙 **Dark Theme**           | Modern, eye-friendly dark interface                  |
| 📱 **Responsive**           | Works on desktop, tablet, and mobile                 |
| 🔒 **Offline Ready**        | No server required, runs entirely in browser         |

## 🖼️ Demo

<div align="center">

### Main Interface

_Modern dark theme with glassmorphism effects_

### Search & Filter

_Real-time search with category filtering_

### MSFVenom Payloads

_Complete MSFVenom payload generation_

</div>

## 🚀 Installation

### Option 1: Direct Use

Simply open `index.html` in your web browser. No installation required!

```bash
# Clone the repository
git clone https://github.com/yourusername/reverse-shell-generator.git

# Navigate to directory
cd reverse-shell-generator

# Open in browser
open index.html  # macOS
xdg-open index.html  # Linux
start index.html  # Windows
```

### Option 2: Local Server

```bash
# Using Python
python -m http.server 8080

# Using PHP
php -S localhost:8080

# Using Node.js
npx serve
```

Then visit `http://localhost:8080`

## 📖 Usage

1. **Enter Connection Details**
   - Set your IP address (LHOST)
   - Set your listening port (LPORT)
   - Choose shell type (/bin/bash, /bin/sh, cmd.exe, etc.)

2. **Select Encoding** (Optional)
   - Raw: No encoding
   - Base64: Base64 encoded payload
   - URL Encode: URL encoded payload
   - Double URL: Double URL encoded payload

3. **Filter Payloads**
   - Use category tabs (Linux, Windows, Web, MSFVenom)
   - Use search box to find specific payloads

4. **Copy & Use**
   - Click "Kopyala" button to copy payload
   - Set up listener using provided commands
   - Execute payload on target

## 🛠️ Available Payloads

### Linux Shells

| Payload       | Type                  |
| ------------- | --------------------- |
| Bash -i       | TCP Reverse Shell     |
| Bash 196      | File Descriptor Shell |
| Bash UDP      | UDP Reverse Shell     |
| Netcat -e     | Traditional Netcat    |
| Netcat mkfifo | OpenBSD Netcat        |
| Python3       | Python PTY Shell      |
| Python2       | Python Subprocess     |
| Perl          | Perl Socket           |
| Ruby          | Ruby Socket           |
| Socat         | Socat Shell           |
| Socat TTY     | Full TTY Shell        |
| AWK           | AWK Shell             |
| Lua           | Lua Socket            |

### Windows Shells

| Payload           | Type            |
| ----------------- | --------------- |
| PowerShell #1     | TCP Client      |
| PowerShell #2     | Hidden Window   |
| PowerShell Base64 | Encoded Payload |

### Web Shells

| Payload           | Type              |
| ----------------- | ----------------- |
| PHP exec          | PHP Exec Shell    |
| PHP shell_exec    | PHP Shell Exec    |
| PHP popen         | PHP Popen         |
| PHP Pentestmonkey | Full Featured PHP |
| Node.js           | Node Socket       |
| Groovy            | Java Groovy       |

### MSFVenom Payloads

| Payload                       | Format    |
| ----------------------------- | --------- |
| Linux Meterpreter (x64/x86)   | ELF       |
| Linux Shell (x64/x86)         | ELF       |
| Windows Meterpreter (x64/x86) | EXE       |
| Windows Shell (x64/x86)       | EXE       |
| Windows DLL                   | DLL       |
| Windows PowerShell            | PS1       |
| Windows HTA                   | HTA       |
| Windows MSI                   | MSI       |
| Windows VBA                   | VBA Macro |
| PHP Meterpreter               | PHP       |
| ASP/ASPX Meterpreter          | ASP/ASPX  |
| JSP Meterpreter               | JSP       |
| WAR Meterpreter               | WAR       |
| Python Meterpreter            | Python    |
| macOS Meterpreter             | Mach-O    |
| Android Meterpreter           | APK       |

## 🎨 Tech Stack

- **HTML5** - Structure
- **CSS3** - Styling with CSS Variables, Glassmorphism, Animations
- **JavaScript** - Vanilla JS, No dependencies
- **Google Fonts** - Inter & JetBrains Mono

## 📁 Project Structure

```
reverse-shell-generator/
├── index.html      # Main HTML file
├── style.css       # Styles and animations
├── script.js       # Payload database and logic
├── README.md       # Documentation
└── .gitignore      # Git ignore file
```

## ⚠️ Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The author is not responsible for misuse of this tool
- Always follow responsible disclosure practices

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-payload`)
3. Commit your changes (`git commit -m 'Add new payload'`)
4. Push to the branch (`git push origin feature/new-payload`)
5. Open a Pull Request

### Ideas for Contributions

- Add more reverse shell payloads
- Add bind shell support
- Add web shell generation
- Add more encoding options
- Improve mobile responsiveness
- Add language translations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Enes Özkırdeniz**

- GitHub: [@enesozkirdeniz](https://github.com/enesozkirdeniz)
- Website: [enesozkirdeniz.com](https://enesozkirdeniz.com)

## ⭐ Show Your Support

If this project helped you, please give it a ⭐ on GitHub!

---

<div align="center">

**🔴 Red Team Toolkit | CTF & Penetration Testing**

Made with ❤️ for the cybersecurity community

</div>
# reverse-shell-generator

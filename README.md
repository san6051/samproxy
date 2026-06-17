## samproxy

samproxy is a simple, lightweight and fast tool that allows pentesters to establish tunnels using SOCKS5.

### Bind SOCKS5 proxy
```
Operator machine                    Pivot machine (behind NAT)
+---------------------+             +---------------------+
| proxychains nmap    |             | socks5_proxy.py     |
|        |            |             |   listening :1080   |
|        v            |--TCP:1080 ->|         |           |
| [ SOCKS5 client ] --+------------>|         v           |
|                     |             | [ connects to ]     |
|                     |             |   internal hosts    |
+---------------------+             +---------------------+
```
#### Server
```
python3 proxy3.py proxyadmin securepassword123 0.0.0.0 1080
```
#### Agent
```
Burpsuite -> (Network/Connections/SOCKS Proxy) -> ProxyHost,ProxyPort,Username,Password
```
### Reverse SOCKS5 proxy
```
Operator machine                    Pivot machine (behind NAT)
+---------------------+             +---------------------+
| rsocks_server.py    |             | rsocks_agent.py     |
|   :4433 (control)   |<--TCP:4433 -|   dials OUT to VPS  |
|   :1080 (SOCKS5)    |             |         |           |
|        |            |             |         v           |
| proxychains nmap    |             | forwards to internal |
|   connects to :1080 |             |   hosts via NAT      |
+---------------------+             +---------------------+

```

#### Server
```
python3 rsocks_server.py --control 0.0.0.0:4433 --socks 127.0.0.1:1080 --pass 'COFFSec!'
```

#### Agent
```
python3 rsocks_agent.py --server vps.example.com:4433 --pass 'COFFSec!'
```
                  

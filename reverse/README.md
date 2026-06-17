## Agent
```
python3 rsocks_agent.py --server vps.example.com:4433 --pass 'COFFSec!'
```

## Server
```
python3 rsocks_server.py --control 0.0.0.0:4433 --socks 127.0.0.1:1080 --pass 'COFFSec!'
```
```
curl --socks5 127.0.0.1:1080 https://ifconfig.me
```

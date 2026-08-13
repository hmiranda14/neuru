#!/usr/bin/env python3
"""Dummy TCP/UDP echo listeners — firewall/NAT/ACL test targets. Managed by util-agent."""
import argparse, socket, threading

def tcp_listener(port, banner):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("0.0.0.0",port)); s.listen(16)
    while True:
        try:
            c,_=s.accept(); c.sendall((banner+"\n").encode())
            try: c.settimeout(2); c.recv(1024)
            except Exception: pass
            c.close()
        except Exception: pass

def udp_listener(port, banner):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("0.0.0.0",port))
    while True:
        try:
            data,addr=s.recvfrom(2048); s.sendto((banner+"\n").encode(),addr)
        except Exception: pass

def ports(s):
    return [int(p) for p in str(s).replace(" ","").split(",") if p.strip().isdigit()]

if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--tcp",default=""); ap.add_argument("--udp",default=""); ap.add_argument("--banner",default="NEURU-UTIL-OK")
    a=ap.parse_args(); threads=[]
    for p in ports(a.tcp): threads.append(threading.Thread(target=tcp_listener,args=(p,a.banner),daemon=True))
    for p in ports(a.udp): threads.append(threading.Thread(target=udp_listener,args=(p,a.banner),daemon=True))
    if not threads: print("no ports configured"); import time; time.sleep(3600); raise SystemExit
    for t in threads: t.start()
    print(f"listening tcp={a.tcp} udp={a.udp}", flush=True)
    for t in threads: t.join()

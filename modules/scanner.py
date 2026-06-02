import subprocess, re

def port_scan(dc_ip):
    portlar = "53,88,135,139,389,445,464,636,3268,3269,5985"
    servisler = {
        53:"DNS", 88:"Kerberos", 135:"RPC", 139:"NetBIOS",
        389:"LDAP", 445:"SMB", 464:"Kpasswd", 636:"LDAPS",
        3268:"Global Catalog", 3269:"GC-SSL", 5985:"WinRM"
    }
    sonuc = {"dc_ip": dc_ip, "ports": [], "services": {}}
    try:
        cmd = ["nmap", "-p", portlar, "--open", "-T4", dc_ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        for m in re.finditer(r'(\d+)/tcp\s+open', r.stdout):
            p = int(m.group(1))
            sonuc["ports"].append(p)
            sonuc["services"][p] = servisler.get(p, str(p))
    except FileNotFoundError:
        import socket
        for p in [int(x) for x in portlar.split(",")]:
            try:
                s = socket.socket()
                s.settimeout(1)
                if s.connect_ex((dc_ip, p)) == 0:
                    sonuc["ports"].append(p)
                    sonuc["services"][p] = servisler.get(p, str(p))
                s.close()
            except: pass
    except subprocess.TimeoutExpired: pass
    return sonuc

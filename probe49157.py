#!/usr/bin/env python3
# i49157: probe registry.yibuapi.com (54.36.150.244) from GitHub-hosted runner:
#   - direct TCP 80/443/5000 + HTTPS/HTTP /v2/
#   - two-hop via operator Squid 40.160.68.125:3128 (OVH source) CONNECT + absolute-URI
import os, socket, ssl, time, urllib.request

TOPIC = os.environ.get("TOPIC","i49157-registry")
SQ_HOST, SQ_PORT = "40.160.68.125", 3128
REG = "registry.yibuapi.com"
REGIP = "54.36.150.244"
buf=[]
def L(*a):
    line=" ".join(str(x) for x in a); print(line, flush=True); buf.append(line)
def send(tag,text):
    text=str(text)
    for i in range(0,len(text),3400):
        try:
            req=urllib.request.Request("https://ntfy.sh/"+TOPIC,
                data=(("[%s] "%tag+text[i:i+3400]).encode("utf-8","replace")),
                method="POST", headers={"Title":("i49157-"+tag)[:60]})
            urllib.request.urlopen(req,timeout=12).read()
        except Exception as e:
            L("NTFYERR",str(e)[:80])
def egress():
    for u in ("https://api.ipify.org","https://icanhazip.com","https://ifconfig.me/ip"):
        try: return urllib.request.urlopen(u,timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"
def tcp(host,port,t=7.0):
    st=time.time()
    try:
        s=socket.create_connection((host,port),timeout=t); s.close()
        return "OPEN:%dms"%round((time.time()-st)*1000)
    except ConnectionRefusedError: return "REFUSED"
    except socket.timeout: return "TIMEOUT"
    except Exception as e: return "ERR:"+str(e)[:50]
def https_direct(host,path="/v2/",t=12):
    try:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        req=urllib.request.Request("https://%s%s"%(host,path),headers={"User-Agent":"curl/8.0"})
        r=urllib.request.urlopen(req,timeout=t,context=ctx)
        body=r.read(600)
        return "HTTP %s | hdrs=%s | body=%s"%(r.status, dict(r.headers).get("Www-Authenticate","-"), body[:200].decode("latin1","replace"))
    except Exception as e:
        return "ERR:"+type(e).__name__+":"+str(e)[:100]
def http_direct(host,path="/v2/",t=12):
    try:
        req=urllib.request.Request("http://%s%s"%(host,path),headers={"User-Agent":"curl/8.0"})
        r=urllib.request.urlopen(req,timeout=t)
        body=r.read(600)
        return "HTTP %s | hdrs=%s | body=%s"%(r.status, dict(r.headers).get("Www-Authenticate","-"), body[:200].decode("latin1","replace"))
    except Exception as e:
        return "ERR:"+type(e).__name__+":"+str(e)[:100]
def squid_connect(host,port,tmo=12):
    try:
        s=socket.create_connection((SQ_HOST,SQ_PORT),timeout=tmo); s.settimeout(tmo)
    except Exception as e:
        return "SQ_TCPFAIL:"+str(e)[:60], None
    try:
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: curl/8.0\r\n\r\n"%(host,port,host,port)).encode())
        data=b""
        while b"\r\n\r\n" not in data and len(data)<2000:
            c=s.recv(1024)
            if not c: break
            data+=c
        first=data.split(b"\r\n")[0].decode("latin1") if data else "(noresp)"
        if " 200" in first: return first,s
        s.close(); return first,None
    except Exception as e:
        try: s.close()
        except: pass
        return "CONNECTERR:"+str(e)[:60],None
def tls_get_over(tunnel,host,path="/v2/",t=12):
    try:
        ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        ss=ctx.wrap_socket(tunnel,server_hostname=host)
        ss.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"%(path,host)).encode())
        data=b""
        while len(data)<1500:
            try: c=ss.recv(2048)
            except: break
            if not c: break
            data+=c
        ss.close()
        return data[:900].decode("latin1","replace")
    except Exception as e:
        return "TLSGETERR:"+type(e).__name__+":"+str(e)[:100]
def squid_absget(url,tmo=12):
    try:
        s=socket.create_connection((SQ_HOST,SQ_PORT),timeout=tmo); s.settimeout(tmo)
        host=url.split('/')[2]
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: curl/8.0\r\n\r\n"%(url,host)).encode())
        data=b""
        while len(data)<900:
            try: c=s.recv(2048)
            except: break
            if not c: break
            data+=c
        s.close()
        return data[:600].decode("latin1","replace")
    except Exception as e:
        return "ABSGETERR:"+str(e)[:80]

def main():
    L("=== i49157 registry probe start ===")
    ip=egress(); L("runner_egress",ip); send("egress",ip)
    # A) direct TCP from runner
    for port in (80,443,5000):
        st=tcp(REGIP,port); L("DIRECT",REGIP,port,st); send("direct","%s:%d = %s"%(REGIP,port,st))
    # B) direct HTTP(S) /v2/
    L("HTTPS /v2/:", https_direct(REG)); send("https_v2", https_direct(REG)[:300])
    L("HTTP  /v2/:", http_direct(REG)); send("http_v2", http_direct(REG)[:300])
    # C) via Squid (OVH source 40.160.68.125)
    stq=tcp(SQ_HOST,SQ_PORT); L("SQUID tcp",SQ_HOST,SQ_PORT,stq); send("squid_tcp","%s:3128 = %s"%(SQ_HOST,stq))
    if stq.startswith("OPEN"):
        # validate squid works
        v=squid_absget("http://api.ipify.org/"); L("SQ absget ipify:",v.replace("\r"," ").replace("\n"," | ")[:200]); send("sq_validate",v[:150])
        # CONNECT registry:443 then TLS GET /v2/
        c1,t1=squid_connect(REG,443); L("SQ CONNECT 443:",c1); send("sq_connect443",c1[:150])
        if t1:
            r=tls_get_over(t1,REG,"/v2/"); L("SQ TLS GET /v2/:",r.replace("\r"," ").replace("\n"," | ")[:500]); send("sq_tls_v2",r[:400])
        # CONNECT registry:80 then GET /v2/
        c2,t2=squid_connect(REG,80); L("SQ CONNECT 80:",c2); send("sq_connect80",c2[:150])
        if t2:
            try:
                t2.sendall(("GET /v2/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"%REG).encode())
                data=b""
                while len(data)<900:
                    c=t2.recv(2048)
                    if not c: break
                    data+=c
                L("SQ CONNECT80 GET /v2/:",data[:600].decode("latin1","replace").replace("\r"," ").replace("\n"," | "))
                send("sq80_v2",data[:400].decode("latin1","replace"))
            except Exception as e: L("sq80 err",str(e)[:80])
    print("\n".join(buf))

main()

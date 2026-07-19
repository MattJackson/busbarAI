import sys, urllib.request, json
url=sys.argv[1]; n=int(sys.argv[2])
body=json.dumps({"model":"bench-pool","messages":[{"role":"user","content":"ping"}],"max_tokens":16}).encode()
def hit():
    req=urllib.request.Request(url,data=body,headers={"content-type":"application/json"})
    r=urllib.request.urlopen(req,timeout=5); r.read(); return r.headers.get("Server-Timing","")
for _ in range(300):
    try: hit()
    except Exception as e: pass
durs=[]
for _ in range(n):
    try:
        st=hit()
        for p in st.split(","):
            if "busbar" in p and "dur=" in p: durs.append(float(p.split("dur=")[1]))
    except Exception: pass
durs.sort()
if not durs: print(json.dumps({"error":"no busbar;dur header","n":0})); sys.exit(0)
pc=lambda p: durs[min(len(durs)-1,int(len(durs)*p))]
print(json.dumps({"n":len(durs),"p50_us":round(pc(.5)*1000,1),"p90_us":round(pc(.9)*1000,1),"p99_us":round(pc(.99)*1000,1),"max_us":round(durs[-1]*1000,1)}))

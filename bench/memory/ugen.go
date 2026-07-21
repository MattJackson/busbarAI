package main
import ("bytes";"flag";"fmt";"io";"net/http";"sort";"strings";"sync";"sync/atomic";"time")
type hdrs []string
func(h *hdrs)String()string{return strings.Join(*h,",")}
func(h *hdrs)Set(v string)error{*h=append(*h,v);return nil}
func main(){
 url:=flag.String("url","","");model:=flag.String("model","gpt-4o-mini","");auth:=flag.String("auth","sk-dummy","")
 conc:=flag.Int("c",200,"");dur:=flag.Int("d",12,"");psize:=flag.Int("psize",0,"pad content to N bytes")
 var extra hdrs; flag.Var(&extra,"H","extra request header 'Key: Value' (repeatable)"); flag.Parse()
 pad:=strings.Repeat("x",*psize)
 var ok,fail int64; var mu sync.Mutex; lat:=[]float64{}
 deadline:=time.Now().Add(time.Duration(*dur)*time.Second)
 tr:=&http.Transport{MaxIdleConns:0,MaxIdleConnsPerHost:*conc,MaxConnsPerHost:*conc}
 cl:=&http.Client{Transport:tr,Timeout:30*time.Second}
 var wg sync.WaitGroup
 for w:=0;w<*conc;w++{wg.Add(1);go func(id int){defer wg.Done();n:=0
  for time.Now().Before(deadline){n++
   body:=[]byte(fmt.Sprintf(`{"model":"%s","messages":[{"role":"user","content":"u-%d-%d-%s"}],"max_tokens":16}`,*model,id,n,pad))
   st:=time.Now();req,_:=http.NewRequest("POST",*url,bytes.NewReader(body));req.Header.Set("content-type","application/json");req.Header.Set("authorization","Bearer "+*auth)
   for _,h:=range extra{if i:=strings.Index(h,":");i>0{req.Header.Set(strings.TrimSpace(h[:i]),strings.TrimSpace(h[i+1:]))}}
   resp,err:=cl.Do(req);if err!=nil{atomic.AddInt64(&fail,1);continue}
   io.Copy(io.Discard,resp.Body);resp.Body.Close()
   if resp.StatusCode==200{atomic.AddInt64(&ok,1)}else{atomic.AddInt64(&fail,1)}
   ms:=float64(time.Since(st).Microseconds())/1000.0;mu.Lock();lat=append(lat,ms);mu.Unlock()}}(w)}
 wg.Wait()
 sort.Float64s(lat);p:=func(q float64)float64{if len(lat)==0{return 0};return lat[int(float64(len(lat))*q)]}
 // ms for humans; us (integer microseconds) for sub-ms precision the perf suite parses.
 fmt.Printf("rps=%d fail=%d p50=%.2f p99=%.2f p50us=%d p99us=%d ok=%d\n",
   int64(float64(ok)/float64(*dur)),fail,p(0.5),p(0.99),int64(p(0.5)*1000),int64(p(0.99)*1000),ok)
}

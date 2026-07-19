package main
import ("bytes";"flag";"fmt";"io";"net/http";"sort";"sync";"sync/atomic";"time")
func main(){
 url:=flag.String("url","",""); model:=flag.String("model","gpt-4o-mini",""); auth:=flag.String("auth","sk-dummy","")
 conc:=flag.Int("c",200,""); dur:=flag.Int("d",12,""); flag.Parse()
 var ok,fail int64
 tr:=&http.Transport{MaxIdleConns:40000,MaxIdleConnsPerHost:40000,MaxConnsPerHost:0,IdleConnTimeout:60*time.Second}
 client:=&http.Client{Transport:tr,Timeout:30*time.Second}
 stop:=time.Now().Add(time.Duration(*dur)*time.Second)
 var ctr int64; lats:=make([][]float64,*conc); var wg sync.WaitGroup
 for i:=0;i<*conc;i++{ wg.Add(1)
  go func(id int){ defer wg.Done(); ls:=make([]float64,0,8192)
   for time.Now().Before(stop){
    n:=atomic.AddInt64(&ctr,1)
    body:=[]byte(fmt.Sprintf(`{"model":"%s","messages":[{"role":"user","content":"u-%d-%d"}],"max_tokens":16}`,*model,id,n))
    t0:=time.Now()
    req,_:=http.NewRequest("POST",*url,bytes.NewReader(body))
    req.Header.Set("content-type","application/json"); req.Header.Set("authorization","Bearer "+*auth)
    resp,err:=client.Do(req)
    if err!=nil{atomic.AddInt64(&fail,1);continue}
    io.Copy(io.Discard,resp.Body); resp.Body.Close()
    if resp.StatusCode==200{atomic.AddInt64(&ok,1)}else{atomic.AddInt64(&fail,1)}
    ls=append(ls,float64(time.Since(t0).Microseconds())/1000.0)
   }
   lats[id]=ls
  }(i) }
 wg.Wait()
 all:=[]float64{}; for _,l:=range lats{all=append(all,l...)}; sort.Float64s(all)
 total:=ok+fail; rps:=float64(total)/float64(*dur)
 p:=func(q float64)float64{ if len(all)==0{return 0}; return all[int(float64(len(all))*q)] }
 fmt.Printf("rps=%.0f ok=%d fail=%d p50=%.2fms p99=%.2fms\n",rps,ok,fail,p(.5),p(.99))
}

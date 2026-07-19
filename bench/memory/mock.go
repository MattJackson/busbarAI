package main
import ("flag";"io";"net/http")
func main(){
 port:=flag.String("port","8000","");flag.Parse()
 resp:=[]byte(`{"id":"chatcmpl-x","object":"chat.completion","created":1,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`)
 h:=func(w http.ResponseWriter,r *http.Request){io.Copy(io.Discard,r.Body);r.Body.Close();w.Header().Set("content-type","application/json");w.WriteHeader(200);w.Write(resp)}
 http.HandleFunc("/",h)
 srv:=&http.Server{Addr:":"+*port}; srv.ListenAndServe()
}

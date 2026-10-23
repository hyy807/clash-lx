package route

import (
	"context"
	"encoding/pem"
	stdhttp "net/http"
	stdtest "net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/component/ca"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestUnifiedDelayKeepsFirstAnswerWhenSecondHEADTimesOut(t *testing.T) {
	previous := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(true)
	defer adapter.UnifiedDelay.Store(previous)
	var calls atomic.Int32
	server := stdtest.NewTLSServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(stdhttp.StatusNoContent)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := ca.AddCertificate(string(cert)); err != nil {
		t.Fatal(err)
	}
	proxy := adapter.NewProxy(outbound.NewDirect())
	req := httptest.NewRequest(http.MethodGet, "/proxies/x/delay?timeout=200&url="+server.URL+"&expected=200-299", nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxKeyProxy, proxy))
	rec := httptest.NewRecorder()
	getProxyDelay(rec, req)
	record, alive, _, ok := proxy.LastURLTestRecord(server.URL)
	if rec.Code != http.StatusOK {
		t.Fatalf("first HEAD succeeded but REST returned %d %s; record=%+v alive=%t", rec.Code, rec.Body.String(), record, alive)
	}
	if !ok || !alive || record.Delay == 0 || record.Delay >= 150 {
		t.Fatalf("first response timing was lost: %+v alive=%t", record, alive)
	}
}

func TestUnifiedDelayDoesNotRepeatPlainHTTP(t *testing.T) {
	previous := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(true)
	defer adapter.UnifiedDelay.Store(previous)
	var calls atomic.Int32
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		calls.Add(1)
		w.WriteHeader(stdhttp.StatusNoContent)
	}))
	defer server.Close()
	rec := delayRequest(t, server.URL, "200-299")
	if rec.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("HTTP probe: status=%d HEAD requests=%d", rec.Code, calls.Load())
	}
}

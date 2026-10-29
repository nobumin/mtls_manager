package acmeserver

import (
	"net/http"
	"time"
)

// pathFederationBundle はトラストバンドル（連携版）の配布先。
const pathFederationBundle = "/federation/bundle"

// handleFederationBundle はトラストバンドル（中間 CA の鍵で署名した JWS）を返す。内容は公開情報だが、
// mtls-agent は自分のルート CA で検証する TLS でだけ取得し、さらに署名を確かめる（設計 8-1）。
func (s *Server) handleFederationBundle(w http.ResponseWriter, r *http.Request) {
	if s.fed == nil {
		http.NotFound(w, r)
		return
	}
	compact, etag, err := s.fed.Current(time.Now())
	if err != nil {
		s.log.Error("トラストバンドルを作れない", "err", err)
		http.Error(w, "トラストバンドルを作れない", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/jose")
	_, _ = w.Write([]byte(compact))
}

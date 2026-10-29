package acmeserver

import (
	"fmt"
	"net/http"

	"github.com/nobumin/mtls_manager/internal/store"
)

const errNS = "urn:ietf:params:acme:error:"

// problem は RFC 7807 形式のエラー（RFC 8555 §6.7）。
type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status,omitempty"`
}

func (p *problem) Error() string { return p.Type + ": " + p.Detail }

func newProblem(status int, typ, format string, args ...any) *problem {
	return &problem{Type: errNS + typ, Detail: fmt.Sprintf(format, args...), Status: status}
}

func malformed(format string, args ...any) *problem {
	return newProblem(http.StatusBadRequest, "malformed", format, args...)
}

func unauthorized(format string, args ...any) *problem {
	return newProblem(http.StatusForbidden, "unauthorized", format, args...)
}

func notFound(what string) *problem {
	return newProblem(http.StatusNotFound, "malformed", "%s が見つからない", what)
}

func serverInternal(format string, args ...any) *problem {
	return newProblem(http.StatusInternalServerError, "serverInternal", format, args...)
}

func (p *problem) stored() *store.Problem {
	return &store.Problem{Type: p.Type, Detail: p.Detail}
}

func fromStored(sp *store.Problem) *problem {
	if sp == nil {
		return nil
	}
	return &problem{Type: sp.Type, Detail: sp.Detail}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func unb64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Control-socket RPC methods. This is trusted local IPC over a 0600 Unix
// socket (see ctlsocket package).
const (
	MethodListRPs         = "ListRPs"
	MethodListCreds       = "ListCreds"
	MethodDeleteCred      = "DeleteCred"
	MethodPINStatus       = "PINStatus"
	MethodSetPIN          = "SetPIN"
	MethodChangePIN       = "ChangePIN"
	MethodResetPINRetries = "ResetPINRetries"
)

type CredentialInfo struct {
	CredentialID string `json:"credential_id"` // base64
	RPID         string `json:"rp_id"`
	UserName     string `json:"user_name"`
	SignCount    uint32 `json:"sign_count"`
}

type PINStatusResult struct {
	IsSet       bool   `json:"is_set"`
	RetriesLeft int    `json:"retries_left"`
	AuthMethod  string `json:"auth_method"`
}

type deleteCredParams struct {
	RPID         string `json:"rp_id"`
	CredentialID string `json:"credential_id"` // base64
}

// handleCtlRequest is the ctlsocket.Handler for this server: dispatches by
// method name to the resident store directly.
func (s *server) handleCtlRequest(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case MethodListRPs:
		return s.resident.RPIDs(), nil

	case MethodListCreds:
		var p struct {
			RPID string `json:"rp_id"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		creds := s.resident.ByRPID(p.RPID)
		out := make([]CredentialInfo, 0, len(creds))
		for _, c := range creds {
			out = append(out, CredentialInfo{
				CredentialID: b64(c.CredentialID),
				RPID:         c.RPID,
				UserName:     c.UserName,
				SignCount:    c.SignCount,
			})
		}
		return out, nil

	case MethodDeleteCred:
		var p deleteCredParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		credID, err := unb64(p.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("invalid credential_id: %w", err)
		}
		if err := s.resident.Delete(p.RPID, credID); err != nil {
			return nil, err
		}
		return struct{}{}, nil

	case MethodPINStatus:
		return PINStatusResult{
			IsSet:       false,
			RetriesLeft: 8,
			AuthMethod:  "pam",
		}, nil

	case MethodSetPIN, MethodChangePIN, MethodResetPINRetries:
		return nil, fmt.Errorf("PIN is disabled; authentication is handled via Linux PAM")

	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

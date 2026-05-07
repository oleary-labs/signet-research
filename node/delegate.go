package node

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"signet/network"
	"signet/tss"
)

// jwtHeader is the JWT header for delegation tokens.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"` // parent key ID used for signing
}

// jwtClaims are the delegation token claims.
type jwtClaims struct {
	Iss            string `json:"iss"`              // group address
	Sub            string `json:"sub"`              // sub-key ID (the delegated key)
	Kid            string `json:"kid"`              // parent key ID (the signing key)
	Grp            string `json:"grp"`              // group address (redundant with iss, for clarity)
	Exp            int64  `json:"exp"`              // expiry timestamp
	Iat            int64  `json:"iat"`              // issued-at timestamp
	ParentKeyPub   string `json:"parent_key_pub"`   // hex-encoded parent key public key
}

// handleDelegate mints a delegation token for a sub-key, signed by a parent key.
//
// POST /v1/delegate
//
//	{"group_id":"0x...","key_id":"<sub_key_id>","parent_key_id":"<parent_key_id>",
//	 "expires_in":2592000,
//	 "session_pub":"02...","request_sig":"hex64","nonce":"hex","timestamp":123}
func (n *Node) handleDelegate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID      string `json:"group_id"`
		KeyID        string `json:"key_id"`        // sub-key to delegate
		KeySuffix    string `json:"key_suffix"`     // alternative to key_id
		ParentKeyID  string `json:"parent_key_id"`  // parent key for signing
		ExpiresIn    int64  `json:"expires_in"`     // seconds until expiry
		Curve        string `json:"curve"`          // curve of the parent key
		SessionPub   string `json:"session_pub"`
		RequestSig   string `json:"request_sig"`
		Nonce        string `json:"nonce"`
		Timestamp    uint64 `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.GroupID == "" || req.ParentKeyID == "" {
		httpError(w, http.StatusBadRequest, "group_id and parent_key_id are required")
		return
	}
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 30 * 24 * 3600 // default 30 days
	}
	if req.Curve == "" {
		req.Curve = string(CurveSecp256k1)
	}
	parentCurve := Curve(req.Curve)
	req.GroupID = strings.ToLower(req.GroupID)

	// Authenticate the user.
	n.groupsMu.RLock()
	grp, ok := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+req.GroupID)
		return
	}

	keyID := req.KeyID
	if n.auth.HasAuthPolicy(req.GroupID) {
		if req.SessionPub == "" {
			httpError(w, http.StatusUnauthorized, "authorization required (session_pub)")
			return
		}
		_, resolvedKeyID, err := n.validateSessionRequest(
			req.SessionPub, req.RequestSig,
			req.GroupID, req.KeyID, req.KeySuffix,
			req.Nonce, req.Timestamp,
			nil,
		)
		if err != nil {
			httpError(w, err.code, err.msg)
			return
		}
		keyID = resolvedKeyID
	}

	if keyID == "" {
		httpError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// Verify the sub-key exists.
	subKeyInfo, err := n.km.GetKeyInfo(req.GroupID, keyID, parentCurve)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load sub-key: "+err.Error())
		return
	}
	if subKeyInfo == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("sub-key not found: %s", keyID))
		return
	}

	// Verify the parent key exists and load its public key.
	parentInfo, err := n.km.GetKeyInfo(req.GroupID, req.ParentKeyID, parentCurve)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load parent key: "+err.Error())
		return
	}
	if parentInfo == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("parent key not found: %s", req.ParentKeyID))
		return
	}

	// Construct JWT.
	now := time.Now()
	exp := now.Add(time.Duration(req.ExpiresIn) * time.Second)

	header := jwtHeader{
		Alg: "signet-threshold",
		Typ: "JWT",
		Kid: req.ParentKeyID,
	}
	claims := jwtClaims{
		Iss:          req.GroupID,
		Sub:          keyID,
		Kid:          req.ParentKeyID,
		Grp:          req.GroupID,
		Exp:          exp.Unix(),
		Iat:          now.Unix(),
		ParentKeyPub: "0x" + hex.EncodeToString(parentInfo.GroupKey),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	// Hash the signing input — this is what gets threshold-signed.
	msgHash := sha256.Sum256([]byte(signingInput))

	// Threshold sign the JWT hash using the parent key.
	n.log.Info("delegate: signing JWT",
		zap.String("group_id", req.GroupID),
		zap.String("sub_key", keyID),
		zap.String("parent_key", req.ParentKeyID),
	)

	sortedSigners := tss.NewPartyIDSlice(grp.Members)
	nonce, err := randomNonce()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "generate nonce: "+err.Error())
		return
	}
	sessID := signSessionID(req.GroupID, req.ParentKeyID, nonce)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedSigners)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	// For ECDSA, ensure self is coordinator.
	signersForCoord := sortedSigners
	if parentCurve == CurveEcdsaSecp256k1 {
		self := tss.PartyID(n.host.Self())
		signersForCoord = make([]tss.PartyID, 0, len(sortedSigners))
		signersForCoord = append(signersForCoord, self)
		for _, s := range sortedSigners {
			if s != self {
				signersForCoord = append(signersForCoord, s)
			}
		}
	}

	if err := n.broadcastCoord(r.Context(), sortedSigners, coordMsg{
		Type:        msgSign,
		GroupID:     req.GroupID,
		KeyID:       req.ParentKeyID,
		SignNonce:   nonce,
		Signers:     signersForCoord,
		MessageHash: msgHash[:],
		Curve:       string(parentCurve),
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := n.km.RunSign(r.Context(), SignParams{
		Host:        n.host,
		SN:          sn,
		SessionID:   sessID,
		GroupID:     req.GroupID,
		KeyID:       req.ParentKeyID,
		Signers:     signersForCoord,
		MessageHash: msgHash[:],
		Curve:       parentCurve,
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, "sign JWT: "+err.Error())
		return
	}

	// Encode signature as base64url.
	sigB64 := base64.RawURLEncoding.EncodeToString(sig.Bytes())
	token := signingInput + "." + sigB64

	n.log.Info("delegate: token minted",
		zap.String("group_id", req.GroupID),
		zap.String("sub_key", keyID),
		zap.String("parent_key", req.ParentKeyID),
		zap.Int64("expires_at", exp.Unix()),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"token":      token,
		"key_id":     keyID,
		"parent_key": req.ParentKeyID,
		"expires_at": exp.Unix(),
	})
}

// VerifyDelegationToken parses and verifies a delegation JWT.
// Returns the claims if valid. Uses the parent key's stored public key
// to verify the threshold signature.
func (n *Node) VerifyDelegationToken(groupID, token string) (*jwtClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	// Verify group matches.
	if strings.ToLower(claims.Grp) != strings.ToLower(groupID) {
		return nil, fmt.Errorf("group mismatch: token=%s request=%s", claims.Grp, groupID)
	}

	// Check expiry.
	if time.Now().After(time.Unix(claims.Exp, 0)) {
		return nil, fmt.Errorf("delegation token expired")
	}

	// Load the parent key to verify signature.
	// Try common curves — the parent key could be FROST or ECDSA.
	var parentPubKey []byte
	for _, curve := range []Curve{CurveSecp256k1, CurveEcdsaSecp256k1, CurveEd25519} {
		info, err := n.km.GetKeyInfo(groupID, claims.Kid, curve)
		if err == nil && info != nil {
			parentPubKey = info.GroupKey
			break
		}
	}
	if parentPubKey == nil {
		return nil, fmt.Errorf("parent key not found: %s", claims.Kid)
	}

	// Verify signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	msgHash := sha256.Sum256([]byte(signingInput))

	// Verify based on signature length:
	// - 65 bytes = FROST Schnorr (R.x 32 + z 32 + v 1) — NOT standard, needs custom verify
	// - 64 bytes = ECDSA (r 32 + s 32) or FROST (R 32 + Z 32)
	// For ECDSA: use ecrecover to verify.
	if len(sigBytes) == 64 && len(parentPubKey) == 33 {
		// Try ECDSA recovery: try v=0 and v=1.
		for v := byte(0); v < 2; v++ {
			recSig := make([]byte, 65)
			copy(recSig, sigBytes)
			recSig[64] = v
			recovered, err := crypto.Ecrecover(msgHash[:], recSig)
			if err != nil {
				continue
			}
			// Compare recovered pubkey with parent key.
			// Convert compressed parent key to uncompressed for comparison.
			parentPub, err := crypto.DecompressPubkey(parentPubKey)
			if err != nil {
				continue
			}
			parentUncompressed := crypto.FromECDSAPub(parentPub)
			if len(recovered) == len(parentUncompressed) {
				match := true
				for i := range recovered {
					if recovered[i] != parentUncompressed[i] {
						match = false
						break
					}
				}
				if match {
					return &claims, nil
				}
			}
		}
		return nil, fmt.Errorf("ECDSA signature verification failed")
	}

	// For FROST Schnorr signatures, verify using the FROST verify path.
	// For now, accept if the signature is from a known parent key.
	// TODO: implement Schnorr signature verification for delegation tokens.
	return nil, fmt.Errorf("unsupported signature format (len=%d)", len(sigBytes))
}

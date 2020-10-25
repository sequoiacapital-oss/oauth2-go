// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package clientcredentials

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"

	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

func randJWTID() (string, error) {
	n := 36
	bytes := make([]byte, n/2)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", big.NewInt(int64(n)).SetBytes(bytes)), nil
}

func (c *tokenSource) jwtAssertionValues() (url.Values, error) {
	v := url.Values{
		"grant_type": {"client_credentials"},
	}
	pk, err := internal.ParseKey(c.conf.PrivateKey)
	if err != nil {
		return nil, err
	}

	jti, err := randJWTID()
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(time.Hour).Unix()
	if t := c.conf.JWTTokenExpirationDuration; t > 0 {
		exp = time.Now().Add(t).Unix()
	}

	claimSet := &jws.ClaimSet{
		Iss: c.conf.ClientID,
		Sub: c.conf.ClientID,
		Aud: c.conf.TokenURL,
		Jti: jti,
		Exp: exp,
	}
	h := jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     c.conf.KeyID,
	}
	payload, err := jws.Encode(&h, claimSet, pk)
	if err != nil {
		return nil, err
	}
	v.Set("client_assertion", payload)
	v.Set("client_assertion_type", clientAssertionType)

	return v, nil
}

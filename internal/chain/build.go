package chain

import (
	"crypto/x509"
	"fmt"
	"sealpath/internal/codec"
	"sealpath/internal/model"
	"sort"
	"strings"
	"time"
)

type Result struct {
	Certificates []*x509.Certificate
	IDs          []string
	Alternatives int
}

func Build(leafID string, values map[string]model.Certificate, trust model.TrustSet, at time.Time) (Result, error) {
	decoded, err := codec.DecodeCertificates(values)
	if err != nil {
		return Result{}, err
	}
	leaf, ok := decoded[leafID]
	if !ok {
		return Result{}, model.Missing("signer certificate", leafID)
	}
	if leaf.IsCA {
		return Result{}, fmt.Errorf("CA certificates cannot sign artifacts")
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	rootSet := map[string]bool{}
	for _, id := range trust.Roots {
		root, ok := decoded[id]
		if !ok {
			return Result{}, fmt.Errorf("trust root missing")
		}
		roots.AddCert(root)
		rootSet[id] = true
	}
	for id, cert := range decoded {
		if cert.IsCA && !rootSet[id] {
			intermediates.AddCert(cert)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err != nil {
		return Result{}, fmt.Errorf("certificate path is not valid: %w", err)
	}
	key := func(path []*x509.Certificate) string {
		ids := []string{}
		for _, cert := range path {
			ids = append(ids, codec.Digest(cert.Raw))
		}
		return strings.Join(ids, "/")
	}
	sort.Slice(chains, func(i, j int) bool {
		if len(chains[i]) != len(chains[j]) {
			return len(chains[i]) < len(chains[j])
		}
		return key(chains[i]) < key(chains[j])
	})
	out := Result{Certificates: chains[0], Alternatives: len(chains)}
	for _, cert := range out.Certificates {
		out.IDs = append(out.IDs, codec.Digest(cert.Raw))
	}
	return out, nil
}

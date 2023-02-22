// Taken from https://github.com/caddyserver/certmagic/blob/v0.17.2/solvers.go on 2023-02-22
// and modified for lecertvend's specific needs.
//
// Original license notice:
//
// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lecertvend

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/mholt/acmez/acme"
)

// DNS01Solver is a type that makes libdns providers usable as ACME dns-01
// challenge solvers. See https://github.com/libdns/libdns
//
// Note that challenges may be solved concurrently by some clients (such as
// acmez, which CertMagic uses), meaning that multiple TXT records may be
// created in a DNS zone simultaneously, and in some cases distinct TXT records
// may have the same name. For example, solving challenges for both example.com
// and *.example.com create a TXT record named _acme_challenge.example.com,
// but with different tokens as their values. This solver distinguishes
// between different records with the same name by looking at their values.
// DNS provider APIs and implementations of the libdns interfaces must also
// support multiple same-named TXT records.
type DNS01Solver struct {
	// The implementation that interacts with the DNS
	// provider to set or delete records. (REQUIRED)
	DNSProvider ACMEDNSProvider

	// The TTL for the temporary challenge records.
	TTL time.Duration

	// How long to wait before starting propagation checks.
	// Default: 0 (no wait).
	PropagationDelay time.Duration

	// Maximum time to wait for temporary DNS record to appear.
	// Set to -1 to disable propagation checks.
	// Default: 2 minutes.
	PropagationTimeout time.Duration

	// Preferred DNS resolver(s) to use when doing DNS lookups.
	Resolvers []string

	// Override the domain to set the TXT record on. This is
	// to delegate the challenge to a different domain. Note
	// that the solver doesn't follow CNAME/NS record.
	OverrideDomain string

	// Remember DNS records while challenges are active; i.e.
	// records we have presented and not yet cleaned up.
	// This lets us clean them up quickly and efficiently.
	// Keyed by domain name (specifically the ACME DNS name).
	// The map value is a slice because there can be multiple
	// concurrent challenges for different domains that have
	// the same ACME DNS name, for example: example.com and
	// *.example.com. We distinguish individual memories by
	// the value of their TXT records, which should contain
	// unique challenge tokens.
	// See https://github.com/caddyserver/caddy/issues/3474.
	txtRecords   map[string][]dnsPresentMemory
	txtRecordsMu sync.Mutex
}

// Present creates the DNS TXT record for the given ACME challenge.
func (s *DNS01Solver) Present(ctx context.Context, challenge acme.Challenge) error {
	dnsName := challenge.DNS01TXTRecordName()
	if s.OverrideDomain != "" {
		dnsName = s.OverrideDomain
	}
	keyAuth := challenge.DNS01KeyAuthorization()

	zone, err := findZoneByFQDN(dnsName, recursiveNameservers(s.Resolvers))
	if err != nil {
		return fmt.Errorf("could not determine zone for domain %q: %v", dnsName, err)
	}

	rec := libdns.Record{
		Type:  "TXT",
		Name:  libdns.RelativeName(dnsName+".", zone),
		Value: keyAuth,
		TTL:   s.TTL,
	}

	results, err := s.DNSProvider.AppendRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		return fmt.Errorf("adding temporary record for zone %q: %w", zone, err)
	}
	if len(results) != 1 {
		return fmt.Errorf("expected one record, got %d: %v", len(results), results)
	}

	// remember the record and zone we got so we can clean up more efficiently
	s.saveDNSPresentMemory(dnsPresentMemory{
		dnsZone: zone,
		dnsName: dnsName,
		rec:     results[0],
	})

	return nil
}

// Wait blocks until the TXT record created in Present() appears in
// authoritative lookups, i.e. until it has propagated, or until
// timeout, whichever is first.
func (s *DNS01Solver) Wait(ctx context.Context, challenge acme.Challenge) error {
	// if configured to, pause before doing propagation checks
	// (even if they are disabled, the wait might be desirable on its own)
	if s.PropagationDelay > 0 {
		select {
		case <-time.After(s.PropagationDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// skip propagation checks if configured to do so
	if s.PropagationTimeout == -1 {
		return nil
	}

	// prepare for the checks by determining what to look for
	dnsName := challenge.DNS01TXTRecordName()
	if s.OverrideDomain != "" {
		dnsName = s.OverrideDomain
	}
	keyAuth := challenge.DNS01KeyAuthorization()

	// timings
	timeout := s.PropagationTimeout
	if timeout == 0 {
		timeout = defaultDNSPropagationTimeout
	}
	const interval = 2 * time.Second

	// how we'll do the checks
	resolvers := recursiveNameservers(s.Resolvers)

	var err error
	start := time.Now()
	for time.Since(start) < timeout {
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return ctx.Err()
		}
		var ready bool
		ready, err = checkDNSPropagation(dnsName, keyAuth, resolvers)
		if err != nil {
			return fmt.Errorf("checking DNS propagation of %q: %w", dnsName, err)
		}
		if ready {
			return nil
		}
	}

	return fmt.Errorf("timed out waiting for record to fully propagate; verify DNS provider configuration is correct - last error: %v", err)
}

// CleanUp deletes the DNS TXT record created in Present().
//
// We ignore the context because cleanup is often/likely performed after
// a context cancellation, and properly-implemented DNS providers should
// honor cancellation, which would result in cleanup being aborted.
// Cleanup must always occur.
func (s *DNS01Solver) CleanUp(_ context.Context, challenge acme.Challenge) error {
	dnsName := challenge.DNS01TXTRecordName()
	if s.OverrideDomain != "" {
		dnsName = s.OverrideDomain
	}
	keyAuth := challenge.DNS01KeyAuthorization()

	// always forget about the record so we don't leak memory
	defer s.deleteDNSPresentMemory(dnsName, keyAuth)

	// recall the record we created and zone we looked up
	memory, err := s.getDNSPresentMemory(dnsName, keyAuth)
	if err != nil {
		return err
	}

	// clean up the record - use a different context though, since
	// one common reason cleanup is performed is because a context
	// was canceled, and if so, any HTTP requests by this provider
	// should fail if the provider is properly implemented
	// (see issue #200)
	timeout := s.PropagationTimeout
	if timeout <= 0 {
		timeout = defaultDNSPropagationTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err = s.DNSProvider.DeleteRecords(ctx, memory.dnsZone, []libdns.Record{memory.rec})
	if err != nil {
		return fmt.Errorf("deleting temporary record for name %q in zone %q: %w", memory.dnsName, memory.dnsZone, err)
	}

	return nil
}

const defaultDNSPropagationTimeout = 2 * time.Minute

type dnsPresentMemory struct {
	dnsZone string
	dnsName string
	rec     libdns.Record
}

func (s *DNS01Solver) saveDNSPresentMemory(mem dnsPresentMemory) {
	s.txtRecordsMu.Lock()
	if s.txtRecords == nil {
		s.txtRecords = make(map[string][]dnsPresentMemory)
	}
	s.txtRecords[mem.dnsName] = append(s.txtRecords[mem.dnsName], mem)
	s.txtRecordsMu.Unlock()
}

func (s *DNS01Solver) getDNSPresentMemory(dnsName, keyAuth string) (dnsPresentMemory, error) {
	s.txtRecordsMu.Lock()
	defer s.txtRecordsMu.Unlock()

	var memory dnsPresentMemory
	for _, mem := range s.txtRecords[dnsName] {
		if mem.rec.Value == keyAuth {
			memory = mem
			break
		}
	}

	if memory.rec.Name == "" {
		return dnsPresentMemory{}, fmt.Errorf("no memory of presenting a DNS record for %q (usually OK if presenting also failed)", dnsName)
	}

	return memory, nil
}

func (s *DNS01Solver) deleteDNSPresentMemory(dnsName, keyAuth string) {
	s.txtRecordsMu.Lock()
	defer s.txtRecordsMu.Unlock()

	for i, mem := range s.txtRecords[dnsName] {
		if mem.rec.Value == keyAuth {
			s.txtRecords[dnsName] = append(s.txtRecords[dnsName][:i], s.txtRecords[dnsName][i+1:]...)
			return
		}
	}
}

// ACMEDNSProvider defines the set of operations required for
// ACME challenges. A DNS provider must be able to append and
// delete records in order to solve ACME challenges. Find one
// you can use at https://github.com/libdns. If your provider
// isn't implemented yet, feel free to contribute!
type ACMEDNSProvider interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

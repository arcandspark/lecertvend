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

	// Zone name in which to create records
	Zone string

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
	if len(s.Zone) == 0 {
		return fmt.Errorf("Zone property of DNS01Solver required")
	}
	if s.TTL == 0 {
		s.TTL = 60 * time.Second
	}
	if s.PropagationDelay == 0 {
		s.PropagationDelay = 30 * time.Second
	}

	dnsName := challenge.DNS01TXTRecordName()
	keyAuth := challenge.DNS01KeyAuthorization()

	rec := libdns.Record{
		Type:  "TXT",
		Name:  libdns.RelativeName(dnsName+".", s.Zone),
		Value: keyAuth,
		TTL:   s.TTL,
	}

	results, err := s.DNSProvider.AppendRecords(ctx, s.Zone, []libdns.Record{rec})
	if err != nil {
		return fmt.Errorf("adding temporary record for zone %q: %w", s.Zone, err)
	}
	if len(results) != 1 {
		return fmt.Errorf("expected one record, got %d: %v", len(results), results)
	}

	// remember the record and zone we got so we can clean up more efficiently
	s.saveDNSPresentMemory(dnsPresentMemory{
		dnsZone: s.Zone,
		dnsName: dnsName,
		rec:     results[0],
	})

	return nil
}

func (s *DNS01Solver) Wait(ctx context.Context, challenge acme.Challenge) error {
	_ = <-time.After(s.PropagationDelay)
	return nil
}

// CleanUp deletes the DNS TXT record created in Present().
func (s *DNS01Solver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	dnsName := challenge.DNS01TXTRecordName()
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
	_, err = s.DNSProvider.DeleteRecords(ctx, memory.dnsZone, []libdns.Record{memory.rec})
	if err != nil {
		return fmt.Errorf("deleting temporary record for name %q in zone %q: %w", memory.dnsName, memory.dnsZone, err)
	}

	return nil
}

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

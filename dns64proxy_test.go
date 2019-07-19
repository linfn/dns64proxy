package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestIPv4To6(t *testing.T) {
	ip := func(s string) net.IP {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatal("invalid ip address", s)
		}
		return ip
	}

	items := [][]string{
		{"2001:db8::/32", "192.0.2.33", "2001:db8:c000:221::"},
		{"2001:db8:100::/40", "192.0.2.33", "2001:db8:1c0:2:21::"},
		{"2001:db8:122::/48", "192.0.2.33", "2001:db8:122:c000:2:2100::"},
		{"2001:db8:122:300::/56", "192.0.2.33", "2001:db8:122:3c0:0:221::"},
		{"2001:db8:122:344::/64", "192.0.2.33", "2001:db8:122:344:c0:2:2100::"},
		{"2001:db8:122:344::/96", "192.0.2.33", "2001:db8:122:344::192.0.2.33"},
		{"64:ff9b::/96", "192.0.2.33", "64:ff9b::192.0.2.33"},
	}

	for _, item := range items {
		_, prefix, err := net.ParseCIDR(item[0])
		if err != nil {
			t.Error(err, item[0])
			continue
		}
		result := ip4to6(prefix, ip(item[1]).To4())
		want := ip(item[2])
		if !result.Equal(want) {
			t.Error("want", want.String(), "but result is", result.String())
		}
	}
}

const network = "udp"

func startUpstream(t *testing.T, addr string, good bool) (close func()) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		defer w.Close()
		resp := dns.Msg{}
		if !good {
			resp.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(&resp)
			return
		}
		q := r.Question[0]
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
			if q.Name == "ipv4.example.com." {
				rr, err := dns.NewRR(q.Name + " IN A 127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				resp.Answer = append(resp.Answer, rr)
			}
		}
		if q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY {
			if q.Name == "ipv6.example.com." {
				rr, err := dns.NewRR(q.Name + " IN AAAA ::1")
				if err != nil {
					t.Fatal(err)
				}
				resp.Answer = append(resp.Answer, rr)
			}
		}
		resp.SetReply(r)
		w.WriteMsg(&resp)
	})
	s := &dns.Server{
		Addr:    addr,
		Net:     network,
		Handler: mux,
	}
	go func() {
		err := s.ListenAndServe()
		if err != nil {
			t.Fatal(err)
		}
	}()
	return func() {
		s.Shutdown()
	}
}

func query(addr string, name string) (*dns.AAAA, error) {
	client := dns.Client{
		ReadTimeout: 3 * time.Second,
		Net:         network,
	}
	msg := dns.Msg{}
	msg.SetQuestion(name, dns.TypeAAAA)
	r, _, err := client.Exchange(&msg, addr)
	if err != nil {
		return nil, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, rcoderr(r.Rcode)
	}
	if len(r.Answer) == 0 {
		return nil, errors.New("no AAAA record")
	}
	aaaa, ok := r.Answer[0].(*dns.AAAA)
	if !ok {
		return nil, errors.New("not a AAAA record")
	}
	return aaaa, nil
}

func TestDNSWithPrefix(t *testing.T) {
	defer startUpstream(t, ":15353", false)()
	defer startUpstream(t, ":15354", true)()
	addr := "localhost:53533"
	srv := Server{
		Config: Config{
			Address:     ":53533",
			Network:     network,
			NameServers: []string{"localhost:15353", "localhost:15354"},
			IPv6Prefix:  "64:ff9b::/96",
		},
	}
	go func() {
		err := srv.Serve()
		if err != nil {
			t.Fatal(err)
		}
	}()
	defer srv.Shutdown()

	// Waiting for the server to be ready
	time.Sleep(1 * time.Second)

	_, err := query(addr, "ipv6.example.com.")
	if err != nil {
		t.Error(err)
	}

	aaaa, err := query(addr, "ipv4.example.com.")
	if err != nil {
		t.Error(err)
	} else if !aaaa.AAAA.Equal(ip4to6(srv.ipv6prefix, net.ParseIP("127.0.0.1").To4())) {
		t.Error("64 prefix not match", aaaa.AAAA.String())
	}
}

func startUpstream64(t *testing.T, addr string) (close func()) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		defer w.Close()
		resp := dns.Msg{}
		q := r.Question[0]
		if q.Qtype == dns.TypeAAAA {
			rr, err := dns.NewRR(q.Name + " IN AAAA 64:ff9b::1")
			if err != nil {
				t.Fatal(err)
			}
			resp.Answer = append(resp.Answer, rr)
		}
		resp.SetReply(r)
		w.WriteMsg(&resp)
	})
	s := &dns.Server{
		Addr:    addr,
		Net:     network,
		Handler: mux,
	}
	go func() {
		err := s.ListenAndServe()
		if err != nil {
			t.Fatal(err)
		}
	}()
	return func() {
		s.Shutdown()
	}
}

func TestDNSWithDNS64Upstream(t *testing.T) {
	defer startUpstream(t, ":15355", true)()
	defer startUpstream64(t, ":16464")()
	addr := "localhost:53533"
	srv := Server{
		Config: Config{
			Address:      ":53533",
			Network:      network,
			NameServers:  []string{"localhost:15355"},
			DNS64Servers: []string{"localhost:16464"},
		},
	}
	go func() {
		err := srv.Serve()
		if err != nil {
			t.Fatal(err)
		}
	}()
	defer srv.Shutdown()

	// Waiting for the server to be ready
	time.Sleep(1 * time.Second)

	_, err := query(addr, "ipv6.example.com.")
	if err != nil {
		t.Error(err)
	}
	_, err = query(addr, "ipv4.example.com.")
	if err != nil {
		t.Error(err)
	}
}

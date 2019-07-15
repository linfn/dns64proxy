package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
	yaml "gopkg.in/yaml.v2"
)

const defaultInterval = 500 * time.Millisecond

var defaultIPv6Prefix *net.IPNet

func init() {
	var err error
	_, defaultIPv6Prefix, err = net.ParseCIDR("64:ff9b::/96")
	if err != nil {
		panic(err)
	}
}

type Config struct {
	Verbose      bool     `yaml:"verbose"`
	Network      string   `yaml:"network"`
	Address      string   `yaml:"address"`
	NameServers  []string `yaml:"nameserver"`
	IPv6Prefix   string   `yaml:"prefix"`
	DNS64Servers []string `yaml:"dns64server"`
	Timeout      int      `yaml:"timeout"`
	Interval     int      `yaml:"interval"`
}

type Server struct {
	Config
	ipv6prefix *net.IPNet
	server     *dns.Server
	client     *dns.Client
}

func getNameServers(ns []string) []string {
	result := make([]string, len(ns))
	for i, ns := range ns {
		_, _, err := net.SplitHostPort(ns)
		if err == nil {
			result[i] = ns
		} else {
			result[i] = net.JoinHostPort(ns, "53")
		}
	}
	return result
}

func (s *Server) Serve() error {
	s.NameServers = getNameServers(s.NameServers)
	s.DNS64Servers = getNameServers(s.DNS64Servers)
	if s.Network == "" {
		s.Network = "udp"
	}
	if s.IPv6Prefix != "" {
		_, prefix, err := net.ParseCIDR("64:ff9b::/96")
		if err != nil {
			return err
		}
		s.ipv6prefix = prefix
	} else {
		s.ipv6prefix = defaultIPv6Prefix
	}
	s.client = &dns.Client{
		Net:     s.Network,
		Timeout: time.Duration(s.Timeout) * time.Millisecond,
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handleDNSRequest)
	s.server = &dns.Server{
		Addr:    s.Address,
		Net:     s.Network,
		Handler: mux,
	}
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown() error {
	return s.server.Shutdown()
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	defer w.Close()
	start := time.Now()
	resp, ns, err := s.query(r)
	elapsed := fmt.Sprintf("+%v", time.Since(start))
	if err != nil {
		var name string
		if len(r.Question) > 0 {
			name = r.Question[0].Name
		}
		log.Println("ERROR:", elapsed, name, ns, err)
		resp = new(dns.Msg)
		if rcode, ok := err.(rcoderr); ok {
			resp.SetRcode(r, int(rcode))
		} else {
			resp.SetRcode(r, dns.RcodeServerFailure)
		}
	} else {
		if s.Verbose {
			log.Println(elapsed, ns, resp)
		}
	}
	w.WriteMsg(resp)
}

func hasQuestion(m *dns.Msg, typ uint16) bool {
	for i := range m.Question {
		if m.Question[i].Qtype == typ {
			return true
		}
	}
	return false
}

func hasAnswer(m *dns.Msg, typ uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == typ {
			return true
		}
	}
	return false
}

func (s *Server) query(req *dns.Msg) (resp *dns.Msg, ns string, err error) {
	resp, ns, err = s.queryByNameServers(req, s.NameServers)
	if err != nil {
		return nil, ns, err
	}

	if hasQuestion(req, dns.TypeAAAA) || hasQuestion(req, dns.TypeANY) {
		if !hasAnswer(resp, dns.TypeAAAA) {
			if len(s.DNS64Servers) == 0 {
				resp, ns, err = s.doDNS64(req, resp, ns)
			} else {
				resp, ns, err = s.queryByNameServers(req, s.DNS64Servers)
			}
			if err != nil {
				return nil, ns, err
			}
		}
	}

	return resp, ns, nil
}

type rcoderr int

func (r rcoderr) Error() string {
	return dns.RcodeToString[int(r)]
}

func (s *Server) queryByNameServers(req *dns.Msg, ns []string) (resp *dns.Msg, responder string, err error) {
	nsCount := len(ns)
	if nsCount == 0 {
		return nil, "", errors.New("no nameservers")
	}

	type Answer struct {
		who string
		*dns.Msg
		error
	}

	resCh := make(chan Answer)
	done := make(chan struct{})
	defer close(done)
	job := func(req *dns.Msg, ns string) bool {
		resp, _, err := s.client.Exchange(req, ns)
		if err == nil && resp.Rcode != dns.RcodeSuccess {
			err = rcoderr(resp.Rcode)
		}
		select {
		case resCh <- Answer{ns, resp, err}:
		case <-done:
		}
		return err == nil
	}

	interval := defaultInterval
	if s.Interval != 0 {
		interval = time.Duration(s.Interval) * time.Millisecond
	}
	go func() {
		for i := 0; i < nsCount; i++ {
			ns := ns[i]
			if i != nsCount-1 {
				failed := make(chan struct{})
				go func() {
					ok := job(req, ns)
					if !ok {
						close(failed)
					}
				}()
				t := time.NewTimer(interval)
				select {
				case <-done:
					t.Stop()
					return
				case <-failed:
					t.Stop()
				case <-t.C:
				}
			} else {
				job(req, ns)
			}
		}
	}()

	counter := nsCount
	for r := range resCh {
		if r.error == nil {
			return r.Msg, r.who, nil
		}
		// record the first error
		if err == nil {
			responder, err = r.who, r.error
		}
		counter--
		if counter == 0 {
			break
		}
	}
	return nil, responder, err
}

// RFC6052 https://tools.ietf.org/html/rfc6052#section-2.2
func ip4to6(prefix *net.IPNet, ip4 net.IP) net.IP {
	ip4 = ip4.To4()
	result := make(net.IP, len(prefix.IP))
	copy(result, prefix.IP)
	ones, _ := prefix.Mask.Size()
	for i, j := ones/8, 0; i < 16; i++ {
		if i == 8 || j > 3 {
			result[i] = 0
		} else {
			result[i] = ip4[j]
			j++
		}
	}
	return result
}

func toAAAA(prefix *net.IPNet, a []dns.RR) []dns.RR {
	var aaaa []dns.RR
	for _, a := range a {
		if a, ok := a.(*dns.A); ok {
			hdr := dns.RR_Header{
				Name:   a.Hdr.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    a.Hdr.Ttl,
			}
			aaaa = append(aaaa, &dns.AAAA{
				Hdr:  hdr,
				AAAA: ip4to6(prefix, a.A),
			})
		}
	}
	return aaaa
}

func (s *Server) doDNS64(req *dns.Msg, resp *dns.Msg, ns string) (*dns.Msg, string, error) {
	aaaa := toAAAA(s.ipv6prefix, resp.Answer)
	if len(aaaa) > 0 {
		resp.Answer = append(resp.Answer, aaaa...)
		return resp, ns, nil
	}

	req = req.Copy()
	req.SetQuestion(req.Question[0].Name, dns.TypeA)
	r, ns, err := s.queryByNameServers(req, s.NameServers)
	if err != nil {
		return nil, ns, err
	}
	resp.Answer = append(resp.Answer, toAAAA(s.ipv6prefix, r.Answer)...)
	return resp, ns, nil
}

var ipv6prefixMasks = map[int]bool{
	32: true,
	40: true,
	48: true,
	56: true,
	64: true,
	96: true,
}

func checkIpv6Prefex(s string) error {
	_, prefix, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}
	ones, _ := prefix.Mask.Size()
	if !ipv6prefixMasks[ones] {
		return errors.New("prefix mask size is invaild")
	}
	if ones == 96 && prefix.IP[8] != 0 {
		return errors.New("prefix bits 64 to 71 must be zero")
	}
	return nil
}

func readConfig(file string, cfg *Config) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return err
	}
	if cfg.IPv6Prefix != "" {
		err = checkIpv6Prefex(cfg.IPv6Prefix)
		if err != nil {
			return err
		}
	}
	return nil
}

var help = flag.Bool("h", false, "help")
var configFile = flag.String("c", "dns64proxy.yaml", "config file path")
var verbose = flag.Bool("V", false, "print log")

func main() {
	flag.Parse()
	if *help {
		flag.Usage()
		return
	}

	srv := Server{}
	err := readConfig(*configFile, &srv.Config)
	if err != nil {
		log.Fatal(err)
	}
	if *verbose {
		srv.Verbose = true
	}

	log.Println("Server Starting")

	go func() {
		err := srv.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()
	defer srv.Shutdown()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Server Quit")
}

#  dns64proxy

A simple dns64 proxy.

It returns AAAA records with these synthetic IPv6 addresses for IPv4-only destinations (with A but not AAAA records in the DNS).

## Installation

```shell
go get github.com/linfn/dns64proxy
```

## Usage

```shell
dns64proxy -c dns64proxy.yaml
```

### IPv6 Prefix

The prefix can only have one of the following lengths: 32, 40, 48, 56, 64, or 96, and 64 to 71 bits must be set to zero. Read [Section 2.2 of RFC6052](https://tools.ietf.org/html/rfc6052#section-2.2) for details.

```yaml
address: ":53"
# Cloudflare Public DNS as upstream
nameserver: ["2606:4700:4700::1111", "2606:4700:4700::1001"]
# The prefix for IPv4 to IPv6
prefix: "64:ff9b::/96"
```

### Use a Public DNS64+NAT64 Service

If you are working in an IPv6-only environment and need to access both IPv4 and IPv6 network, the easiest way is to use a public DNS64+NAT64 service.

[TREX](http://www.trex.fi/2011/dns64.html) and [go6lab](https://go6lab.si/current-ipv6-tests/nat64dns64-public-test/) offer such public services. However, their servers are all in Europe, and no Anycast or GeoDNS support. 

So you can use the usual DNS server to query the AAAA record first. If no AAAA record exist, then fallback to the public dns64 servers for IPv4-only websites.

```yaml
address: ":53"
# Cloudflare Public DNS as upstream
nameserver: ["2606:4700:4700::1111", "2606:4700:4700::1001"]
# go6lab's public DNS64
dns64server: ["2001:67c:27e4:15::64", "2001:67c:27e4:15::6411"]
```

To check if it works fine, `curl` an IPv4-only website such as github.com.

```shell
curl -6 -v github.com
```


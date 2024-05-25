package vpn

import (
	"github.com/xtls/xray-core/core"
)

type ScanWorker struct {
	Instance *core.Instance
}
type Log struct {
	Loglevel string `json:"loglevel"`
}

type Inbound struct {
	Port     int    `json:"port"`
	Listen   string `json:"listen"`
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Settings struct {
		Auth string `json:"auth"`
		UDP  bool   `json:"udp"`
		IP   string `json:"ip"`
	} `json:"settings"`
	Sniffing struct {
		Enabled      bool     `json:"enabled"`
		DestOverride []string `json:"destOverride"`
	} `json:"sniffing"`
}

type User struct {
	ID string `json:"id"`
}

type VNext struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Users   []User `json:"users"`
}

type WSSettings struct {
	Headers struct {
		Host string `json:"Host"`
	} `json:"headers"`
	Path string `json:"path"`
}

type TLSSettings struct {
	ServerName    string `json:"serverName"`
	AllowInsecure bool   `json:"allowInsecure"`
}

type StreamSettings struct {
	Network     *string      `json:"network"`
	Security    *string      `json:"security"`
	WSSettings  *WSSettings  `json:"wsSettings"`
	TLSSettings *TLSSettings `json:"tlsSettings"`
	Sockopt     Sockopt      `json:"sockopt"`
}

type Outbound struct {
	Protocol       string         `json:"protocol"`
	Settings       Settings       `json:"settings"`
	StreamSettings StreamSettings `json:"streamSettings"`
}

type XRay struct {
	Log       Log        `json:"log"`
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Other     struct{}   `json:"other"`
}
type Fragment struct {
	Packets  string `json:"packets"`
	Length   string `json:"length"`
	Interval string `json:"interval"`
}

type Sockopt struct {
	DialerProxy      string `json:"dialerProxy"`
	TcpKeepAliveIdle uint64 `json:"tcpKeepAliveIdle"`
	Mark             uint64 `json:"mark"`
	TcpNoDelay       *bool  `json:"tcpNoDelay"`
}

type Settings struct {
	VNext    *[]VNext  `json:"vnext"`
	Fragment *Fragment `json:"fragment"`
}

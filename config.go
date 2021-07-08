package pcap

import (
	"context"
	"github.com/rock-go/rock/lua"
	"io"
)

type Config struct {
	Name        string
	Device      string // 接口名称
	Snapshot    int    // 抓取包的最大长度
	Promiscuous string // 是否混杂模式
	Timeout     int    // 超时
}

type Packet struct {
	lua.Super
	C Config

	uptime string
	status lua.LightUserDataStatus
	cancel context.CancelFunc
}

type Transport interface {
	io.Writer
	Name() string
}

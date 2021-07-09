package pcap

import (
	"github.com/rock-go/rock/lua"
	"github.com/rock-go/rock/utils"
)

type config struct {
	name        string
	Device      string // 接口名称
	Snapshot    int    // 抓取包的最大长度
	Promiscuous string // 是否混杂模式
	Timeout     int    // 超时
}

func newConfig(L *lua.LState) *config {
	tab := L.CheckTable(1)
	cfg := &config{}

	tab.ForEach(func(key lua.LValue, val lua.LValue) {
		switch key.String() {
		case "name":
			cfg.name = utils.CheckProcName(val, L)
		case "device":
			dev, err := getDevByIP(utils.LValueToStr(val, ""))
			if err != nil {
				L.RaiseError("%v", err)
				return
			}

			cfg.Device = dev
		case "timeout":
			cfg.Timeout = utils.LValueToInt(val, 30)
		case "snapshot":
			cfg.Snapshot = utils.LValueToInt(val, 1024)
		case "promiscuous":
			cfg.Promiscuous = utils.LValueToStr(val, "off")
		default:
			L.RaiseError("not found %s key , got %s", key.String())
		}
	})

	if e := cfg.verify(); e != nil {
		L.RaiseError("%v", e)
		return nil
	}

	return cfg
}

func (cfg *config) verify() error {
	return nil
}

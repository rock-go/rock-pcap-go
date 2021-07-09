package pcap

import (
	"github.com/google/gopacket/pcap"
	"github.com/rock-go/rock/lua"
	"github.com/rock-go/rock/utils"
	"github.com/rock-go/rock/xcall"
	"reflect"
)

var PACKET = reflect.TypeOf((*Packet)(nil)).String()

func newLuaPacket(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, PACKET)
	if proc.IsNil() {
		proc.Set(newPacket(cfg))
	} else {
		proc.Value.(*Packet).cfg = cfg
	}
	L.Push(proc)
	return 1
}

func (p *Packet) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "list":
		return lua.NewFunction(p.LList)
	case "live":
		// 在线抓包,通过transport发送
		return lua.NewFunction(p.LLive)
	case "close":
		// 关闭在线抓包
		return lua.NewFunction(p.LClose)
	case "write":
		return lua.NewFunction(p.LWrite)
	case "read":
		return lua.NewFunction(p.LRead)
	}

	return lua.LNil
}

func (p *Packet) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		p.cfg.name = lua.CheckString(L, val)
	case "device":
		dev, err := getDevByIP(utils.LValueToStr(val, ""))
		if err != nil {
			L.RaiseError("%v", err)
			return
		}
		p.cfg.Device = dev
	case "snap_shot":
		p.cfg.Snapshot = lua.CheckInt(L, val)
	case "promiscuous":
		p.cfg.Promiscuous = lua.CheckString(L, val)
	case "timeout":
		p.cfg.Timeout = lua.CheckInt(L, val)
	}
}

func (p *Packet) LList(L *lua.LState) int {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		L.RaiseError("list all devices error: %v", err)
		return 0
	}

	var devices string
	for _, dev := range devs {
		var ips string
		for _, ip := range dev.Addresses {
			ips = ips + ip.IP.String() + " "
		}
		devices = devices + dev.Name + ": " + ips + "\n"
	}

	L.Push(lua.LString(devices))
	return 1
}

func (p *Packet) LLive(L *lua.LState) int {
	ud := L.CheckLightUserData(1)
	tp, ok := ud.Value.(lua.Writer)
	if !ok {
		L.RaiseError("invalid transport")
		return 0
	}

	go func(tp lua.Writer) {
		p.LiveCapture(tp)
	}(tp)

	return 0
}

func (p *Packet) LClose(L *lua.LState) int {
	if err := p.Close(); err != nil {
		L.RaiseError("pcap close live capture error: %v", err)
	}

	return 0
}

func (p *Packet) LWrite(L *lua.LState) int {
	path := L.CheckString(1)
	count := L.CheckInt(2)
	duration := L.CheckInt(3)

	go func(path string, c int, d int) {
		_ = p.PcapWrite(path, c, d)
	}(path, count, duration)

	return 0
}

func (p *Packet) LRead(L *lua.LState) int {
	path := L.CheckString(1)
	tp := lua.CheckWriter(L.CheckLightUserData(2))
	if tp == nil {
		L.RaiseError("invalid transport")
		return 0
	}

	if err := p.PcapRead(path, tp); err != nil {
		L.RaiseError("pcap  read data from file error: %v", err)
	}

	return 0
}

func LuaInjectApi(env xcall.Env) {
	env.Set("pcap", lua.NewFunction(newLuaPacket))
}

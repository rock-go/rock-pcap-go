package pcap

import "github.com/rock-go/rock/lua"

func (p *Packet) Header(out lua.Printer) {
	out.Printf("type: %s", p.Type())
	out.Printf("uptime: %s", p.U.String())
	out.Println("version: v1.0.0")
	out.Println("")
}

func (p *Packet) Show(out lua.Printer) {
	p.Header(out)

	out.Printf("name: %s", p.Name())
	out.Printf("device: %s", p.cfg.Device)
	out.Printf("snap_shot: %d", p.cfg.Snapshot)
	out.Printf("promiscuous: %s", p.cfg.Promiscuous)
	out.Printf("timeout: %d", p.cfg.Timeout)

	out.Println("")
}

func (p *Packet) Help(out lua.Printer) {
	p.Header(out)

	out.Printf(".list() 列出所有网卡设备")
	out.Printf(".live() 在线抓包")
	out.Printf(".write() 抓包保存到文件")
	out.Printf(".read() 读取离线包")
	out.Printf(".close() 关闭抓包")
}

package pcap

import "github.com/rock-go/rock/lua"

func (p *Packet) Header(out lua.Printer) {
	out.Printf("type: %s", p.Type())
	out.Printf("uptime: %s", p.uptime)
	out.Println("version: v1.0.0")
	out.Println("")
}

func (p *Packet) Show(out lua.Printer) {
	p.Header(out)

	out.Printf("name: %s", p.Name())
	out.Printf("device: %s", p.C.Device)
	out.Printf("snap_shot: %d", p.C.Snapshot)
	out.Printf("promiscuous: %s", p.C.Promiscuous)
	out.Printf("timeout: %d", p.C.Timeout)
	//out.Printf("count: %d", p.Count)
	//out.Printf("duration: %d", p.Duration)
	//out.Printf("path: %s", p.Path)
	//out.Printf("transport: %s", p.Transport.Name())
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

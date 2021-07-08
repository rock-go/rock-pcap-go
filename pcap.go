package pcap

import (
	"context"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/rock-go/rock/logger"
	"github.com/rock-go/rock/lua"
	"os"
	"time"
)

type Packet struct {
	lua.Super
	cfg  *config
	cancel context.CancelFunc
}

func newPacket( cfg *config ) *Packet {
	p := &Packet{cfg:cfg}
	p.S = lua.INIT
	p.T = PACKET
	return p
}

// LiveCapture 实时抓包
func (p *Packet) LiveCapture(tp lua.Writer) {
	var promiscuous bool
	if p.cfg.Promiscuous == "on" {
		promiscuous = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	p.S = lua.RUNNING
	p.U = time.Now()

	handle, err := pcap.OpenLive(
		p.cfg.Device, int32(p.cfg.Snapshot), promiscuous, time.Duration(p.cfg.Timeout)*time.Second)
	if err != nil {
		logger.Errorf("Open live pcap error: %v", err)
		return
	}
	defer handle.Close()

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSrc.Packets():
			_, err = tp.Write(packet.Data())
		case <-ctx.Done():
			logger.Errorf("live pcap canceled")
			return
		}
	}
}

// PcapWrite 抓包写入文件
func (p *Packet) PcapWrite(path string, c int, d int) error {
	var promiscuous bool
	if p.cfg.Promiscuous == "on" {
		promiscuous = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	f, err := os.Create(path)
	if err != nil {
		logger.Errorf("create packet save file %s error: %v", path, err)
		return err
	}

	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(uint32(p.cfg.Snapshot), layers.LinkTypeEthernet)
	if err != nil {
		logger.Errorf("pcap write file header error: %v", err)
	}

	handle, err := pcap.OpenLive(
		p.cfg.Device, int32(p.cfg.Snapshot), promiscuous, time.Duration(p.cfg.Timeout)*time.Second)
	if err != nil {
		logger.Errorf("Open live pcap error: %v", err)
		return err
	}
	defer handle.Close()

	count := 0
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	duration := time.NewTicker(time.Duration(d) * time.Second)
	for {
		select {
		case <-duration.C:
			logger.Infof("pcap for %ds, packets count: %d", d, count)
			return nil
		case packet := <-packetSrc.Packets():
			err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				logger.Errorf("write packet to file %s error: %v", path, err)
				continue
			}
			count++
			if count >= c {
				logger.Errorf("packets count: %d", count)
				return nil
			}
		case <-ctx.Done():
			logger.Errorf("write pcap res to file canceled")
			return nil
		}
	}
}

// PcapRead 读取抓包文件
func (p *Packet) PcapRead(path string, tp lua.Writer) error {
	if tp == nil {
		logger.Errorf("transport is nil")
		return errors.New("transport is nil")
	}

	handle, err := pcap.OpenOffline(path)
	if err != nil {
		logger.Errorf("open offline pcap file error: %v", err)
		return err
	}
	defer handle.Close()

	var count int
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSrc.Packets() {
		_, err = tp.Write(packet.Data())
		count++
	}

	logger.Infof("pcap read file %s done, count %d packets", path, count)
	return nil
}

// Close 停止抓包
func (p *Packet) Close() error {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}

	p.S = lua.CLOSE
	return nil
}

func (p *Packet) Name() string {
	return p.cfg.name
}
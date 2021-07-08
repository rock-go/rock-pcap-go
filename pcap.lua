---
--- Generated by Luanalysis
--- Created by Administrator.
--- DateTime: 2021/7/6 16:33
---

--kafka生产者模块，持续抓包输出到远端或读取离线文件时需要
local kfk = kafka.producer {
    name = "kafka_producer_test",
    addr = "172.16.88.80:9092",
    timeout = 60,
    --key = "byte",
    topic = "access-log",
    num = 1000,
    flush = 10,
    buffer = 4096,
    thread = 10,
    limit = 5000,
    compression = 2,
    heartbeat = 10,
}

proc.start(kfk)

-- 抓包
local pcap = rock.pcap {
    name = "pcap_test",
    device = "\\Device\\NPF_{E71E2A75-FBC9-4647-94A4-20D04517C952}",
    snapshot = 1024,
    promiscuous = "on",
    timeout = 5,
}

local device = pcap.list()
print(device)

--pcap.live(kfk)
--pcap.close()
-- 抓包结果保存至文件
--pcap.write("resource/test1.pcap", 1000, 30)
-- 从文件读取抓包结果
--pcap.read("resource/test1.pcap", kfk)
# rock-pcap-go

rock-go框架系统的抓包组件，需要系统安装libpcap（linux）或winpcap（Windows）。

# 使用说明

## 导入

```go
import pcap "github.com/rock-go/rock-pcap-go"
```

## 注册

```go
rock.Inject(xcall.Rock, pcap.LuaInjectApi)
```

## lua 脚本调用

```lua
-- 抓包模块
local pcap = rock.pcap {
    name = "pcap_test",
    device = "192.168.1.2", -- 要抓包的网卡IP地址
    snapshot = 1024, -- 抓取包的最大长度
    promiscuous = "on", -- 是否开启混杂模式，on 表示开启，其它则不开启
    timeout = 5, -- 超时，单位秒
}

-- 函数
-- 函数支持
-- list() 列出所有网卡名和IP地址
-- live(param1) 持续抓包，输出到远端,param1 为kafka等与远端存储
-- close() 结束持续抓包或短暂抓包
-- write(path,count,duration) 根据count和duration短暂抓包，输出到本地文件path，通常使用该函数
-- read(path,tp) 从本地读取离线数据包，输出到远端
local device = pcap.list()
print(device)

-- example
--pcap.live(kfk)
--pcap.close()
-- 抓包结果保存至文件
--pcap.write("resource/test1.pcap", 1000, 30)
-- 从文件读取抓包结果
--pcap.read("resource/test1.pcap", kfk)
```
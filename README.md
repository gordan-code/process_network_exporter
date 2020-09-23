# process_network_exporter

属于Prometheus exporter,用于监控进程的网络连接情况，包括本地地址，远端地址，连接状态等。

### 运行

```
./process_network_exporter -config.path=/path/to/config.yaml
```

### 配置项

+ check_interval_seconds: 采集频率，决定多久执行一次采集
+ http_server_port: http端口
+ excluded_users: 被排除的用户。程序将监控除了写入配置文件中的用户之外的其他用户拥有的进程
+ 示例如下：

```
---
# The period in seconds between scraping metrics
check_interval_seconds: 3
# Http service port
http_server_port: 9500
# List excluded users(by name).System will monitor the processes of all users except these users
excluded_users:
  - root
  - mail
  - news
  - daemon
  - bin
  - sys
  - man
  - games
  - lp
  - uucp
  - proxy
  - www-data
  - backup
  - list
  - irc
  - gnats
  - nobody
  - systemd-network
  - systemd-resolve
  - syslog
  - messagebus
  - _apt
  - uuidd
  - avahi-autoipd
  - usbmux
  - dnsmasq
  - rtkit
  - cups-pk-helper
  - kernoops
  - saned
  - pulse
  - avahi
  - colord
  - geoclue
  - sshd
  - gdm
  - systemd-timesync
  - systemd-timesyn
  - whoopsie
```

### 命令行参数

```
Usage: process_network_exporter [-hvV] [-config.dir dirname]

Options:
  -config.dir string
    	dir of configuration file. (default "./config")
  -h	this help
  -v	show version and exit
```

### 程序目录

```
- BO				//业务对象
- config			//存放配置文件 config.yaml  logconf.xml
- db				//bbolt数据库 运行前需要建好
- PO				//持久层对象 指操作bbolt时使用的KV结构
- test				//单元测试
	- Bbolt_test.go	--测试bbolt
	- data_test.go  --测试该有的指标是否都有
- util				//工具类
	- Config.go		//配置结构体
(log)				//日志目录，运行时会生成 
	- (default.log) //默认日志名 按100M大小分割 
go.mod
go.sum
main.go				
ProcCollector.go	
README.md
```


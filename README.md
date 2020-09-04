# process_network_exporter

属于Prometheus exporter,用于监控进程的网络连接情况，包括本地地址，远端地址，连接状态等。

### 运行

```
./process_network_exporter -config.path=/path/to/config.yaml
```

### 配置项

+ check_interval_seconds: 采集频率，决定多久执行一次采集
+ http_server_port: http端口
+ log_path: 日志存储路径，注意要以'/'结尾
+ excluded_users: 被排除的用户。程序将监控除了写入配置文件中的用户之外的其他用户拥有的进程
+ 示例如下：

```
---
# The period in seconds between scraping metrics
check_interval_seconds: 3
# Http service port
http_server_port: 9500
# Log storage directory
log_path: /opt/log/
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
Usage: process_network_exporter [-hvV] [-config.path filename] [-web.telemetry-path metricspath]

Options:
  -config.path string
        path to YAML config file (default "config.yaml")
  -h    this help
  -metric.namespace string
        Prometheus metrics namespace, as the prefix of metrics name. e.g: process (default "process")
  -v    show version and exit
  -web.telemetry-path string
        A path under which to expose metrics. e.g: /metrics (default "/metrics")

```


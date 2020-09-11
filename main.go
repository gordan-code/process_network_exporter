package main

import (
	"bytes"
	"flag"
	"fmt"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"testExporter/util"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	h                 bool
	v                 bool
	version           = "1.00"
	configPaths       = flag.String("config.path", "config.yaml", "path to YAML config file")
	metricsPaths      = flag.String("web.telemetry-path", "/metrics", "A path under which to expose metrics. e.g: /metrics")
	metricsNamespaces = flag.String("metric.namespace", "process", "Prometheus metrics namespace, as the prefix of metrics name. e.g: process")

	mapUidCmd  sync.Map
	mapUserUid sync.Map
	tcpCache   *cache.Cache
	cfgs                                = &util.Config{}
	num        uint64 = 0

	writer *rotatelogs.RotateLogs
)

func usage() {
	fmt.Fprintf(os.Stderr, `process_network_exporter version: process_network_exporter/1.00
Usage: process_network_exporter [-hvV] [-config.path filename] [-web.telemetry-path metricspath]

Options:
`)
	flag.PrintDefaults()
}

func init() {
	//解析命令行参数
	flag.BoolVar(&h, "h", false, "this help")
	flag.BoolVar(&v, "v", false, "show version and exit")
	flag.Usage = usage
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true
	flag.Parse()
	if h {
		flag.Usage()
		os.Exit(1)
	}
	if v {
		fmt.Println("process_network_exporter: v", version)
		os.Exit(1)
	}

	//初始化cache
	tcpCache = cache.New(2*time.Minute, 10*time.Second)
	//map_uid_cmd = make(map[string]string)
	//map_user_uid = make(map[string]string)
	pathUser := "/etc/passwd"
	contents, err := ioutil.ReadFile(pathUser)
	if err != nil {
		log.Errorf("Error occured: ", err)
	}
	lines := bytes.Split(contents, []byte("\n"))

	for i := 0; i < len(lines)-1; i++ {
		l := strings.Split(string(lines[i]), ":")
		user := l[0]
		uid := l[2]
		//map_uid_cmd[uid] = user
		mapUserUid.Store(user,uid)
		//map_user_uid[user] = uid
	}

	//读取配置文件
	viper.SetConfigType("yaml")

	//configPath := "config.yaml"
	viper.SetConfigFile(*configPaths)

	err = viper.ReadInConfig()
	if err != nil {
		log.Errorf("read config failed: %s", err)
		os.Exit(1)
	}
	err = viper.Unmarshal(cfgs)
	if err != nil {
		//fmt.Println("unmarshal config is failed, err:", err)
		log.Errorf("unmarshal config is failed, err: %s", err)
		os.Exit(1)
	}

	//初始化log
	/* 日志轮转相关函数
	`WithLinkName` 为最新的日志建立软连接
	`WithRotationTime` 设置日志分割的时间，隔多久分割一次
	WithMaxAge 和 WithRotationCount二者只能设置一个
	 `WithMaxAge` 设置文件清理前的最长保存时间
	 `WithRotationCount` 设置文件清理前最多保存的个数
	*/
	// 下面配置日志每隔 1 天轮转一个新文件，保留最近 2周的日志文件，多余的自动清理掉。

	path := cfgs.Log_path + "test.log"
	writer, err = rotatelogs.New(
		path+".%Y%m%d",
		rotatelogs.WithLinkName(path),
		rotatelogs.WithMaxAge(time.Duration(336)*time.Hour),      //保留2周内的日志
		rotatelogs.WithRotationTime(time.Duration(24)*time.Hour), //按天切分
	)
	if err != nil {
		log.Errorf("Error occured:", err)
	}

	log.SetOutput(writer)
	log.SetReportCaller(true)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05", //时间格式化
	})
	//log.SetFormatter(&log.JSONFormatter{})

}

func main() {

	metrics := NewProcCollector(*metricsNamespaces)
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics)

	go metrics.Scrape()

	http.Handle(*metricsPaths, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Process_Network_Exporter</title></head>
			<body>
			<h1>Process Network Exporter</h1>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`))
	})

	log.Printf("Starting Server at http://localhost:%s%s", cfgs.Http_server_port, *metricsPaths)
	log.Fatal(http.ListenAndServe(":"+cfgs.Http_server_port, nil))
	err:=writer.Close()
	if err!= nil{
		log.Fatalf("Fatal error: ",err)
	}
}

package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/allegro/bigcache"
	log "github.com/cihub/seelog"
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
)

var (
	h       bool
	v       bool
	version = "1.00"
	//configPaths       = flag.String("config.path", "config.yaml", "path to YAML config file")
	//metricsPaths      = flag.String("web.telemetry-path", "/metrics", "A path under which to expose metrics. e.g: /metrics")
	//metricsNamespaces = flag.String("metric.namespace", "process", "Prometheus metrics namespace, as the prefix of metrics name. e.g: process")
	configDir = flag.String("config.dir", "./config", "dir of configuration file.")

	mapUidCmd  sync.Map
	mapUserUid sync.Map
	tcpCache   *cache.Cache
	BOCache    *bigcache.BigCache
	cfgs              = &util.Config{}
	num        uint64 = 0

	lock    sync.RWMutex
	metrics []prometheus.Metric
)


const (
	namespace = "process"
)

var TCPStatuses = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type MemoryInfo struct {
	pid    string
	pname  string //process cmdline
	user   string
	prss   uint64
	pvms   uint64
	pswap  uint64
	memper float32
}

func NewProcCollector(namespace string) *ProcCollector {
	return &ProcCollector{
	}
}

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

	flag.Parse()
	if h {
		flag.Usage()
		os.Exit(1)
	}
	if v {
		fmt.Println("process_network_exporter: v", version)
		os.Exit(1)
	}

	log.Flush()
	logger, err := log.LoggerFromConfigAsFile(*configDir + "/logconf.xml")
	if err != nil {
		log.Errorf("parse logconfig.xml err: %v", err)
	}
	log.ReplaceLogger(logger)

	//读取配置文件
	viper.SetConfigType("yaml")

	//configPath := "config.yaml"
	viper.SetConfigFile(*configDir + "/config.yaml")

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

	//初始化cache
	tcpCache = cache.New(2*time.Minute, 1*time.Minute)

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
		mapUserUid.Store(user, uid)
		//map_user_uid[user] = uid
	}
}

func processCollect() {
	//processes, err := getPidsExceptSomeUser()
	//if err != nil {
	//	log.Errorf("Error occured: %s", err)
	//}
	var procMetrics []prometheus.Metric

	wg := sync.WaitGroup{}
	wg.Add(2)

	wg.Wait()
	//统一写操作
	lock.Lock()
	metrics = procMetrics
	defer lock.Unlock()
}

func Scrape() {
	processes, err := getPidsExceptSomeUser()
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}

	intervals := int64(1000 * cfgs.Check_interval_seconds)
	t := time.NewTicker(time.Duration(intervals) * time.Millisecond)

	//log.Info("Create a cron manager")
	//cronmanager := cron.New(cron.WithSeconds())
	//cronmanager.AddFunc("*/"+strconv.FormatFloat(cfgs.Check_interval_seconds, 'E', -1, 64)+" * * * * *", processCollect)
	//cronmanager.Start()

	for {
		select {
		case <-t.C:
			GetConnInfoExceptSomeUser(&processes)
			//t.Stop()
		}
	}
}
func remoteProcHandler(w http.ResponseWriter, r *http.Request) {
	registry := prometheus.NewRegistry()
	remoteCollector := ProcCollector{}
	registry.MustRegister(remoteCollector)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {

	log.Info("Starting process_network_exporter")

	go Scrape()

	http.HandleFunc("/metrics", remoteProcHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Process_Network_Exporter</title></head>
			<body>
			<h1>Process Network Exporter</h1>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`))
	})

	log.Infof("Starting Server at http://localhost:%s/metrics", cfgs.Http_server_port)
	err := http.ListenAndServe(":"+cfgs.Http_server_port, nil)
	if err != nil {
		log.Error(err)
	}
}

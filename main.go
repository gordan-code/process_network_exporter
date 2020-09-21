package main

import (
	"bytes"
	"flag"
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/spf13/viper"
	bolt "go.etcd.io/bbolt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"testExporter/BO"
	"testExporter/util"
	"time"

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
	//tcpCache   *cache.Cache
	//ConnCache    *bigcache.BigCache
	//db 			 *gorocksdb.DB
	DB   *bolt.DB
	Cfgs              = &util.Config{}
	num  uint64 = 0

	lock    sync.RWMutex
	metrics []prometheus.Metric
)


const (
	namespace = "process"
	collectorNum=2
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
	err = viper.Unmarshal(Cfgs)
	if err != nil {
		//fmt.Println("unmarshal config is failed, err:", err)
		log.Errorf("unmarshal config is failed, err: %s", err)
		os.Exit(1)
	}


	//open bboltdb
	DB, err = bolt.Open("./db/exporter.db", 0666, nil)
	if err != nil {
		log.Error("open bboltdb error! "+err.Error())
	}

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

func collectMemoryInfo(processes []util.Process) []prometheus.Metric{
	var targetMetrics []prometheus.Metric
	log.Info("before reading memoryinfo")

	processMemoryInfo := GetMemoryInfo(processes)
	if len(processMemoryInfo) == 0 {
		log.Error("MemoryInfo or ContextInfo is empty!")
	}
	for _, meminfo := range processMemoryInfo {
		if meminfo == (MemoryInfo{}) {
			log.Error("ERROR: memoryinfo is empty!")
		}
		prss := meminfo.prss
		pvms := meminfo.pvms
		pswap := meminfo.pswap
		memPer := meminfo.memper
		targetMetrics=append(targetMetrics,prometheus.MustNewConstMetric(memInfoDesc, prometheus.GaugeValue, float64(prss), meminfo.pid, meminfo.user, meminfo.pname, "rss"))   //pid user cmd `rss`
		targetMetrics=append(targetMetrics,prometheus.MustNewConstMetric(memInfoDesc, prometheus.GaugeValue, float64(pvms), meminfo.pid, meminfo.user, meminfo.pname, "vms"))   //pid user cmd `vms`
		targetMetrics=append(targetMetrics, prometheus.MustNewConstMetric(memInfoDesc, prometheus.GaugeValue, float64(pswap), meminfo.pid, meminfo.user, meminfo.pname, "swap")) //pid user cmd `swap`
		targetMetrics=append(targetMetrics,prometheus.MustNewConstMetric(memPerDesc, prometheus.GaugeValue, float64(memPer), meminfo.pid, meminfo.user, meminfo.pname))         //pid user cmd
	}
	return targetMetrics
}

func collectNetworkInfo(processes []util.Process) []prometheus.Metric {
	var targetMetrics []prometheus.Metric

	tx, err := DB.Begin(true)
	if err != nil {
		log.Errorf("error occured: %s", err.Error())
	}
	//defer tx.Rollback()
	bkt, err := tx.CreateBucketIfNotExists([]byte("MyBucket"))
	if err != nil {
		log.Errorf("error occured: %s", err.Error())
	}
	for _, process := range processes {
		pid := process.Pid
		pathTcp := fmt.Sprintf("/proc/%s/net/tcp", pid)
		//log.Info("生成/tcp地址: ",path_tcp)
		rowTcp, err := parseTCPInfo(pathTcp)
		if err != nil {
			log.Errorf("Error occured at parseTCPInfo(): %s", err)
		}
		var networkKey BO.NetworkKey

		//log.Println("Before web get: Cmd: ",process.Cmd)
		for _, conn := range rowTcp {
			networkKey.Pid = pid
			networkKey.Src = conn.Laddr
			networkKey.Dst = conn.Raddr
			networkKey.TypeStr = "ipv4/tcp"

			key := parseEncode(networkKey).([]byte)

			//bboltdb
			v := bkt.Get(key)
			if v != nil {
				networkValue := parseDecode(v, BO.NetworkValue{}).(BO.NetworkValue)
				src, err := parseIPV4(conn.Laddr)
				if err != nil {
					log.Errorf("Error occured: %s", err.Error())
				}
				dst, err := parseIPV4(conn.Raddr)
				if err != nil {
					log.Errorf("Error occured: %s", err.Error())
				}
				ended, err := time.ParseInLocation("2006-01-02 15:04:05", networkValue.End_time, time.Local)
				if err != nil {
					log.Errorf("Error occured: %s", err.Error())
				}
				value := ended.UnixNano() / 1e6
				targetMetrics=append(targetMetrics,prometheus.MustNewConstMetric(networkInfoDesc, prometheus.GaugeValue, float64(value), pid, process.User, process.Cmd, "ipv4/tcp", src, dst, networkValue.Status))

			}
		}
	}
	defer tx.Rollback()
	if err := tx.Commit(); err != nil {
		log.Errorf("Error occured: %s", err.Error())
	}

	return targetMetrics
}


func Scrape() {
	processes, err := getPidsExceptSomeUser()
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}

	intervals := int64(1000 * Cfgs.Check_interval_seconds)
	t := time.NewTicker(time.Duration(intervals) * time.Millisecond)

	//log.Info("Create a cron manager")
	//cronmanager := cron.New(cron.WithSeconds())
	//cronmanager.AddFunc("*/"+strconv.FormatFloat(Cfgs.Check_interval_seconds, 'E', -1, 64)+" * * * * *", processCollect)
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

	log.Infof("Starting Server at http://localhost:%s/metrics", Cfgs.Http_server_port)
	err := http.ListenAndServe(":"+Cfgs.Http_server_port, nil)
	if err != nil {
		log.Errorf("Fatal error:%s",err.Error())
	}
}

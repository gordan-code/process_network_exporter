package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/allegro/bigcache"
	log "github.com/cihub/seelog"
	"github.com/robfig/cron/v3"
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
	h                 bool
	v                 bool
	version           = "1.00"
	configPaths       = flag.String("config.path", "config.yaml", "path to YAML config file")
	metricsPaths      = flag.String("web.telemetry-path", "/metrics", "A path under which to expose metrics. e.g: /metrics")
	metricsNamespaces = flag.String("metric.namespace", "process", "Prometheus metrics namespace, as the prefix of metrics name. e.g: process")
	configDir		  = flag.String("config.dir","./config","dir of configuration file.")

	mapUidCmd  sync.Map
	mapUserUid sync.Map
	tcpCache   *cache.Cache
	BOCache    *bigcache.BigCache
	cfgs                                = &util.Config{}
	num        uint64 = 0

	lock      sync.RWMutex
	metrics   []prometheus.Metric
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
	logger, err := log.LoggerFromConfigAsFile( *configDir +"/logconf.xml")
	if err != nil {
		log.Errorf("parse logconfig.xml err: %v", err)
	}
	log.ReplaceLogger(logger)

	//读取配置文件
	viper.SetConfigType("yaml")

	//configPath := "config.yaml"
	viper.SetConfigFile(*configDir+"/config.yaml")

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
	BOCache, _ =bigcache.NewBigCache(bigcache.DefaultConfig(2 * time.Minute))

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
}

func collectIOPS(processes []util.Process) []prometheus.Metric{
	return nil
}

func collectIOInfo(processes []util.Process) []prometheus.Metric{
	var monitorMetrics [] prometheus.Metric
	processIOInfo:=GetIOInfo(processes)
	if len(processIOInfo)==0{
		log.Error("IOInfo is empty!")
	}
	for _,ioInfo:=range processIOInfo {
		if ioInfo == (IOInfo{}) {
			log.Error("ERROR: ioInfo  is empty!")
		}
		readBytes := float64(ioInfo.ReadBytes)
		writeBytes := float64(ioInfo.WriteBytes)
		monitorMetrics=append(monitorMetrics,prometheus.MustNewConstMetric(readBytesDesc, prometheus.CounterValue, readBytes, ioInfo.Pid, ioInfo.Uid, ioInfo.Cmd)) //pid uid cmd
		monitorMetrics=append(monitorMetrics,prometheus.MustNewConstMetric(writeBytesDesc, prometheus.CounterValue, writeBytes, ioInfo.Pid, ioInfo.Uid, ioInfo.Cmd))//pid uid cmd
	}
	return monitorMetrics
}

func collectCPUAndPageInfo(processes []util.Process) []prometheus.Metric{
	var monitorMetrics [] prometheus.Metric
	processCpuInfo,processPageInfo:= GetCPUAndPageInfo(processes)
	if (len(processCpuInfo)==0 || len(processPageInfo)==0){
		log.Error("CPUInfo or PageInfo is empty!")
	}
	for _,cpuinfo:=range processCpuInfo {
		if cpuinfo==(CPUInfo{}){
			log.Error("ERROR: cpuinfo  is empty!")
		}
		userper:=cpuinfo.userper
		sysper:=cpuinfo.sysper
		monitorMetrics=append(monitorMetrics,prometheus.MustNewConstMetric(cpuPercentDesc,prometheus.GaugeValue,float64(userper),cpuinfo.pid,cpuinfo.uid,cpuinfo.cmd,"user"))
		monitorMetrics=append(monitorMetrics,prometheus.MustNewConstMetric(cpuPercentDesc,prometheus.GaugeValue,float64(sysper),cpuinfo.pid,cpuinfo.uid,cpuinfo.cmd,"system")) // pid uid cmd mode='system' )
	}
	for _,pageinfo :=range processPageInfo {
		if pageinfo == (PageInfo{}) {
			log.Error("ERROR: pageinfo  is empty!")
		}
		monitorMetrics=append(monitorMetrics,prometheus.MustNewConstMetric(majorPageFaultsDesc, prometheus.CounterValue, pageinfo.majflt, pageinfo.pid, pageinfo.uid, pageinfo.cmd)) // pid uid cmd
		monitorMetrics=append(monitorMetrics,prometheus.MustNewConstMetric(minorPageFaultsDesc, prometheus.CounterValue, pageinfo.minflt, pageinfo.pid, pageinfo.uid, pageinfo.cmd))// pid uid cmd
	}
	return monitorMetrics
}

func processCollect(){
	processes, err := getPidsExceptSomeUser()
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}
	var procMetrics []prometheus.Metric
	var cpuAndPageMetrics []prometheus.Metric
	wg := sync.WaitGroup{}
	wg.Add(2)
	log.Info("before reading cpuinfo and pageInfo ")
	go func(processes []util.Process) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(5))
		defer cancel()
		//业务 begin

		cpuAndPageMetrics =collectCPUAndPageInfo(processes)
		procMetrics=append(procMetrics, cpuAndPageMetrics...)

		//业务 end
		select {
		case <-ctx.Done():
			log.Error("收到超时信号,采集退出")
		default:
			//log.Info(config.Targets[i].Host,":指标采集完成",len(cpuAndPageMetrics))
		}
		wg.Done()
	}(processes)

	log.Info("before reading ioinfo ")
	go func(processes []util.Process) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(5))
		defer cancel()
		//业务 begin
		lock.Lock()
		procMetrics=append(procMetrics,collectIOInfo(processes)...)
		lock.Unlock()
		//业务 end
		select {
		case <-ctx.Done():
			log.Error("收到超时信号,采集退出")
		default:
			//log.Info(config.Targets[i].Host,":指标采集完成",len(cpuAndPageMetrics))
		}
		wg.Done()
	}(processes)

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
	//if len(processes)==0 {
	//	log.Error("出错!!!切片为空!")
	//}
	intervals := int64(1000 * cfgs.Check_interval_seconds)
	t:=time.NewTicker(time.Duration(intervals) * time.Millisecond)

	log.Info("Create a cron manager")
	cronmanager := cron.New(cron.WithSeconds())
	cronmanager.AddFunc("*/5 * * * * *", processCollect)
	cronmanager.Start()

	for {
		select {
		case <-t.C:
			GetConnInfoExceptSomeUser(&processes)
			GetIOPSThroughput(processes)
			//t.Stop()
		}
	}
	//for {
	//	GetConnInfoExceptSomeUser(processes)
	//	intervals := int64(1000 * cfgs.Check_interval_seconds)
	//	time.Sleep(time.Duration(intervals) * time.Millisecond)
	//}
}


func main() {

	metrics := NewProcCollector(namespace)
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics)

	go Scrape()

	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Process_Network_Exporter</title></head>
			<body>
			<h1>Process Network Exporter</h1>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`))
	})

	//log.Infof("Starting Server at http://localhost:%s%s", cfgs.Http_server_port,"/metrics")
	//log.Info(cfgs.Http_server_port)
	//err := http.ListenAndServe(cfgs.Http_server_port, nil)
	//if err != nil {
	//	log.Error(err)
	//}

	log.Infof("Starting Server at http://localhost:%s%s", cfgs.Http_server_port, *metricsPaths)
	err := http.ListenAndServe(":"+cfgs.Http_server_port, nil)
	if err!= nil{
		log.Error(err)
	}
}

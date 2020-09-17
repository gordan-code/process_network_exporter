package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

const (
	namespace = "process"
)

type collector struct{}

type ContextInfo struct {
	pid                        string
	uid                        string
	cmd                        string
	voluntary_ctxt_switches    uint64
	nonvoluntary_ctxt_switches uint64
}

type CPUInfo struct{
	pid		string
	uid		string
	cmd		string
	utime	string
	stime 	string
	userper  float64
	sysper   float64
}

type CPUStat struct {
	user        float64
	nice        float64
	system      float64
	idle        float64
	iowait      float64
	irq         float64
	softirq     float64
	stealstolen float64
	guest       float64
	guest_nice  float64
}


type DiskInfo struct{
	Pid string
	Uid string
	Cmd string
	Read_IOPS uint64
	Write_IOPS uint64
	Read_Throughput uint64
	Write_Throughput uint64
}

type IOInfo struct {
	Pid string
	Uid string
	Cmd string
	// Chars read.
	RChar uint64
	// Chars written.
	WChar uint64
	// Read syscalls.
	SyscR uint64
	// Write syscalls.
	SyscW uint64
	// Bytes read.
	ReadBytes uint64
	// Bytes written.
	WriteBytes uint64
	// Bytes written, but taking into account truncation. See
	// Documentation/filesystems/proc.txt in the kernel sources for
	// detailed explanation.
	CancelledWriteBytes int64
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

type PageInfo struct {
	pid    string
	uid    string
	cmd    string
	majflt float64
	minflt float64
}

type UnameInfo struct{
	SysName    string
	Release    string
	Version    string
	Machine    string
	NodeName   string
	DomainName string
}
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


var (
	memoryInfoDesc= prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "memory", "info"),
		"Process memory information.",
		[]string{"pid", "uid", "cmd", "memtype"},
		nil,
	)

	memoryPercentDesc=prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "memory", "percent"),
		"The percentage of memory used by the process.",
		[]string{"pid", "uid", "cmd"},
		nil,
	)

	networkInfoDesc=prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "network", "info"),
		"TCP connection information opened by the process.",
		[]string{"pid", "uid", "cmd", "type", "src", "dst", "status"},
		nil,
	)

	durationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "scrape_duration", "seconds"),
		"Returns how long the scrape took to complete in seconds.",
		nil,
		nil,
	)
)

func (c collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- memoryInfoDesc
	ch <- memoryPercentDesc
	ch <- networkInfoDesc
}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	lock.RLock()
	for _, metric := range metrics {
		if metric != nil{
			ch <- metric
		}
	}
	lock.RUnlock()
}
func GetMemoryInfo(){
	for _, process := range *processes {
		pid := process.Pid
		pathStatus := "/proc/" + pid + "/status"
		memoryInfo, pageInfo,err := parseMemAndPageInfo(pathStatus)
		if err != nil {
			log.Errorf("Error occured: %s", err)
		}
		memoryInfo.pid = pid
		memoryInfo.pname = process.Cmd
		memoryInfo.user = process.User

		pageInfo.pid=pid
		pageInfo.uid=process.User
		pageInfo.cmd=process.Cmd

		processMemInfoData = append(processMemInfoData, memoryInfo)
		processContextInfoData =append(processContextInfoData,pageInfo)
	}
	return
}

func collectConnectionInfo(){

}

func collectInfo(desc *prometheus.Desc,typestr string) []prometheus.Metric{
	var procMetrics  [] prometheus.Metric
	switch typestr {
	case "memory_info":
		GetMemoryInfo()
	case "memory_percent":
		GetMemoryInfo()
	case "network_info":
		GetConnectionInfo()
	}

	return procMetrics
}

func collectProcess() (error,[]prometheus.Metric) {
	var monitorMetrics [] prometheus.Metric
	monitorMetrics = append(monitorMetrics,collectInfo(memoryInfoDesc,"memory_info")...)
	monitorMetrics = append(monitorMetrics,collectInfo(memoryPercentDesc,"memory_percent")...)
	monitorMetrics = append(monitorMetrics,collectInfo(networkInfoDesc,"network_info")...)
}

func ProcCollect() []prometheus.Metric {
	var procMetrics [] prometheus.Metric
	start := time.Now()
	duration := time.Since(start).Seconds()
	//log.Debugf("Scrape of target %s took %f seconds.", target.Host, duration)
	durationMetrics := prometheus.MustNewConstMetric(
		durationDesc,
		prometheus.GaugeValue,
		duration,
	)
	procMetrics=append(procMetrics, durationMetrics)
	_,collectMetcics = collectProcess()
	procMetrics=append(procMetrics, collectMetcics)
	return procMetrics
}


package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	flatbuffers "github.com/google/flatbuffers/go"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/spf13/viper"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testExporter/util"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/procfs"
	log "github.com/sirupsen/logrus"
)

// 指标结构体
type ProcCollector struct {
	Metrics map[string]*prometheus.Desc
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

type MemoryInfo struct {
	pid    string
	pname  string //process cmdline
	user   string
	prss   uint64
	pvms   uint64
	pswap  uint64
	memper float32
}

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

	TCPStatuses = map[string]string{
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

	writer *rotatelogs.RotateLogs
)

func RunCommand(cmd string) (string, error) {
	//fmt.Println("Running Linux cmd:" + cmd)
	result, err := exec.Command("/bin/sh", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(result)), err
}



//16进制的ipv4地址转为可识别的ipv4格式：例如“10.10.25.50:8888”
func parseIPV4(s string) (string, error) {
	hexIP := s[:len(s)-5]
	hexPort := s[len(s)-4:]
	bytesIP, err := hex.DecodeString(hexIP)
	if err != nil {
		return "", nil
	}
	uint32IP := binary.LittleEndian.Uint32(bytesIP) //转换为主机字节序
	IP := make(net.IP, 4)
	binary.BigEndian.PutUint32(IP, uint32IP)
	port, err := strconv.ParseUint(hexPort, 16, 16)
	return fmt.Sprintf("%s:%d", IP.String(), port), err
}

//读入指定行数文件内容
func ReadLine(filename string, lineNumber int) string {
	file, err := os.Open(filename)
	if err != nil {
		log.Errorf("Error occured: ", err)
	}
	fileScanner := bufio.NewScanner(file)
	lineCount := 1
	for fileScanner.Scan() {
		if lineCount == lineNumber {
			return fileScanner.Text()
		}
		lineCount++
	}
	err = file.Close()
	if err != nil{
		log.Errorf("error occured:", err)
	}
	return ""
}
func parseCPUTotal()(CPUStat,error){
	pathStat :="/proc/stat"
	var cpuStat CPUStat
	line := ReadLine(pathStat,1)
	fields := strings.Fields(line)

	cpuStat.user,_=strconv.ParseFloat(fields[1],64)
	cpuStat.nice,_=strconv.ParseFloat(fields[2],64)
	cpuStat.system,_=strconv.ParseFloat(fields[3],64)
	cpuStat.idle,_=strconv.ParseFloat(fields[4],64)
	cpuStat.iowait,_=strconv.ParseFloat(fields[5],64)
	cpuStat.irq,_=strconv.ParseFloat(fields[6],64)
	cpuStat.softirq,_=strconv.ParseFloat(fields[7],64)
	cpuStat.stealstolen,_=strconv.ParseFloat(fields[8],64)
	cpuStat.guest,_=strconv.ParseFloat(fields[9],64)
	cpuStat.guest_nice,_=strconv.ParseFloat(fields[10],64)

	return cpuStat,nil
}


func parseMemTotal() (float32, error) {
	pathMeminfo := "/proc/meminfo"
	line := ReadLine(pathMeminfo, 1)
	fields := strings.Split(line, ":")

	value := strings.TrimSpace(fields[1])
	value = strings.Replace(value, " kB", "", -1)

	t, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, err
	}
	total := t * 1024
	return float32(total), nil
}

func parseCPUAndPageInfo(file string) (CPUInfo,PageInfo,error){
	var cpuInfo CPUInfo
	var pageInfo PageInfo
	contents,err:=ioutil.ReadFile(file)
	if err != nil {
		return CPUInfo{},PageInfo{}, err
	}
	fields:=strings.Fields(string(contents))
	i := 1
	for !strings.HasSuffix(fields[i], ")") {
		i++
	}
	utime, err := strconv.ParseFloat(fields[i+12], 64)
	if err != nil {
		log.Errorf("error occured:", err)
		return CPUInfo{},PageInfo{},err
	}
	stime, err := strconv.ParseFloat(fields[i+13], 64)
	if err != nil {
		log.Errorf("error occured:", err)
		return CPUInfo{},PageInfo{},err
	}
	majflt,err:= strconv.ParseFloat(fields[i+10],64)
	if err != nil {
		log.Errorf("error occured:", err)
		return CPUInfo{},PageInfo{},err
	}
	minflt,err :=strconv.ParseFloat(fields[i+8],64)
	if err != nil {
		log.Errorf("error occured:", err)
		return CPUInfo{},PageInfo{},err
	}

	cpuInfo.utime=strconv.FormatFloat(utime, 'E', -1, 64)
	cpuInfo.stime=strconv.FormatFloat(stime, 'E', -1, 64)

	pageInfo.majflt=majflt
	pageInfo.minflt=minflt

	cpuStat,err:=parseCPUTotal()
	if err != nil {
		return CPUInfo{},PageInfo{}, err
	}
	cpuInfo.userper=(100*float64(utime)/float64(cpuStat.user))
	cpuInfo.sysper=(100*float64(stime)/float64(cpuStat.system))
	return cpuInfo,pageInfo,nil
}

func parseIOInfo(file string)(IOInfo,error){
	var ioInfo IOInfo
	contents,err:=ioutil.ReadFile(file)
	if err !=nil{
		return IOInfo{},err
	}
	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		tabParts := strings.Fields(line)
		if len(tabParts) ==0{
			continue
		}
		value := tabParts[1]
		switch strings.TrimRight(tabParts[0], ":") {
		case "rchar":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return IOInfo{}, err
			}
			ioInfo.RChar=v
		case "wchar":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return IOInfo{}, err
			}
			ioInfo.WChar=v
		case "syscr":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return IOInfo{}, err
			}
			ioInfo.SyscR=v
		case "syscw":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return IOInfo{}, err
			}
			ioInfo.SyscW=v
		case "read_bytes":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return IOInfo{}, err
			}
			ioInfo.ReadBytes=v
		case "write_bytes":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return IOInfo{}, err
			}
			ioInfo.WriteBytes=v
		case "cancelled_write_bytes":
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return IOInfo{}, err
			}
			ioInfo.CancelledWriteBytes=v
		}
	}
	return  ioInfo,nil
}

// proc/$pid/status 计算内存占比
func parseMemAndPageInfo(file string) (MemoryInfo, ContextInfo, error) {
	var memInfo MemoryInfo
	var pageInfo ContextInfo
	contents, err := ioutil.ReadFile(file)
	if err != nil {
		return MemoryInfo{}, ContextInfo{}, err
	}
	//fields := strings.Split(string(contents), " ")
	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		tabParts := strings.SplitN(line, "\t", 2)
		if len(tabParts) < 2 {
			continue
		}
		value := tabParts[1]
		switch strings.TrimRight(tabParts[0], ":") {
		case "VmRSS":
			value := strings.Trim(value, " kB") //remove last KB
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return MemoryInfo{}, ContextInfo{}, err
			}
			memInfo.prss = v * 1024
		case "VmSize":
			value := strings.Trim(value, " kB") // remove last "kB"
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return MemoryInfo{}, ContextInfo{}, err
			}
			memInfo.pvms = v * 1024
		case "VmSwap":
			value := strings.Trim(value, " kB") // remove last "kB"
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return MemoryInfo{}, ContextInfo{}, err
			}
			memInfo.pswap = v * 1024
		case "voluntary_ctxt_switches":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return MemoryInfo{}, ContextInfo{}, err
			}
			pageInfo.voluntary_ctxt_switches=v
		case "nonvoluntary_ctxt_switches":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return MemoryInfo{}, ContextInfo{}, err
			}
			pageInfo.nonvoluntary_ctxt_switches=v
		}
	}
	total, err := parseMemTotal()
	if err != nil {
		return MemoryInfo{}, ContextInfo{}, err
	}
	used := memInfo.prss
	memInfo.memper = (100 * float32(used) / float32(total))

	return memInfo, pageInfo,nil
}

func removeDuplication(addrs []GPUInfo) []GPUInfo {
	result := make([]GPUInfo, 0, len(addrs))
	temp := map[GPUInfo]struct{}{}
	for _, item := range addrs {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func parseGPUInfo(file string) ([]GPUInfo,error){
	contents, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if len(contents)<1{
		log.Println("Error! file "+file+"is empty!")
	}
	lines := bytes.Split(contents, []byte("\n"))

	var processGPUInfo []GPUInfo
	for _,line:=range lines[2:]{
		l := strings.Fields(string(line))
		if len(l)<8 {
			continue
		}
		idx,err:=strconv.Atoi(l[0])
		if err != nil {
			log.Errorf("error occured:", err)
			return nil, err
		}
		pid:=l[1]
		sm,err:=strconv.ParseFloat(l[3],64)
		if err != nil {
			log.Errorf("error occured:", err)
			return nil, err
		}
		mem,err:=strconv.ParseFloat(l[4],64)
		if err != nil {
			log.Errorf("error occured:", err)
			return nil, err
		}
		enc,err:=strconv.ParseFloat(l[5],64)
		if err != nil {
			log.Errorf("error occured:", err)
			return nil, err
		}
		dec,err:=strconv.ParseFloat(l[6],64)
		if err != nil {
			log.Errorf("error occured:", err)
			return nil, err
		}
		cmd:=l[7]
		util:=sm+enc+dec

		processGPUInfo=append(processGPUInfo,GPUInfo{
			Pid: pid,
			Cmd: cmd,
			Utilization: util,
			Mem: mem,
			Idx: idx,
		})
	}
	ret:=removeDuplication(processGPUInfo)
	return ret,nil
}

func parseTCPInfo(file string) ([]util.TCPInfo, error) {
	contents, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(contents, []byte("\n"))

	var ret []util.TCPInfo
	for _, line := range lines[1:] {
		l := strings.Fields(string(line))
		if len(l) < 10 {
			continue
		}
		laddr := l[1]
		raddr := l[2]
		status := l[3]
		if err != nil {
			log.Errorf("error occured:", err)
			return nil, err
		}
		if err != nil {
			log.Errorf("error occured:", err)
			return nil, err
		}

		status = TCPStatuses[status]

		ret = append(ret, util.TCPInfo{
			Laddr:  laddr,
			Raddr:  raddr,
			Status: status,
		})
	}
	return ret, nil
}

func newGlobalCollector(namespace string, metricName string, docString string, labels []string) *prometheus.Desc {
	return prometheus.NewDesc(namespace+"_"+metricName, docString, labels, nil)
}

func NewProcCollector(namespace string) *ProcCollector {
	return &ProcCollector{
		Metrics: map[string]*prometheus.Desc{
			"process_memory_info":    newGlobalCollector(namespace, "memory_info", "Process memory information", []string{"pid", "uid", "cmd", "memtype"}),
			"process_memory_percent": newGlobalCollector(namespace, "memory_percent", "The percentage of memory used by the process", []string{"pid", "uid", "cmd"}),
			"process_network_info":   newGlobalCollector(namespace, "network_info", "TCP/UDP connection information opened by the process", []string{"pid", "uid", "cmd", "type", "src", "dst", "status"}),
			"process_cpu_percent": newGlobalCollector(namespace,"cpu_percent","CPU Percent of the process",[]string{"pid","uid","cmd","mode"}),
			"process_context_switches_total": newGlobalCollector(namespace,"context_switches_total","Context switches",[]string{"pid","uid","cmd","ctxswitchtype"}),
			"process_major_page_faults_total":newGlobalCollector(namespace,"major_page_faults_total","Major page faults",[]string{"pid","uid","cmd"}),
			"process_minor_page_faults_total":newGlobalCollector(namespace,"minor_page_faults_total","Minor page faults",[]string{"pid","uid","cmd"}),
			"process_read_bytes_total":newGlobalCollector(namespace,"process_read_bytes_total"," The total number of bytes actually read from the disk by the process",[]string{"pid","uid","cmd"}),
			"process_write_bytes_total":newGlobalCollector(namespace,"process_write_bytes_total","The total number of bytes actually written to disk by the process",[]string{"pid","uid","cmd"}),
			"process_iops":newGlobalCollector(namespace,"process_iops","Number of disk reads and writes per second by the process",[]string{"pid","uid","cmd","type"}),
			"process_throughput":newGlobalCollector(namespace,"process_throughput","The process actually reads and writes disk bytes per second, that is, throughput",[]string{"pid","uid","cmd","type"}),
			"process_gpu_utilzation":newGlobalCollector(namespace,"process_gpu_utilzation","GPU utilization of the process",[]string{"pid","uid","cmd","idx"}),
			"process_gpu_memory_percent":newGlobalCollector(namespace,"process_gpu_memory_percent","The memory utilization of the process",[]string{"pid","uid","cmd","idx"}),
		},
	}
}

func (c *ProcCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.Metrics {
		ch <- m
	}
}

func (c *ProcCollector) Collect(ch chan<- prometheus.Metric) {
	log.Info("Visiting web page...")
	processes, err := getPidsExceptSomeUser()
	if len(processes)==0{
		log.Error("出错!!!切片为空!")
	}
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}

	processMemoryInfo, processContextInfo := c.GetMemoryAndContextInfo(processes)
	for _, meminfo := range processMemoryInfo {
		prss := meminfo.prss
		pvms := meminfo.pvms
		pswap := meminfo.pswap
		memPer := meminfo.memper
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_info"], prometheus.GaugeValue, float64(prss), meminfo.pid, meminfo.user, meminfo.pname, "rss")   //pid user cmd `rss`
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_info"], prometheus.GaugeValue, float64(pvms), meminfo.pid, meminfo.user, meminfo.pname, "vms")   //pid user cmd `vms`
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_info"], prometheus.GaugeValue, float64(pswap), meminfo.pid, meminfo.user, meminfo.pname, "swap") //pid user cmd `swap`
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_percent"], prometheus.GaugeValue, float64(memPer), meminfo.pid, meminfo.user, meminfo.pname)     //pid user cmd
	}
	for _,pageinfo := range processContextInfo {
		nonvoluntaryCtxtSwitches :=float64(pageinfo.nonvoluntary_ctxt_switches)
		voluntaryCtxtSwitches :=float64(pageinfo.voluntary_ctxt_switches)
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_context_switches_total"],prometheus.CounterValue, nonvoluntaryCtxtSwitches,pageinfo.pid,pageinfo.uid,pageinfo.cmd,"nonvoluntary") // pid uid cmd ctxswitchtype
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_context_switches_total"],prometheus.CounterValue, voluntaryCtxtSwitches,pageinfo.pid,pageinfo.uid,pageinfo.cmd,"voluntary")       // pid uid cmd ctxswitchtype
	}

	processCpuInfo,processPageInfo:= c.GetCPUAndPageInfo(processes)
	for _,cpuinfo:=range processCpuInfo {
		userper:=cpuinfo.userper
		sysper:=cpuinfo.sysper
		ch<- prometheus.MustNewConstMetric(c.Metrics["process_cpu_percent"],prometheus.GaugeValue,float64(userper),cpuinfo.pid,cpuinfo.uid,cpuinfo.cmd,"user") // pid uid cmd mode='user'
		ch<- prometheus.MustNewConstMetric(c.Metrics["process_cpu_percent"],prometheus.GaugeValue,float64(sysper),cpuinfo.pid,cpuinfo.uid,cpuinfo.cmd,"system") // pid uid cmd mode='system'

	}
	for _,pageinfo :=range processPageInfo{
		ch<- prometheus.MustNewConstMetric(c.Metrics["process_major_page_faults_total"],prometheus.CounterValue,pageinfo.majflt,pageinfo.pid,pageinfo.uid,pageinfo.cmd)// pid uid cmd
		ch<- prometheus.MustNewConstMetric(c.Metrics["process_minor_page_faults_total"],prometheus.CounterValue,pageinfo.minflt,pageinfo.pid,pageinfo.uid,pageinfo.cmd)// pid uid cmd
	}
	processIOInfo:=c.GetIOInfo(processes)
	for _,ioInfo:=range processIOInfo {
		readBytes:=float64(ioInfo.ReadBytes)
		writeBytes:=float64(ioInfo.WriteBytes)
		ch<- prometheus.MustNewConstMetric(c.Metrics["process_read_bytes_total"],prometheus.CounterValue,readBytes,ioInfo.Pid,ioInfo.Uid,ioInfo.Cmd)//pid uid cmd
		ch<- prometheus.MustNewConstMetric(c.Metrics["process_write_bytes_total"],prometheus.CounterValue,writeBytes,ioInfo.Pid,ioInfo.Uid,ioInfo.Cmd)//pid uid cmd
	}

	processDiskInfo:=c.GetIOPSThroughput(processes)
	for _,diskInfo:=range processDiskInfo {
		readIops :=float64(diskInfo.Read_IOPS)
		writeIops :=float64(diskInfo.Write_IOPS)
		readThroughput :=float64(diskInfo.Read_Throughput)
		writeThroughput :=float64(diskInfo.Write_Throughput)
		ch<-prometheus.MustNewConstMetric(c.Metrics["process_iops"],prometheus.GaugeValue, readIops,diskInfo.Pid,diskInfo.Uid,diskInfo.Cmd,"read")               // pid uid cmd type
		ch<-prometheus.MustNewConstMetric(c.Metrics["process_iops"],prometheus.GaugeValue, writeIops,diskInfo.Pid,diskInfo.Uid,diskInfo.Cmd,"write")             // pid uid cmd type
		ch<-prometheus.MustNewConstMetric(c.Metrics["process_throughput"],prometheus.GaugeValue, readThroughput,diskInfo.Pid,diskInfo.Uid,diskInfo.Cmd,"read")   // pid uid cmd type
		ch<-prometheus.MustNewConstMetric(c.Metrics["process_throughput"],prometheus.GaugeValue, writeThroughput,diskInfo.Pid,diskInfo.Uid,diskInfo.Cmd,"write") // pid uid cmd type
	}

	//Get GPU info
	processGPUInfo:=c.GetGPUUtilization(processes)
	if len(processGPUInfo)>0{
		for _,gpuInfo:=range processGPUInfo {
			idx:=strconv.Itoa(gpuInfo.Idx)
			ch<-prometheus.MustNewConstMetric(c.Metrics["process_gpu_utilzation"],prometheus.GaugeValue,gpuInfo.Utilization,gpuInfo.Pid,gpuInfo.Uid,gpuInfo.Cmd,idx) //pid uid cmd idx
			ch<-prometheus.MustNewConstMetric(c.Metrics["process_gpu_memory_percent"],prometheus.GaugeValue,gpuInfo.Mem,gpuInfo.Pid,gpuInfo.Uid,gpuInfo.Cmd,idx)// pid uid cmd idx
		}
	}

	//Get Connection Info
	log.Println("size of the map: ", tcpCache.ItemCount())
	if tcpCache.ItemCount()==0{
		log.Error("出错!!!map中数据为0条 ")
	}

	log.Info("开始读缓存")
	for _, process := range processes {
		pid := process.Pid
		pathTcp := fmt.Sprintf("/proc/%s/net/tcp", pid)
		//Info("生成/tcp地址: ",path_tcp)
		rowTcp, err := parseTCPInfo(pathTcp)
		if err != nil {
			log.Errorf("Error occured at Collect(): %s", err)
		}
		//var dataKey util.DataKey
		var dataValue util.DataValue
		builder := flatbuffers.NewBuilder(0)

		log.Println("Before web get: Cmd: ",process.Cmd)
		for _, conn := range rowTcp {
			Pid := builder.CreateString(pid)
			Src := builder.CreateString(conn.Laddr)
			Dst := builder.CreateString(conn.Raddr)
			typeStr := builder.CreateString("ipv4/tcp")

			util.DataKeyStart(builder)
			util.DataKeyAddPid(builder, Pid)
			util.DataKeyAddSrc(builder, Src)
			util.DataKeyAddDst(builder, Dst)
			util.DataKeyAddTypestr(builder, typeStr)
			key := util.DataKeyEnd(builder)
			builder.Finish(key)

			Key := string(key)

			if x, found := tcpCache.Get(Key); found {

				dataValue = x.(util.DataValue)
				log.Println("web: 获取到数据: ",dataValue)
				src, err := parseIPV4(conn.Laddr)
				if err != nil {
					log.Errorf("Error occured: ", err)
				}
				dst, err := parseIPV4(conn.Raddr)
				if err != nil {
					log.Errorf("Error occured: ", err)
				}
				ended, err := time.ParseInLocation("2006-01-02 15:04:05", dataValue.End_time, time.Local)
				if err != nil {
					log.Errorf("Error occured: ", err)
				}
				value := ended.UnixNano() / 1e6
				ch <- prometheus.MustNewConstMetric(c.Metrics["process_network_info"], prometheus.GaugeValue, float64(value), pid, process.User, process.Cmd, "ipv4/tcp", src, dst, dataValue.Status)

			}
		}
	}

}

//返回所有要监控的用户的进程消息(pid,user,cmd)
func getPidsExceptSomeUser() ([]util.Process, error) {
	var ret []util.Process
	exclude := mapset.NewSet()
	for _, t := range cfgs.Excluded_users {
		uid,ok:= mapUserUid.Load(t)
		if ok{
			exclude.Add(uid.(string))
		}
		//uid := map_user_uid[t]
		//exclude.Add(uid)
	}
	processes, err := procfs.AllProcs()
	if err != nil {
		log.Errorf("Error occured: %s", err)
		return nil, err
	}

	for _, process := range processes {
		cmd, err := process.Comm()
		if err != nil {
			log.Errorf("Error occured: %s", err)
			return nil, err
		}

		procStat, err := process.NewStatus()
		if err != nil {
			log.Errorf("Error occured: %s", err)
			return nil, err
		}
		uid := procStat.UIDs[0]
		pid := strconv.Itoa(process.PID)
		if !exclude.Contains(uid) {
			//uname := map_uid_cmd[uid]
			//map_uid_cmd[uid] = cmd
			mapUidCmd.Store(uid,cmd)
			ret = append(ret, util.Process{Pid: pid, User: uid, Cmd: cmd})
		}
	}
	return ret, nil
}



func (c *ProcCollector) GetIOPSThroughput(processes []util.Process)(processDiskInfoData []DiskInfo){
	var diskInfo DiskInfo
	for _,process:=range processes{
		pid := process.Pid
		pathIo :="/proc/"+pid +"/io"
		ioInfo1,err:=parseIOInfo(pathIo)
		if err != nil {
			log.Errorf("Error occured: %s", err)
		}
		time.Sleep(1*time.Second)
		ioInfo2,err:=parseIOInfo(pathIo)
		if err != nil {
			log.Errorf("Error occured: %s", err)
		}
		diskInfo.Read_IOPS=ioInfo2.SyscR-ioInfo1.SyscR
		diskInfo.Write_IOPS=ioInfo2.SyscW-ioInfo1.SyscW
		diskInfo.Read_Throughput=ioInfo2.ReadBytes-ioInfo1.ReadBytes
		diskInfo.Write_Throughput=ioInfo2.WriteBytes-ioInfo1.WriteBytes

		diskInfo.Pid=pid
		diskInfo.Uid=process.User
		diskInfo.Cmd=process.Cmd

		processDiskInfoData=append(processDiskInfoData,diskInfo)
	}
	return
}

func (c *ProcCollector) GetIOInfo(processes []util.Process)(processIOInfoData []IOInfo){

	for _,process:= range processes{
		pid := process.Pid
		pathIo :="/proc/"+pid +"/io"
		ioInfo,err:=parseIOInfo(pathIo)
		if err != nil {
			log.Errorf("Error occured: %s", err)
		}
		ioInfo.Pid=pid
		ioInfo.Uid=process.User
		ioInfo.Cmd=process.Cmd

		processIOInfoData=append(processIOInfoData,ioInfo)
	}
	return
}

func (c *ProcCollector) GetCPUAndPageInfo(processes []util.Process) (processCPUInfoData []CPUInfo,processPageInfoData []PageInfo){
	for _,process:= range processes {
		pid := process.Pid
		pathStat :="/proc/"+pid +"/stat"
		cpuInfo,pageInfo,err:= parseCPUAndPageInfo(pathStat)
		if err != nil {
			log.Errorf("Error occured: %s", err)
		}
		cpuInfo.pid=pid
		cpuInfo.uid=process.User
		cpuInfo.cmd=process.Cmd

		pageInfo.pid=pid
		pageInfo.uid=process.User
		pageInfo.cmd=process.Cmd

		processCPUInfoData=append(processCPUInfoData,cpuInfo)
		processPageInfoData=append(processPageInfoData,pageInfo)
	}
	return
}


func (c *ProcCollector) GetMemoryAndContextInfo(processes []util.Process) (processMemInfoData []MemoryInfo, processContextInfoData []ContextInfo) {
	for _, process := range processes {
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

func scrape() {
	//defer func() {
	//	if err := recover(); err != nil {
	//		log.Fatal("go routine fatal error occured:", err)
	//	}
	//}()
	processes, err := getPidsExceptSomeUser()
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}
	if len(processes)==0 {
		log.Error("出错!!!切片为空!")
	}
	for {
		GetConnInfoExceptSomeUser(processes)
		intervals := int64(1000 * cfgs.Check_interval_seconds)
		time.Sleep(time.Duration(intervals) * time.Millisecond)
	}
}

func (c *ProcCollector) GetGPUUtilization(processes []util.Process)(processGPUInfoData []GPUInfo){
	//var gpuInfo GPUInfo
	for _,process:=range processes{
		pid:=process.Pid
		pathGPU:="gpu.log"
		rowGPU,err:=parseGPUInfo(pathGPU)
		if err != nil {
			log.Errorf("Error occured at : %s", err)
		}
		for _,gpuInfo :=range rowGPU{
			if gpuInfo.Pid==pid {
				gpuInfo.Uid=process.User
				processGPUInfoData=append(processGPUInfoData,gpuInfo)
			}
		}
	}
	return
}

func GetConnInfoExceptSomeUser(processes []util.Process) {
	num++
	log.Info("exporter is collecting.Number of times: ", num)


	//traverse this array processes and get the pid and read file /tcp ,then store the key and value in data structure.(currently cache)
	for _, process := range processes {

		//fmt.Printf("Ranging CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)

		pid := process.Pid
		pathTcp := fmt.Sprintf("/proc/%s/net/tcp", pid)
		log.Info("采集： 生成/tcp地址: ", pathTcp)
		rowTcp, err := parseTCPInfo(pathTcp)
		if err != nil {
			log.Errorf("Error occured at Collect(): %s", err)
		}
		log.Info("读取到/tcp内容:", pathTcp)
		//fmt.Printf("CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
		//var dataKey util.DataKey
		var dataValue util.DataValue
		builder := flatbuffers.NewBuilder(0)
		for _, conn := range rowTcp {
			//fmt.Printf("1st CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
			Pid := builder.CreateString(pid)
			Src := builder.CreateString(conn.Laddr)
			Dst := builder.CreateString(conn.Raddr)
			typeStr := builder.CreateString("ipv4/tcp")

			util.DataKeyStart(builder)
			util.DataKeyAddPid(builder, Pid)
			util.DataKeyAddSrc(builder, Src)
			util.DataKeyAddDst(builder, Dst)
			util.DataKeyAddTypestr(builder, typeStr)
			key := util.DataKeyEnd(builder)
			builder.Finish(key)

			//fmt.Printf("2nd  CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
			Key := string(key)
			//fmt.Printf("3rd  CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)

			x, found := tcpCache.Get(Key)
			if found == true {
				log.Println("key has value.Update end time.size of the map: ", tcpCache.ItemCount())
				if tcpCache.ItemCount()==0{
					log.Println("出错!!!map中数据为0条 ")
				}

				endTime := time.Now().String()[:23]
				dataValue = x.(util.DataValue)
				dataValue.End_time = endTime

				log.WithFields(log.Fields{
				"Uid": dataValue.User,
				"Name":  dataValue.Name,
				"Status": dataValue.Status,
				"starttime":dataValue.Create_time,
				"lastupdatetime":dataValue.End_time,
				}).Info("更新cache记录")

				tcpCache.Set(Key, dataValue, cache.DefaultExpiration)
				log.Println("Set完毕。现在map的长度为 : ",tcpCache.ItemCount())
			} else if found == false {
				//fmt.Printf("before set CMD=====: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
				//fmt.Println("key has no value. first time created.")
				log.Println("key has no value. first time created. size of the map: ", tcpCache.ItemCount())
				if tcpCache.ItemCount()==0{
					log.Println("出错!!!map中数据为0条 ")
				}
				createTime := time.Now().String()[:23]
				endTime := createTime
				dataValue.User = process.User
				dataValue.Name = process.Cmd //cmdline
				dataValue.Status = conn.Status
				dataValue.Create_time = createTime
				dataValue.End_time = endTime

				log.WithFields(log.Fields{
					"Uid": dataValue.User,
					"Name":  dataValue.Name,
					"Status": dataValue.Status,
					"starttime":dataValue.Create_time,
					"lastupdatetime":dataValue.End_time,
				}).Info("开始往cache中存入数据")

				tcpCache.Set(Key, dataValue, cache.DefaultExpiration)
			}
		}
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

	go scrape()

	metrics := NewProcCollector(*metricsNamespaces)
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics)

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

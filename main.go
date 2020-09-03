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
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"testExporter/util"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/procfs"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// 指标结构体
type ProcCollector struct {
	Metrics map[string]*prometheus.Desc
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

	map_uid_cmd  map[string]string
	map_user_uid map[string]string
	tcpCache     *cache.Cache
	cfgs          = &util.Config{}
	num          uint64 = 0

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
	if err !=nil{
		log.Errorf("Error occured: ",err)
	}
	fileScanner := bufio.NewScanner(file)
	lineCount := 1
	for fileScanner.Scan() {
		if lineCount == lineNumber {
			return fileScanner.Text()
		}
		lineCount++
	}
	defer file.Close()

	return ""
}

func parseMemTotal() (float32, error) {
	path_meminfo := "/proc/meminfo"
	line := ReadLine(path_meminfo, 1)
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

// proc/$pid/status 计算内存占比
func parseMemInfo(file string) (MemoryInfo, error) {
	var memInfo MemoryInfo
	contents, err := ioutil.ReadFile(file)
	if err != nil {
		return MemoryInfo{}, err
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
				return MemoryInfo{}, err
			}
			memInfo.prss = v * 1024
		case "VmSize":
			value := strings.Trim(value, " kB") // remove last "kB"
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return MemoryInfo{}, err
			}
			memInfo.pvms = v * 1024
		case "VmSwap":
			value := strings.Trim(value, " kB") // remove last "kB"
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return MemoryInfo{}, err
			}
			memInfo.pswap = v * 1024
		}
	}
	total, err := parseMemTotal()
	if err != nil {
		return MemoryInfo{}, err
	}
	used := memInfo.prss
	memInfo.memper = (100 * float32(used) / float32(total))

	return memInfo, nil
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
			log.Errorf("error occured:",err)
			return nil,err
		}
		if err != nil {
			log.Errorf("error occured:",err)
			return nil,err
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
			"process_memory_info":    newGlobalCollector(namespace, "memory_info", "Process memory information", []string{"pid", "uid","cmd", "memtype"}),
			"process_memory_percent": newGlobalCollector(namespace, "memory_percent", "The percentage of memory used by the process", []string{"pid","uid","cmd"}),
			"process_network_info":   newGlobalCollector(namespace, "network_info", "TCP/UDP connection information opened by the process", []string{"pid","uid","cmd", "type", "src", "dst", "status"}),
		},
	}
}

func (c *ProcCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.Metrics {
		ch <- m
	}
}

func (c *ProcCollector) Collect(ch chan<- prometheus.Metric) {
	//log.Info("Visiting web page...")
	processMemoryInfo := c.GetMemoryInfo()
	for _, meminfo := range processMemoryInfo {
		prss := meminfo.prss
		pvms := meminfo.pvms
		pswap := meminfo.pswap
		memPer := meminfo.memper
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_info"], prometheus.GaugeValue, float64(prss), meminfo.pid,meminfo.user, meminfo.pname, "rss")   //pid user cmd `rss`
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_info"], prometheus.GaugeValue, float64(pvms), meminfo.pid,meminfo.user, meminfo.pname, "vms")   //pid user cmd `vms`
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_info"], prometheus.GaugeValue, float64(pswap), meminfo.pid,meminfo.user,meminfo.pname, "swap") //pid user cmd `swap`
		ch <- prometheus.MustNewConstMetric(c.Metrics["process_memory_percent"], prometheus.GaugeValue, float64(memPer), meminfo.pid,meminfo.user,meminfo.pname)     //pid user cmd
	}
	//log.Println("size of the map: ", tcpCache.ItemCount())
	processes, err := getPidsExceptSomeUser()
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}
	//log.Info("开始读缓存")
	for _, process := range processes {
		pid := process.Pid
		path_tcp := fmt.Sprintf("/proc/%s/net/tcp", pid)
		//Info("生成/tcp地址: ",path_tcp)
		row_tcp, err := parseTCPInfo(path_tcp)
		if err != nil {
			log.Errorf("Error occured at Collect(): %s", err)
		}
		//var dataKey util.DataKey
		var dataValue util.DataValue
		builder:=flatbuffers.NewBuilder(0)

		//log.Println("Before web get: Cmd: ",process.Cmd)
		for _, conn := range row_tcp {
			Pid:=builder.CreateString(pid)
			Src:=builder.CreateString(conn.Laddr)
			Dst:=builder.CreateString(conn.Raddr)
			typeStr:=builder.CreateString("ipv4/tcp")

			util.DataKeyStart(builder)
			util.DataKeyAddPid(builder,Pid)
			util.DataKeyAddSrc(builder,Src)
			util.DataKeyAddDst(builder,Dst)
			util.DataKeyAddTypestr(builder,typeStr)
			key:=util.DataKeyEnd(builder)
			builder.Finish(key)

			Key:=string(key)

			if x, found := tcpCache.Get(Key); found {

				dataValue = x.(util.DataValue)
				//log.Println("web: 获取到数据: ",dataValue)
				src, err :=parseIPV4(conn.Laddr)
				if err !=nil{
					log.Errorf("Error occured: ",err)
				}
				dst,err :=parseIPV4(conn.Raddr)
				if err !=nil{
					log.Errorf("Error occured: ",err)
				}
				ended, err := time.ParseInLocation("2006-01-02 15:04:05", dataValue.End_time, time.Local)
				if err !=nil{
					log.Errorf("Error occured: ",err)
				}
				value := ended.UnixNano() / 1e6
				ch <- prometheus.MustNewConstMetric(c.Metrics["process_network_info"], prometheus.GaugeValue, float64(value), pid,process.User, process.Cmd, "ipv4/tcp", src, dst, dataValue.Status)

			}
		}
	}

}

//返回所有要监控的用户的进程消息(pid,user,cmd)
func getPidsExceptSomeUser() ([]util.Process, error) {
	var ret []util.Process
	exclude := mapset.NewSet()
	for _, t := range cfgs.Excluded_users {
		uid := map_user_uid[t]
		exclude.Add(uid)
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
			map_uid_cmd[uid]=cmd
			ret = append(ret, util.Process{Pid: pid, User: uid, Cmd: cmd})
		}
	}
	return ret, nil
}

func (c *ProcCollector) GetMemoryInfo() (processMemInfoData []MemoryInfo) {
	processes, err := getPidsExceptSomeUser()
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}
	for _, process := range processes {
		pid := process.Pid
		path_status := "/proc/" + pid + "/status"
		memoryInfo, err := parseMemInfo(path_status)
		if err != nil {
			fmt.Println(err.Error())
		}
		memoryInfo.pid = pid
		memoryInfo.pname = process.Cmd
		memoryInfo.user = process.User
		processMemInfoData = append(processMemInfoData, memoryInfo)
	}
	return
}

func scrape() {
	defer func() {
		if err := recover();err != nil {
			log.Fatal("go routine fatal error occured:",err)
		}
	}()
	for {
		GetConnInfoExceptSomeUser()
		intervals := int64(1000 * cfgs.Check_interval_seconds)
		time.Sleep(time.Duration(intervals) * time.Millisecond)
	}
}

func GetConnInfoExceptSomeUser() {
	num++
	log.Info("exporter is collecting.Number of times: ", num)

	processes, err := getPidsExceptSomeUser()
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}

	//traverse this array processes and get the pid and read file /tcp ,then store the key and value in data structure.(currently cache)
	for _, process := range processes {

		//fmt.Printf("Ranging CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)

		pid := process.Pid
		path_tcp := fmt.Sprintf("/proc/%s/net/tcp", pid)
		//log.Info("采集： 生成/tcp地址: ",path_tcp)
		row_tcp, err := parseTCPInfo(path_tcp)
		if err != nil {
			log.Errorf("Error occured at Collect(): %s", err)
		}
		//log.Info("读取到/tcp内容:",path_tcp)
		//fmt.Printf("CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
		//var dataKey util.DataKey
		var dataValue util.DataValue
		builder := flatbuffers.NewBuilder(0)
		for _, conn := range row_tcp{
			//fmt.Printf("1st CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
			Pid:=builder.CreateString(pid)
			Src:=builder.CreateString(conn.Laddr)
			Dst:=builder.CreateString(conn.Raddr)
			typeStr:=builder.CreateString("ipv4/tcp")

			util.DataKeyStart(builder)
			util.DataKeyAddPid(builder,Pid)
			util.DataKeyAddSrc(builder,Src)
			util.DataKeyAddDst(builder,Dst)
			util.DataKeyAddTypestr(builder,typeStr)
			key:=util.DataKeyEnd(builder)
			builder.Finish(key)

			//fmt.Printf("2nd  CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
			Key := string(key)
			//fmt.Printf("3rd  CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)

			x, found := tcpCache.Get(Key);
			if  found ==true{
				end_time := time.Now().String()[:23]
				dataValue = x.(util.DataValue)
				dataValue.End_time = end_time

				//log.WithFields(log.Fields{
				//"Uid": dataValue.User,
				//"Name":  dataValue.Name,
				//"Status": dataValue.Status,
				//"starttime":dataValue.Create_time,
				//"lastupdatetime":dataValue.End_time,
				//}).Info("更新cache记录")

				tcpCache.Set(Key, dataValue, cache.DefaultExpiration)
			}else if found==false{
				//fmt.Printf("before set CMD=====: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
				//fmt.Println("key has no value. first time created.")
				create_time := time.Now().String()[:23]
				end_time := create_time
				dataValue.User = process.User
				dataValue.Name = process.Cmd//cmdline
				dataValue.Status = conn.Status
				dataValue.Create_time = create_time
				dataValue.End_time = end_time

				//log.WithFields(log.Fields{
				//	"Uid": dataValue.User,
				//	"Name":  dataValue.Name,
				//	"Status": dataValue.Status,
				//	"starttime":dataValue.Create_time,
				//	"lastupdatetime":dataValue.End_time,
				//}).Info("开始往cache中存入数据")

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
	flag.BoolVar(&h, "h", false, "this help")
	flag.BoolVar(&v, "v", false, "show version and exit")
	flag.Usage = usage
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	tcpCache = cache.New(2*time.Minute, 10*time.Second)
	map_uid_cmd = make(map[string]string)
	map_user_uid = make(map[string]string)
	path_user := "/etc/passwd"
	contents, err := ioutil.ReadFile(path_user)
	if err != nil {
		log.Errorf("Error occured: ", err)
	}
	lines := bytes.Split(contents, []byte("\n"))

	for i := 0; i < len(lines)-1; i++ {
		l := strings.Split(string(lines[i]), ":")
		user := l[0]
		uid := l[2]
		//map_uid_cmd[uid] = user
		map_user_uid[user] = uid
	}

	/* 日志轮转相关函数
	`WithLinkName` 为最新的日志建立软连接
	`WithRotationTime` 设置日志分割的时间，隔多久分割一次
	WithMaxAge 和 WithRotationCount二者只能设置一个
	 `WithMaxAge` 设置文件清理前的最长保存时间
	 `WithRotationCount` 设置文件清理前最多保存的个数
	*/
	// 下面配置日志每隔 1 天轮转一个新文件，保留最近 2周的日志文件，多余的自动清理掉。
	path := "./log/test.log"
	writer, _ = rotatelogs.New(
		path+".%Y%m%d",
		rotatelogs.WithLinkName(path),
		rotatelogs.WithMaxAge(time.Duration(336)*time.Hour),//保留2周内的日志
		rotatelogs.WithRotationTime(time.Duration(24)*time.Hour),//按天切分
	)

	log.SetOutput(writer)
	log.SetReportCaller(true)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",//时间格式化
	})
	//log.SetFormatter(&log.JSONFormatter{})

}

func main() {
	flag.Parse()
	if h {
		flag.Usage()
		os.Exit(1)
	}
	if v {
		fmt.Println("process_network_exporter: v", version)
		os.Exit(1)
	}

	viper.SetConfigType("yaml")

	//configPath := "config.yaml"
	viper.SetConfigFile(*configPaths)

	err := viper.ReadInConfig()
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
	defer writer.Close()
}

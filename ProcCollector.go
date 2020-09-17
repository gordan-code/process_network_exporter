package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	log "github.com/cihub/seelog"
	mapset "github.com/deckarep/golang-set"
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testExporter/util"
	"time"
)

// 指标结构体
type ProcCollector struct{}

func collectNetworkInfo() []prometheus.Metric{
	var targetMetrics []prometheus.Metric


	return targetMetrics
}

var (
	cpuPercentDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "cpu", "percent"),
		"CPU Percent of the process.",
		[]string{"pid", "uid", "cmd", "mode"},
		nil,
	)

	//Process memory information
	memInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "memory", "info"),
		"Process memory information.",
		[]string{"pid", "uid", "cmd", "memtype"},
		nil,
	)

	//The percentage of memory used by the process
	memPerDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "memory", "percent"),
		"The percentage of memory used by the process.",
		[]string{"pid", "uid", "cmd"},
		nil,
	)

	networkInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "network", "info"),
		"TCP connection information opened by the process.",
		[]string{"pid", "uid", "cmd", "type", "src", "dst", "status"},
		nil,
	)
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
	if err != nil {
		log.Errorf("error occured:", err)
	}
	return ""
}

//返回所有要监控的用户的进程消息(pid,user,cmd)
func getPidsExceptSomeUser() ([]util.Process, error) {
	var ret []util.Process
	exclude := mapset.NewSet()
	for _, t := range cfgs.Excluded_users {
		uid, ok := mapUserUid.Load(t)
		if ok {
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
			mapUidCmd.Store(uid, cmd)
			ret = append(ret, util.Process{Pid: pid, User: uid, Cmd: cmd})
		}
	}
	return ret, nil
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

// proc/$pid/status 计算内存占比
func parseMemAndContextInfo(file string) (MemoryInfo, error) {
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

func GetMemoryInfo(processes []util.Process) (processMemInfoData []MemoryInfo) {
	for _, process := range processes {
		pid := process.Pid
		pathStatus := "/proc/" + pid + "/status"
		memoryInfo, err := parseMemAndContextInfo(pathStatus)
		if err != nil {
			log.Errorf("Error occured: %s", err)
		}
		memoryInfo.pid = pid
		memoryInfo.pname = process.Cmd
		memoryInfo.user = process.User

		processMemInfoData = append(processMemInfoData, memoryInfo)
	}
	return
}

func GetConnInfoExceptSomeUser(processes *[]util.Process) {
	num++
	//log.Info("exporter is collecting.Number of times: ", num)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(10))
		defer cancel()
		for _, process := range *processes {

			//fmt.Printf("Ranging CMD: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)

			pid := process.Pid
			pathTcp := fmt.Sprintf("/proc/%s/net/tcp", pid)
			//log.Info("采集： 生成/tcp地址: ", pathTcp)
			rowTcp, err := parseTCPInfo(pathTcp)
			if err != nil {
				log.Errorf("Error occured at Collect(): %s", err)
			}
			//log.Info("读取到/tcp内容:", pathTcp)
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
					//log.Println("key has value.Update end time.size of the map: ", tcpCache.ItemCount())
					if tcpCache.ItemCount() == 0 {
						log.Info("//向cache中存入数据前出错!!!map中数据为0条 ")
					}

					endTime := time.Now().String()[:23]
					dataValue = x.(util.DataValue)
					dataValue.End_time = endTime

					log.Infof("更新cache记录:%+v", dataValue)

					tcpCache.Set(Key, dataValue, cache.DefaultExpiration)
					log.Infof("Set完毕。现在map的长度为 :%d ", tcpCache.ItemCount())
				} else if found == false {
					//fmt.Printf("before set CMD=====: %s User:%s Pid:%s \n",process.Cmd,process.User,process.Pid)
					//fmt.Println("key has no value. first time created.")
					//log.Println("key has no value. first time created. size of the map: ", tcpCache.ItemCount())
					if tcpCache.ItemCount() == 0 {
						log.Error("//向cache中存入数据时出错!!!map中数据为0条 ")
					}
					createTime := time.Now().String()[:23]
					endTime := createTime
					dataValue.User = process.User
					dataValue.Name = process.Cmd //cmdline
					dataValue.Status = conn.Status
					dataValue.Create_time = createTime
					dataValue.End_time = endTime

					log.Infof("开始往cache中存入数据:%+v", dataValue)

					tcpCache.Set(Key, dataValue, cache.DefaultExpiration)
				}
			}
		}

		select {
		case <-ctx.Done():
			log.Error("收到超时信号,采集退出")
		default:
			//log.Info(config.Targets[i].Host,":指标采集完成",len(targetMetrics))
		}
		wg.Done()
	}()
	wg.Wait()
}

func (c ProcCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- memInfoDesc
	ch <- memPerDesc
	ch <- networkInfoDesc
}

func (c ProcCollector) Collect(ch chan<- prometheus.Metric) {
	//log.Info("Visiting web page...")
	//lock.RLock()
	//for _, metric := range metrics {
	//	if metric != nil{
	//		ch <- metric
	//	}
	//}
	//lock.RUnlock()

	processes, err := getPidsExceptSomeUser()
	if len(processes) == 0 {
		log.Error("出错!!!切片为空!")
	}
	if err != nil {
		log.Errorf("Error occured: %s", err)
	}

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
		ch <- prometheus.MustNewConstMetric(memInfoDesc, prometheus.GaugeValue, float64(prss), meminfo.pid, meminfo.user, meminfo.pname, "rss")   //pid user cmd `rss`
		ch <- prometheus.MustNewConstMetric(memInfoDesc, prometheus.GaugeValue, float64(pvms), meminfo.pid, meminfo.user, meminfo.pname, "vms")   //pid user cmd `vms`
		ch <- prometheus.MustNewConstMetric(memInfoDesc, prometheus.GaugeValue, float64(pswap), meminfo.pid, meminfo.user, meminfo.pname, "swap") //pid user cmd `swap`
		ch <- prometheus.MustNewConstMetric(memPerDesc, prometheus.GaugeValue, float64(memPer), meminfo.pid, meminfo.user, meminfo.pname)         //pid user cmd
	}

	//Get Connection Info
	log.Infof("size of the map: %d", tcpCache.ItemCount())
	if tcpCache.ItemCount() == 0 {
		log.Error("读取Connection Info数据时出错!!!map中数据为0条 ")
	}
	//log.Info("开始读缓存")

	for _, process := range processes {
		pid := process.Pid
		pathTcp := fmt.Sprintf("/proc/%s/net/tcp", pid)
		//log.Info("生成/tcp地址: ",path_tcp)
		rowTcp, err := parseTCPInfo(pathTcp)
		if err != nil {
			log.Errorf("Error occured at parseTCPInfo(): %s", err)
		}
		//var dataKey util.DataKey
		var dataValue util.DataValue
		builder := flatbuffers.NewBuilder(0)

		//log.Println("Before web get: Cmd: ",process.Cmd)
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
				//log.Println("web: 获取到connection数据: ",dataValue)
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
				ch <- prometheus.MustNewConstMetric(networkInfoDesc, prometheus.GaugeValue, float64(value), pid, process.User, process.Cmd, "ipv4/tcp", src, dst, dataValue.Status)

			}
		}
	}

}
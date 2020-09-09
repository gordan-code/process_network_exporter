package main

type DiskInfo struct{
	Pid string
	Uid string
	Cmd string
	Read_IOPS uint64
	Write_IOPS uint64
	Read_Throughput uint64
	Write_Throughput uint64
}

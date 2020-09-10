package main

type GPUInfo struct{
	Pid string
	Uid string
	Cmd string
	Utilization float64 //GPU 利用率
	Mem float64			//显存利用率
	Idx int
}

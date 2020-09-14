package main

type MemoryInfo struct {
	pid    string
	pname  string //process cmdline
	user   string
	prss   uint64
	pvms   uint64
	pswap  uint64
	memper float32
}

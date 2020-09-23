package BO

type MemoryInfo struct {
	Pid    string
	Pname  string //process cmdline
	User   string
	Prss   uint64
	Pvms   uint64
	Pswap  uint64
	Memper float32
}

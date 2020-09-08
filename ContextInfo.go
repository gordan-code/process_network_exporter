package main

type ContextInfo struct {
	pid                        string
	uid                        string
	cmd                        string
	voluntary_ctxt_switches    uint64
	nonvoluntary_ctxt_switches uint64
}

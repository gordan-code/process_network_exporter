package main

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

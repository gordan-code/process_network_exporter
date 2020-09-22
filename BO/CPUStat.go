package BO

type CPUStat struct {
	User        float64
	Nice        float64
	System      float64
	Idle        float64
	Iowait      float64
	Irq         float64
	Softirq     float64
	Stealstolen float64
	Guest       float64
	Guest_nice  float64
}

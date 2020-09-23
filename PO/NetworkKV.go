package PO

type NetworkKey struct {
	Pid     string		`json:"pid"`
	Src     string		`json:"src"`
	Dst     string		`json:"dst"`
	TypeStr string		`json:"type"`
}

type NetworkValue struct {
	User		string
	Name        string  //cmd of process
	Status      string
	Create_time string
	End_time    string
}

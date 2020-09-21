package test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)
func isInSlice(s string,fields []string) bool {
	for _,field := range fields{
		if field == s{
			return true
		}
	}
	return false
}
func TestData(t *testing.T){
	client := &http.Client{}
	resp, err := client.Get("http://localhost:9500/metrics")
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(body))

	result:=string(body)

	metrics:=[]string{"process_memory_info","process_memory_percent","process_network_info"}
	for _,metric := range metrics{
		if strings.Contains(result,metric){
			fmt.Println(metric+": 包含")
		}else {
			fmt.Println(metric+": 不包含")
		}
	}

}

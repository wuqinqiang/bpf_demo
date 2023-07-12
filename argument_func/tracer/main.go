package main

import (
	"flag"
	"fmt"
	"github.com/iovisor/gobpf/bcc"
	"log"
	"os"
	"os/signal"
)

var eBPF_Text = `
#include <uapi/linux/ptrace.h>
#include <linux/string.h>

BPF_PERF_OUTPUT(events);

inline int function_was_called(struct pt_regs *ctx) {
   void* stackAddr = (void*)ctx->sp;
   long parameter_value;
   bpf_probe_read(&parameter_value, sizeof(parameter_value), stackAddr+8);

   long tmp = 520;
   bpf_probe_write_user(stackAddr+8, &tmp, sizeof(tmp));

   events.perf_submit(ctx, &parameter_value, sizeof(parameter_value));
   return 0;
}
`
var tracePrg string
var traceFun string

func init() {
	flag.StringVar(&tracePrg, "binary", "", "")
	flag.StringVar(&traceFun, "func", "", "The function to probe")
}

func main() {
	flag.Parse()

	bpfModule := bcc.NewModule(eBPF_Text, []string{})
	uprobeFd, err := bpfModule.LoadUprobe("function_was_called")
	if err != nil {
		panic(err)
	}
	if err = bpfModule.AttachUprobe(tracePrg,
		traceFun, uprobeFd, -1); err != nil {
		panic(err)
	}

	table := bcc.NewTable(bpfModule.TableId("events"), bpfModule)

	outputChannel := make(chan []byte)
	lostChan := make(chan uint64)

	perfMap, err := bcc.InitPerfMap(table, outputChannel, lostChan)
	if err != nil {
		log.Fatal(err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		for {
			value := <-outputChannel
			fmt.Println(string(value))
		}
	}()
	perfMap.Start()
	<-sigCh
	perfMap.Stop()
}

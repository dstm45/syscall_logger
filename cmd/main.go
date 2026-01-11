package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dstm45/syscall_logger/build"
	"github.com/dstm45/syscall_logger/internal/handler"
)

func main() {
	log.SetOutput(os.Stdout)
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatalln(err)
	}
	init, err := handler.Initialize()
	if err != nil {
		log.Fatalln("Erreur lors du chargment des programmes dans le kernel", err)
	}
	defer init.Close()
	log.Println("Programmes eBPF chargés. Appuyez sur Ctrl+C pour quitter.")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	log.Println("Surveillance active...")

	for {
		select {
		case <-stopper:
			log.Println("Fermeture du programme...")
			return
		case <-ticker.C:
			var key uint64
			var value build.MainDataT

			mapIterator := init.MainObject.Datatable.Iterate()
			for mapIterator.Next(&key, &value) {
				if handler.IsExcluded(value.Filename) {
					continue
				}
				log.Printf("[commande]: %s [pid]: %d [filename]: %s [uid]: %d", handler.Int8ToString(value.ProcessName), value.Pid, handler.Int8ToString(value.Filename), value.Uid)
				init.MainObject.Datatable.Delete(&key)
			}
			if err := mapIterator.Err(); err != nil {
				log.Printf("Erreur itération: %v", err)
			}
		}
	}
}

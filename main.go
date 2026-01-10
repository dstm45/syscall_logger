package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	log.SetOutput(os.Stdout)
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatalln(err)
	}
	init, err := Initialize()
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
			var value mainDataT

			mapIterator := init.MainObject.Datatable.Iterate()
			for mapIterator.Next(&key, &value) {
				if isExcluded(value.Filename) {
					continue
				}
				log.Printf("[commande]: %s [pid]: %d [filename]: %s [uid]: %d", int8ToString(value.ProcessName), key>>32, int8ToString(value.Filename), value.Uid)
				init.MainObject.Datatable.Delete(&key)
			}
			if err := mapIterator.Err(); err != nil {
				log.Printf("Erreur itération: %v", err)
			}
		}
	}
}

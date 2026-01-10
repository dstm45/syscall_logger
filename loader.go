package main

import (
	"log"

	"github.com/cilium/ebpf/link"
)

type Loader struct {
	OpenatEnter   link.Link
	OpenatExit    link.Link
	LsmFileOpen   link.Link
	LsmPathUnlink link.Link
	MainObject    mainObjects
}

func Initialize() (*Loader, error) {
	var objets mainObjects
	err := loadMainObjects(&objets, nil)
	if err != nil {
		return nil, err
	}
	openatEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objets.TraceFiles, nil)
	if err != nil {
		return nil, err
	}
	openatExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objets.CheckFiles, nil)
	if err != nil {
		return nil, err
	}
	RestrictFileAccess, err := link.AttachLSM(link.LSMOptions{Program: objets.RestrictFileAccess})
	if err != nil {
		return nil, err
	}

	RestrictFileDeletion, err := link.AttachLSM(link.LSMOptions{Program: objets.RestrictFileDeletion})
	if err != nil {
		return nil, err
	}
	loader := Loader{
		OpenatEnter:   openatEnter,
		OpenatExit:    openatExit,
		LsmFileOpen:   RestrictFileAccess,
		LsmPathUnlink: RestrictFileDeletion,
		MainObject:    objets,
	}
	err = RestrictFiles(loader)
	if err != nil {
		log.Fatalln(err)
	}
	return &loader, nil
}

func (l *Loader) Close() {
	l.LsmFileOpen.Close()
	l.LsmPathUnlink.Close()
	l.OpenatEnter.Close()
	l.OpenatExit.Close()
}

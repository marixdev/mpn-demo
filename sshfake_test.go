package main

import (
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func TestFakeSFTP(t *testing.T) {
	resetData()
	f := newFakeSSH()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := f.Dial("shop")
		if err != nil {
			t.Error("dial", err)
			return
		}
		t.Log("dialed")
		sc, err := sftp.NewClient(c)
		if err != nil {
			t.Error("sftp", err)
			return
		}
		t.Log("sftp open")
		wd, err := sc.Getwd()
		t.Log("wd", wd, err)
		fi, err := sc.ReadDir(wd)
		t.Log("readdir", len(fi), err)
		for _, x := range fi {
			t.Log(" ", x.Name(), x.IsDir())
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

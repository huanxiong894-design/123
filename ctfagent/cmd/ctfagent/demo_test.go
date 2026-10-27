package main

import (
	"os"
	"testing"
)

// 演示是"第一次接触这个项目的人"唯一一定会跑的命令，必须永远可跑、永远通过。
// 它同时守着一条红线：题库的答案文件（flag.txt）不能出现在 agent 的工作目录里，
// 所以演示题故意把 flag 放在 secret.txt 里。
func TestCmdDemoEndToEnd(t *testing.T) {
	old := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = devnull
	code := cmdDemo([]string{"-v=false"})
	os.Stdout = old
	devnull.Close()
	if code != 0 {
		t.Fatalf("demo 退出码 = %d，应该是 0", code)
	}
}

func TestParseDurations(t *testing.T) {
	got, err := parseDurations("30m, 20m")
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err=%v", got, err)
	}
	if _, err := parseDurations("0s"); err == nil {
		t.Fatal("非正数应报错")
	}
	if _, err := parseDurations(""); err == nil {
		t.Fatal("空串应报错")
	}
	if _, err := parseDurations("abc"); err == nil {
		t.Fatal("非法时长应报错")
	}
}

package main

import (
	"fmt"
	"os"

	. "github.com/carlpett/winlsa"
)

func main() {
	luids, err := GetLogonSessions()
	if err != nil {
		fmt.Println("GetLogonSessions:", err)
		os.Exit(1)
	}

	for _, luid := range luids {
		sd, err := GetLogonSessionData(&luid)
		if err != nil {
			fmt.Println("LsaGetLogonSessionData:", err)
			os.Exit(1)
		}

		fmt.Printf("logonid: %v\nlogontype: %v\nusername: %s\nsession: %v\nsid: %s\n\n", luid, sd.LogonType, sd.UserName, sd.Session, sd.Sid)
	}
}

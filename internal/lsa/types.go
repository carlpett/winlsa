package lsa

import (
	"golang.org/x/sys/windows"
)

type LUID struct {
	lowPart  uint32
	highPart int32
}

type LSA_LAST_INTER_LOGON_INFO struct {
	LastSuccessfulLogon                        uint64
	LastFailedLogon                            uint64
	FailedAttemptCountSinceLastSuccessfulLogon uint32
}

type SECURITY_LOGON_SESSION_DATA struct {
	Size                  uint32
	LogonId               LUID
	UserName              LSA_UNICODE_STRING
	LogonDomain           LSA_UNICODE_STRING
	AuthenticationPackage LSA_UNICODE_STRING
	LogonType             uint32
	Session               uint32
	Sid                   *windows.SID
	LogonTime             uint64
	LogonServer           LSA_UNICODE_STRING
	DnsDomainName         LSA_UNICODE_STRING
	Upn                   LSA_UNICODE_STRING
	UserFlags             uint32
	LastLogonInfo         LSA_LAST_INTER_LOGON_INFO
	LogonScript           LSA_UNICODE_STRING
	ProfilePath           LSA_UNICODE_STRING
	HomeDirectory         LSA_UNICODE_STRING
	HomeDirectoryDrive    LSA_UNICODE_STRING
	LogoffTime            uint64
	KickOffTime           uint64
	PasswordLastSet       uint64
	PasswordCanChange     uint64
	PasswordMustChange    uint64
}

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

package winlsa

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/carlpett/winlsa/internal/lsa"
)

// A LUID is a locally unique identifier guaranteed to be unique on the
// operating system that generated it until the system is restarted.
//
// In the context of winlsa, it is a session identifier.
type LUID = lsa.LUID

type LogonType uint32

func (lt LogonType) String() string {
	switch lt {
	case LogonTypeInteractive:
		return "Interactive"
	case LogonTypeNetwork:
		return "Network"
	case LogonTypeBatch:
		return "Batch"
	case LogonTypeService:
		return "Service"
	case LogonTypeProxy:
		return "Proxy"
	case LogonTypeUnlock:
		return "Unlock"
	case LogonTypeNetworkCleartext:
		return "NetworkCleartext"
	case LogonTypeNewCredentials:
		return "NewCredentials"
	case LogonTypeRemoteInteractive:
		return "RemoteInteractive"
	case LogonTypeCachedInteractive:
		return "CachedInteractive"
	case LogonTypeCachedRemoteInteractive:
		return "CachedRemoteInteractive"
	case LogonTypeCachedUnlock:
		return "CachedUnlock"
	default:
		return "UndefinedLogonType"
	}
}

const (
	LogonTypeInteractive LogonType = iota + 2
	LogonTypeNetwork
	LogonTypeBatch
	LogonTypeService
	LogonTypeProxy
	LogonTypeUnlock
	LogonTypeNetworkCleartext
	LogonTypeNewCredentials
	LogonTypeRemoteInteractive
	LogonTypeCachedInteractive
	LogonTypeCachedRemoteInteractive
	LogonTypeCachedUnlock
)

type LogonSessionData struct {
	UserName                                   string
	LogonDomain                                string
	AuthenticationPackage                      string
	LogonType                                  LogonType
	Session                                    uint32
	Sid                                        *windows.SID
	LogonTime                                  time.Time
	LogonServer                                string
	DnsDomainName                              string
	Upn                                        string
	UserFlags                                  uint32
	LastSuccessfulLogon                        time.Time
	LastFailedLogon                            time.Time
	FailedAttemptCountSinceLastSuccessfulLogon uint32
	LogonScript                                string
	ProfilePath                                string
	HomeDirectory                              string
	HomeDirectoryDrive                         string
	LogoffTime                                 time.Time
	KickOffTime                                time.Time
	PasswordLastSet                            time.Time
	PasswordCanChange                          time.Time
	PasswordMustChange                         time.Time
}

func newLogonSessionData(data *lsa.SECURITY_LOGON_SESSION_DATA) *LogonSessionData {
	var sid *windows.SID
	if data.Sid != nil {
		sid, _ = data.Sid.Copy()
	}
	return &LogonSessionData{
		UserName:              stringFromLSAString(data.UserName),
		LogonDomain:           stringFromLSAString(data.LogonDomain),
		AuthenticationPackage: stringFromLSAString(data.AuthenticationPackage),
		LogonType:             LogonType(data.LogonType),
		Session:               data.Session,
		Sid:                   sid,
		LogonTime:             timeFromUint64(data.LogonTime),
		LogonServer:           stringFromLSAString(data.LogonServer),
		DnsDomainName:         stringFromLSAString(data.DnsDomainName),
		Upn:                   stringFromLSAString(data.Upn),
		UserFlags:             data.UserFlags,
		LogonScript:           stringFromLSAString(data.LogonScript),
		ProfilePath:           stringFromLSAString(data.ProfilePath),
		HomeDirectory:         stringFromLSAString(data.HomeDirectory),
		HomeDirectoryDrive:    stringFromLSAString(data.HomeDirectoryDrive),
		LogoffTime:            timeFromUint64(data.LogoffTime),
		KickOffTime:           timeFromUint64(data.KickOffTime),
		PasswordLastSet:       timeFromUint64(data.PasswordLastSet),
		PasswordCanChange:     timeFromUint64(data.PasswordCanChange),
		PasswordMustChange:    timeFromUint64(data.PasswordMustChange),
		LastSuccessfulLogon:   timeFromUint64(data.LastLogonInfo.LastSuccessfulLogon),
		LastFailedLogon:       timeFromUint64(data.LastLogonInfo.LastFailedLogon),
		FailedAttemptCountSinceLastSuccessfulLogon: data.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon,
	}
}

func stringFromLSAString(s lsa.LSA_UNICODE_STRING) string {
	if s.Buffer == 0 || s.Length == 0 {
		return ""
	}
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(s.Buffer))[:s.Length])
}
func timeFromUint64(nsec uint64) time.Time {
	if nsec == 0 || nsec == ^uint64(0)>>1 {
		return time.Time{}
	}
	const windowsEpoch = 116444736000000000
	return time.Unix(0, int64(nsec-windowsEpoch)*100)
}

func GetLogonSessions() ([]LUID, error) {
	var cnt uint32
	var buffer uintptr
	err := lsa.LsaEnumerateLogonSessions(&cnt, &buffer)
	if err != nil {
		return nil, err
	}

	data := (*[]LUID)(unsafe.Pointer(&buffer))
	luids := make([]LUID, cnt)
	for idx := uint32(0); idx < cnt; idx++ {
		luids[idx] = (*data)[idx]
	}

	err = lsa.LsaFreeReturnBuffer(buffer)
	if err != nil {
		return nil, err
	}
	return luids, nil
}
func GetLogonSessionData(luid *LUID) (*LogonSessionData, error) {
	var dataBuffer *lsa.SECURITY_LOGON_SESSION_DATA
	err := lsa.LsaGetLogonSessionData(luid, &dataBuffer)
	if err != nil {
		return nil, err
	}
	sessionData := newLogonSessionData(dataBuffer)

	err = lsa.LsaFreeReturnBuffer(uintptr(unsafe.Pointer(dataBuffer)))
	if err != nil {
		return nil, err
	}

	return sessionData, nil
}

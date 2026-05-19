//go:build windows

package envvars

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Scope describes whether to write env vars system-wide (HKLM) or per-user (HKCU).
type Scope int

const (
	ScopeSystem Scope = iota // HKLM\System\CurrentControlSet\Control\Session Manager\Environment
	ScopeUser                // HKCU\Environment
)

// windowsManager writes env vars to the registry (machine or user scope) and
// broadcasts WM_SETTINGCHANGE so already-running processes pick them up.
//
// Per the design, Connect *fully owns* its variables: each Apply replaces any
// previous value, and Remove deletes the values entirely. We do not attempt
// to merge with pre-existing user PROXY settings; the assumption is that the
// endpoint is provisioned with Connect as the only proxy controller.
type windowsManager struct {
	// Scope defaults to ScopeSystem; can be flipped to ScopeUser by callers.
	Scope Scope

	// also write WinINet ProxyServer key (HKCU\...\Internet Settings)
	WriteWinINet bool

	// also run `netsh winhttp set proxy <addr>` (machine-wide WinHTTP)
	WriteWinHTTP bool
}

// newManager returns the default Windows manager (system scope, both legacy
// proxy locations enabled).
func newManager() Manager {
	return &windowsManager{
		Scope:        ScopeSystem,
		WriteWinINet: true,
		WriteWinHTTP: true,
	}
}

// Apply writes the managed env vars to the registry and broadcasts the change.
// Returns the list of registry/legacy-target paths that were touched.
func (w *windowsManager) Apply(v Vars) ([]string, error) {
	pairs := varsToEnvPairs(v)
	if len(pairs) == 0 {
		return nil, nil
	}
	root, sub, err := openEnvKey(w.Scope, registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	var touched []string
	var errs []error
	for name, value := range pairs {
		if err := root.SetStringValue(name, value); err != nil {
			errs = append(errs, fmt.Errorf("registry set %s: %w", name, err))
			continue
		}
	}
	if len(errs) == 0 {
		touched = append(touched, sub)
	}

	if w.WriteWinINet && v.HTTPSProxy != "" {
		if err := writeWinINetProxy(stripURLScheme(v.HTTPSProxy)); err != nil {
			errs = append(errs, fmt.Errorf("wininet: %w", err))
		} else {
			touched = append(touched, `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
		}
	}
	if w.WriteWinHTTP && v.HTTPSProxy != "" {
		if out, err := setNetshWinHTTPProxy(stripURLScheme(v.HTTPSProxy)); err != nil {
			errs = append(errs, fmt.Errorf("netsh winhttp: %w (output: %s)", err, out))
		} else {
			touched = append(touched, "netsh winhttp")
		}
	}

	broadcastEnvChange()
	return touched, errors.Join(errs...)
}

// Remove deletes the managed env vars and clears the legacy proxy locations.
func (w *windowsManager) Remove() ([]string, error) {
	root, sub, err := openEnvKey(w.Scope, registry.SET_VALUE)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	var touched []string
	var errs []error
	for _, name := range managedEnvNames() {
		if err := root.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			errs = append(errs, fmt.Errorf("registry del %s: %w", name, err))
		}
	}
	touched = append(touched, sub)

	if w.WriteWinINet {
		_ = clearWinINetProxy() // best-effort
		touched = append(touched, `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	}
	if w.WriteWinHTTP {
		_, _ = exec.Command("netsh", "winhttp", "reset", "proxy").CombinedOutput()
		touched = append(touched, "netsh winhttp")
	}

	broadcastEnvChange()
	return touched, errors.Join(errs...)
}

// CheckIntegrity reports the managed names whose registry value diverges from
// the expected one.
func (w *windowsManager) CheckIntegrity(v Vars) ([]string, error) {
	root, _, err := openEnvKey(w.Scope, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	expected := varsToEnvPairs(v)
	var drift []string
	for name, want := range expected {
		got, _, err := root.GetStringValue(name)
		if err != nil || got != want {
			drift = append(drift, name)
		}
	}
	return drift, nil
}

// openEnvKey opens the appropriate Environment subkey for the chosen scope.
// Returns the open key, a human-readable path string, and an error.
func openEnvKey(scope Scope, access uint32) (registry.Key, string, error) {
	switch scope {
	case ScopeSystem:
		const sub = `System\CurrentControlSet\Control\Session Manager\Environment`
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, sub, access)
		return k, `HKLM\` + sub, err
	case ScopeUser:
		const sub = `Environment`
		k, err := registry.OpenKey(registry.CURRENT_USER, sub, access)
		return k, `HKCU\` + sub, err
	default:
		return 0, "", fmt.Errorf("envvars: unknown scope %d", scope)
	}
}

// writeWinINetProxy sets HKCU\...\Internet Settings\ProxyEnable + ProxyServer.
func writeWinINetProxy(addr string) error {
	const sub = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	k, err := registry.OpenKey(registry.CURRENT_USER, sub, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	return k.SetStringValue("ProxyServer", addr)
}

func clearWinINetProxy() error {
	const sub = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	k, err := registry.OpenKey(registry.CURRENT_USER, sub, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	_ = k.SetDWordValue("ProxyEnable", 0)
	_ = k.DeleteValue("ProxyServer")
	return nil
}

// setNetshWinHTTPProxy is a testable seam.
var setNetshWinHTTPProxy = func(addr string) ([]byte, error) {
	return exec.Command("netsh", "winhttp", "set", "proxy", addr).CombinedOutput()
}

// broadcastEnvChange sends WM_SETTINGCHANGE to all top-level windows so that
// shells / Explorer pick up the new environment without a logoff.
//
// LPARAM = "Environment" (LPCWSTR), per the documented contract.
func broadcastEnvChange() {
	const HWND_BROADCAST = uintptr(0xFFFF)
	const WM_SETTINGCHANGE = uint32(0x001A)
	const SMTO_ABORTIFHUNG = uint32(0x0002)

	user32 := windows.NewLazySystemDLL("user32.dll")
	sendMessageTimeout := user32.NewProc("SendMessageTimeoutW")

	param, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var result uintptr
	_, _, _ = sendMessageTimeout.Call(
		HWND_BROADCAST,
		uintptr(WM_SETTINGCHANGE),
		0,
		uintptr(unsafe.Pointer(param)),
		uintptr(SMTO_ABORTIFHUNG),
		uintptr(5000),
		uintptr(unsafe.Pointer(&result)),
	)
}

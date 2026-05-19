package certstore

import "os"

// writeTempPEM writes pemBytes to a temp file and returns its path. Used by
// the Windows and macOS installers to stage the CA before invoking the OS CLI.
func writeTempPEM(pemBytes []byte) (string, error) {
	f, err := os.CreateTemp("", "ai-scan-connect-ca-*.pem")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

package transfer

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jlaffaye/ftp"
	"k8s.io/klog/v2"
)

type TransferFTP struct {
	Username string
	Password string
	Host     string
	Port     string
	Path     string
}

func NewTransferFTP(username, password, host, port, path string) *TransferFTP {
	return &TransferFTP{
		Username: username,
		Password: password,
		Host:     host,
		Port:     port,
		Path:     path,
	}
}

func (t *TransferFTP) Create(filePath string) error {

	connStr := fmt.Sprintf("%s:%s", t.Host, t.Port)
	conn, err := ftp.Dial(connStr, ftp.DialWithTimeout(10*time.Second))

	klog.Infof("FTP Dialing %s", connStr)

	if err != nil {
		klog.Error(err, "FTP Dial failed")
		return err
	}
	defer conn.Quit()

	if err := conn.Login(t.Username, t.Password); err != nil {
		klog.Error(err, "FTP Login failed")

		return err
	}

	klog.Info("FTP Login successful")

	// Open the local file for reading
	file, err := os.Open(filePath)
	if err != nil {
		klog.Error(err, "Failed to open local certificate file for FTP transfer", "path", filePath)
		return err
	}
	defer file.Close()

	klog.Infof("FTP Uploading %s to %s", filePath, t.Path)
	err = conn.Stor(t.Path, file)
	if err != nil {
		klog.Error(err, "FTP Stor (upload) failed")
		return err
	}
	klog.Info("FTP Upload successful")

	return nil
}

func (t *TransferFTP) List() ([]string, error) {
	conn, err := ftp.Dial(fmt.Sprintf("%s:%s", t.Host, t.Port))
	if err != nil {
		return nil, err
	}
	defer conn.Quit()

	if err := conn.Login(t.Username, t.Password); err != nil {
		return nil, err
	}

	entries, err := conn.List(t.Path)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		files = append(files, entry.Name)
	}

	return files, nil
}

func (t *TransferFTP) Delete(filePath string) error {
	conn, err := ftp.Dial(fmt.Sprintf("%s:%s", t.Host, t.Port))
	if err != nil {
		return err
	}
	defer conn.Quit()

	if err := conn.Login(t.Username, t.Password); err != nil {
		return err
	}

	remotePath := filepath.Join(t.Path, filePath)
	if err := conn.Delete(remotePath); err != nil {
		return err
	}

	return nil
}

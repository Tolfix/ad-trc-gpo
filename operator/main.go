package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Tolfix/ad-trc-gpo/operator/transfer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"
)

// Configuration struct to hold settings
type Config struct {
	LabelPrefix      string
	LabelKey         string
	LabelValue       string
	CertificateKey   string
	TempDir          string
	TransferMethod   string
	RemoteHost       string
	RemotePort       string
	RemoteUserEnvVar string // Env var name for remote user
	RemotePassEnvVar string // Env var name for remote password
	RemoteBaseDir    string
	Kubeconfig       string
	Namespace        string // Namespace to watch, empty for all namespaces
}

// Global config variable
var config Config

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	namespace := flag.String("namespace", "", "Namespace to watch secrets in. Leave empty to watch all namespaces.")

	flag.StringVar(&config.LabelPrefix, "label-prefix", "ad-gpo-trc", "Label prefix to watch for on secrets.")
	flag.StringVar(&config.LabelKey, "label-key", "trust", "Label key to watch for on secrets.")
	flag.StringVar(&config.LabelValue, "label-value", "true", "Required value for the watched label.")
	flag.StringVar(&config.CertificateKey, "certificate-key", "tls.crt", "Data key within the secret containing the certificate.")
	flag.StringVar(&config.TempDir, "temp-dir", "/tmp/certs", "Temporary directory to store certificates before upload.")
	flag.StringVar(&config.TransferMethod, "transfer-method", "FTP", "File transfer method (FTP, SFTP, SMB, NONE).")
	flag.StringVar(&config.RemoteHost, "remote-host", "ftp.your-ad-server.local", "Hostname/IP of the remote server.")
	flag.StringVar(&config.RemotePort, "remote-port", "21", "Port of the remote server.")
	flag.StringVar(&config.RemoteUserEnvVar, "remote-user-env", "REMOTE_USER", "Environment variable name for the remote username.")
	flag.StringVar(&config.RemotePassEnvVar, "remote-pass-env", "REMOTE_PASSWORD", "Environment variable name for the remote password.")
	flag.StringVar(&config.RemoteBaseDir, "remote-base-dir", "/k8s_certs_to_process", "Base directory on the remote server for uploads.")

	flag.Parse()

	config.Kubeconfig = *kubeconfig
	config.Namespace = *namespace

	klog.Infof("Starting operator with configuration:")
	klog.Infof("  Label: %s=%s", config.LabelKey, config.LabelValue)
	klog.Infof("  Certificate Key: %s", config.CertificateKey)
	klog.Infof("  Namespace: %s (all if empty)", config.Namespace)
	klog.Infof("  Transfer Method: %s", config.TransferMethod)
	klog.Infof("  Remote Target: %s@%s:%s%s", os.Getenv(config.RemoteUserEnvVar), config.RemoteHost, config.RemotePort, config.RemoteBaseDir)

	var k8sConfig *rest.Config
	var err error

	k8sConfig, err = rest.InClusterConfig()
	if err != nil {
		klog.Warningf("Could not get in-cluster config: %v. Trying kubeconfig file.", err)
		k8sConfig, err = clientcmd.BuildConfigFromFlags("", config.Kubeconfig)
		if err != nil {
			klog.Fatalf("Error building kubeconfig: %s", err.Error())
		}
	}

	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		klog.Fatalf("Error creating Kubernetes clientset: %s", err.Error())
	}

	if err := os.MkdirAll(config.TempDir, 0750); err != nil {
		klog.Fatalf("Failed to create temporary certificate directory %s: %v", config.TempDir, err)
	}

	secretInformer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.LabelSelector = fmt.Sprintf("%s=%s", config.LabelKey, config.LabelValue)
				return clientset.CoreV1().Secrets(config.Namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.LabelSelector = fmt.Sprintf("%s=%s", config.LabelKey, config.LabelValue)
				return clientset.CoreV1().Secrets(config.Namespace).Watch(context.TODO(), options)
			},
		},
		&corev1.Secret{},
		0,
		cache.Indexers{},
	)

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				klog.Warningf("Expected Secret but got %T", obj)
				return
			}
			klog.Infof("Secret ADDED: %s/%s", secret.Namespace, secret.Name)
			processSecret(secret)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			_, okOld := oldObj.(*corev1.Secret)
			newSecret, okNew := newObj.(*corev1.Secret)
			if !okOld || !okNew {
				klog.Warningf("Expected Secret in update but got %T -> %T", oldObj, newObj)
				return
			}
			klog.Infof("Secret UPDATED: %s/%s", newSecret.Namespace, newSecret.Name)
			processSecret(newSecret)
		},
		DeleteFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.Warningf("Expected Secret or Tombstone but got %T", obj)
					return
				}
				secret, ok = tombstone.Obj.(*corev1.Secret)
				if !ok {
					klog.Warningf("Expected Secret in Tombstone but got %T", tombstone.Obj)
					return
				}
			}
			klog.Infof("Secret DELETED: %s/%s", secret.Namespace, secret.Name)
			handleSecretDeletion(secret)
		},
	})

	stopCh := make(chan struct{})
	defer close(stopCh)

	klog.Info("Starting secret informer...")
	go secretInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, secretInformer.HasSynced) {
		klog.Fatal("Timed out waiting for caches to sync")
	}
	klog.Info("Informer cache synced. Watching for secrets...")

	<-stopCh
	klog.Info("Shutting down.")
}

type CheckedLabels struct {
	// The Key file name if exists
	KeyFileName *string
}

// checkLabels checks if it has few labels for more dynamic configuration
func checkLabels(label map[string]string) CheckedLabels {
	labelKey := fmt.Sprintf("%s/%s", config.LabelPrefix, "key-file-name")
	keyFileName, exists := label[labelKey]
	if exists && keyFileName != "" {
		return CheckedLabels{
			KeyFileName: &keyFileName,
		}
	}
	return CheckedLabels{
		KeyFileName: nil,
	}
}

// processSecret checks labels, extracts cert, and triggers transfer
func processSecret(secret *corev1.Secret) {
	labels := secret.GetLabels()
	labelKey := fmt.Sprintf("%s/%s", config.LabelPrefix, config.LabelKey)
	if val, ok := labels[labelKey]; !ok || val != config.LabelValue {
		klog.V(1).Infof("Secret %s/%s does not have the required label, ignoring", secret.Namespace, secret.Name)
		return
	}

	klog.Infof("Found matching Secret: %s/%s with label %s=%s", secret.Namespace, secret.Name, labelKey, config.LabelValue)

	if secret.Type != corev1.SecretTypeTLS && secret.Type != corev1.SecretTypeOpaque {
		klog.Warningf("Secret %s/%s has label but is not type TLS or Opaque (%s), ignoring", secret.Namespace, secret.Name, secret.Type)
		return
	}

	checkedLabel := checkLabels(labels)
	var certificateKey *string

	if certificateKey = checkedLabel.KeyFileName; certificateKey == nil {
		certificateKey = &config.CertificateKey
	}

	certDataEncoded, ok := secret.Data[*certificateKey]
	if !ok {
		klog.Warningf("Secret %s/%s does not contain certificate data key '%s'", secret.Namespace, secret.Name, certificateKey)
		return
	}
	if len(certDataEncoded) == 0 {
		klog.Warningf("Secret %s/%s has empty certificate data for key '%s'", secret.Namespace, secret.Name, certificateKey)
		return
	}

	certDataDecoded, err := base64.StdEncoding.DecodeString(string(certDataEncoded))
	if err != nil {
		klog.Errorf("Failed to decode certificate data from Secret %s/%s: %v", secret.Namespace, secret.Name, err)
		return
	}

	certFilename := fmt.Sprintf("%s-%s.crt", secret.Namespace, secret.Name)
	localCertPath := filepath.Join(config.TempDir, certFilename)

	err = os.WriteFile(localCertPath, certDataDecoded, 0640)
	if err != nil {
		klog.Errorf("Failed to write certificate to temporary file %s for Secret %s/%s: %v", localCertPath, secret.Namespace, secret.Name, err)
		return
	}

	defer func() {
		if err := os.Remove(localCertPath); err != nil && !os.IsNotExist(err) {
			klog.Warningf("Failed to remove temporary cert file %s: %v", localCertPath, err)
		}
	}()

	klog.Infof("Certificate saved locally: %s for Secret %s/%s", localCertPath, secret.Namespace, secret.Name)

	klog.Infof("Attempting to transfer certificate file %s for Secret %s/%s", certFilename, secret.Namespace, secret.Name)
	err = transferCertificateFile(localCertPath, certFilename)
	if err != nil {
		klog.Errorf("Transfer failed for %s from Secret %s/%s", certFilename, secret.Namespace, secret.Name)
		return
	}

	klog.Infof("Successfully processed and initiated transfer for certificate from Secret %s/%s", secret.Namespace, secret.Name)
}

// transferCertificateFile handles the actual file upload logic.
func transferCertificateFile(localPath, remoteFilename string) error {

	remoteFullPath := config.RemoteBaseDir + "/" + remoteFilename
	remoteFullPath = filepath.Clean(remoteFullPath)

	switch config.TransferMethod {
	case "FTP":

		ftpUser := os.Getenv(config.RemoteUserEnvVar)
		ftpPassword := os.Getenv(config.RemotePassEnvVar)

		if ftpUser == "" || ftpPassword == "" {
			err := fmt.Errorf("remote credentials not found in environment variables (%s, %s)", config.RemoteUserEnvVar, config.RemotePassEnvVar)
			klog.Error(err, " Credentials missing")
			return err
		}

		klog.Infof("Using FTP transfer method: %s -> ftp://%s@%s:%s%s",
			localPath, ftpUser, config.RemoteHost, config.RemotePort, remoteFullPath)
		ftp := transfer.NewTransferFTP(ftpUser, ftpPassword, config.RemoteHost, config.RemotePort, remoteFullPath)
		ftp.Create(localPath)
		return nil
	case "SFTP":
		klog.Warning("SFTP transfer not implemented")
		return fmt.Errorf("SFTP transfer not implemented")
	case "SMB":
		klog.Warning("SMB transfer not implemented")
		return fmt.Errorf("SMB transfer not implemented")
	case "NONE":
		klog.Infof("Transfer method set to NONE. Skipping actual file transfer for %s", localPath)
		return nil // Useful for testing the K8s part without network dependency
	default:
		err := fmt.Errorf("unsupported transfer method: %s", config.TransferMethod)
		klog.Error(err, " Configuration error")
		return err
	}
}

// handleSecretDeletion could be called from the DeleteFunc handler
func handleSecretDeletion(secret *corev1.Secret) {
	labels := secret.GetLabels()
	labelKey := fmt.Sprintf("%s/%s", config.LabelPrefix, config.LabelKey)
	if val, ok := labels[labelKey]; !ok || val != config.LabelValue {
		return
	}

	remoteFilename := fmt.Sprintf("%s-%s.crt", secret.Namespace, secret.Name)
	klog.Infof("Secret %s/%s deleted, attempting to clean up remote file: %s", secret.Namespace, secret.Name, remoteFilename)

	err := deleteRemoteCertificateFile(remoteFilename)
	if err != nil {
		klog.Errorf("Failed to delete remote certificate file %s for deleted Secret %s/%s: %v", remoteFilename, secret.Namespace, secret.Name, err)
	} else {
		klog.Infof("Successfully deleted remote file %s for deleted Secret %s/%s", remoteFilename, secret.Namespace, secret.Name)
	}
}

// deleteRemoteCertificateFile handles deleting the file from the remote store.
func deleteRemoteCertificateFile(remoteFilename string) error {
	klog.Warningf("Remote deletion for %s not implemented.", remoteFilename)
	// Placeholder: Implement FTP DELE command, SFTP Remove, etc.
	// Remember secure credential handling here too.
	return fmt.Errorf("remote deletion not implemented")
}

//go:build image_smoke

package smoke

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const dashboardPort = "18080"

func TestImageRendersVulnerabilityReportFromKubernetesAPI(t *testing.T) {
	image := os.Getenv("TRIVY_DASHBOARD_SMOKE_IMAGE")
	if image == "" {
		image = "trivy-dashboard:smoke"
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env := &envtest.Environment{
		CRDs: []*apiextensionsv1.CustomResourceDefinition{
			vulnerabilityReportCRD(),
		},
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Logf("stop envtest: %v", err)
		}
	})

	createFixtureReport(t, ctx, cfg)

	dir := t.TempDir()
	kubeconfig := filepath.Join(dir, "kubeconfig")
	writeKubeconfig(t, kubeconfig, cfg)

	container := "trivy-dashboard-smoke-" + strings.ToLower(randomSuffix())
	run := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", container,
		"--network", "host",
		"-e", "TRIVY_DASHBOARD_ADDR=:"+dashboardPort,
		"-e", "KUBECONFIG=/tmp/kubeconfig",
		"-v", kubeconfig+":/tmp/kubeconfig:ro",
		image,
	)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("start container: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
		if len(logs) > 0 {
			t.Logf("container logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", container).Run()
	})

	waitStatus(t, ctx, "http://127.0.0.1:"+dashboardPort+"/healthz", http.StatusOK)
	waitStatus(t, ctx, "http://127.0.0.1:"+dashboardPort+"/readyz", http.StatusOK)

	dashboard := getBody(t, ctx, "http://127.0.0.1:"+dashboardPort+"/api/dashboard")
	assertContains(t, dashboard, "web/nginx-abc")
	assertContains(t, dashboard, "library/nginx:1.25")
	assertContains(t, dashboard, "1 Critical")
	assertContains(t, dashboard, "rag-red")

	detail := getBody(t, ctx, "http://127.0.0.1:"+dashboardPort+"/workload/web/nginx-abc")
	assertContains(t, detail, "CVE-2024-0001")
	assertContains(t, detail, "CRITICAL")
	assertContains(t, detail, "libcurl")
}

func createFixtureReport(t *testing.T, ctx context.Context, cfg *rest.Config) {
	t.Helper()

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("create kubernetes client: %v", err)
	}
	if _, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("create dynamic client: %v", err)
	}
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}
	report := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]any{
				"name":      "replicaset-nginx-abc-nginx",
				"namespace": "web",
				"labels": map[string]any{
					"trivy-operator.resource.kind": "ReplicaSet",
					"trivy-operator.resource.name": "nginx-abc",
				},
			},
			"report": map[string]any{
				"artifact": map[string]any{
					"repository": "library/nginx",
					"tag":        "1.25",
				},
				"summary": map[string]any{
					"criticalCount": int64(1),
					"highCount":     int64(0),
					"mediumCount":   int64(0),
					"lowCount":      int64(0),
					"unknownCount":  int64(0),
				},
				"vulnerabilities": []any{
					map[string]any{
						"vulnerabilityID":  "CVE-2024-0001",
						"severity":         "CRITICAL",
						"score":            9.8,
						"title":            "Buffer overflow in libcurl",
						"resource":         "libcurl",
						"installedVersion": "7.88",
						"fixedVersion":     "8.0",
						"primaryLink":      "https://avd.aquasec.com/nvd/cve-2024-0001",
					},
				},
			},
		},
	}
	if _, err := dyn.Resource(gvr).Namespace("web").Create(ctx, report, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create vulnerability report: %v", err)
	}
}

func writeKubeconfig(t *testing.T, path string, cfg *rest.Config) {
	t.Helper()

	kubeconfig := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"envtest": {
				Server:                   cfg.Host,
				CertificateAuthorityData: cfg.CAData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"envtest": {
				ClientCertificateData: cfg.CertData,
				ClientKeyData:         cfg.KeyData,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"envtest": {
				Cluster:  "envtest",
				AuthInfo: "envtest",
			},
		},
		CurrentContext: "envtest",
	}

	data, err := clientcmd.Write(kubeconfig)
	if err != nil {
		t.Fatalf("serialize kubeconfig: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
}

func waitStatus(t *testing.T, ctx context.Context, url string, want int) {
	t.Helper()

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s did not return %d before timeout", url, want)
}

func getBody(t *testing.T, ctx context.Context, url string) string {
	t.Helper()

	waitStatus(t, ctx, url, http.StatusOK)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(body)
}

func assertContains(t *testing.T, body, want string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Fatalf("response missing %q:\n%s", want, body)
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
}

func randomSuffix() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

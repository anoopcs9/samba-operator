/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command to start the samba-operator.
package main

import (
	"crypto/tls"
	goflag "flag"
	"os"
	goruntime "runtime"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	flag "github.com/spf13/pflag"
	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	sambaoperatorv1alpha1 "github.com/samba-in-kubernetes/samba-operator/api/v1alpha1"
	"github.com/samba-in-kubernetes/samba-operator/internal/conf"
	"github.com/samba-in-kubernetes/samba-operator/internal/controller"
	pln "github.com/samba-in-kubernetes/samba-operator/internal/planner"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")

	// Version of the software at compile time.
	Version = "(unset)"
	// CommitID of the revision used to compile the software.
	CommitID = "(unset)"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(monitoringv1.AddToScheme(scheme))

	utilruntime.Must(sambaoperatorv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// managerOptions holds the command-line configurable options used to
// construct the controller manager.
type managerOptions struct {
	metricsAddr          string
	metricsCertPath      string
	metricsCertName      string
	metricsCertKey       string
	webhookCertPath      string
	webhookCertName      string
	webhookCertKey       string
	enableLeaderElection bool
	probeAddr            string
	secureMetrics        bool
	enableHTTP2          bool
}

// bindFlags registers all command-line flags and returns the parsed options
// together with the configuration source.
func bindFlags() (*managerOptions, *conf.Source) {
	o := &managerOptions{}
	flag.StringVar(&o.metricsAddr, "metrics-bind-address", "0",
		"The address the metrics endpoint binds to. Use :8443 for HTTPS or "+
			":8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&o.probeAddr, "health-probe-bind-address", ":8081",
		"The address the probe endpoint binds to.")
	flag.BoolVar(&o.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&o.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. "+
			"Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&o.webhookCertPath, "webhook-cert-path", "",
		"The directory that contains the webhook certificate.")
	flag.StringVar(&o.webhookCertName, "webhook-cert-name", "tls.crt",
		"The name of the webhook certificate file.")
	flag.StringVar(&o.webhookCertKey, "webhook-cert-key", "tls.key",
		"The name of the webhook key file.")
	flag.StringVar(&o.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&o.metricsCertName, "metrics-cert-name", "tls.crt",
		"The name of the metrics server certificate file.")
	flag.StringVar(&o.metricsCertKey, "metrics-cert-key", "tls.key",
		"The name of the metrics server key file.")
	flag.BoolVar(&o.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	zapOpts := zap.Options{Development: true}
	zapFlagSet := goflag.NewFlagSet("zap", goflag.ExitOnError)
	zapOpts.BindFlags(zapFlagSet)
	flag.CommandLine.AddGoFlagSet(zapFlagSet)
	confSource := conf.NewSource()
	flag.CommandLine.AddFlagSet(confSource.Flags())
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	return o, confSource
}

// loadConfig loads and validates the operator configuration.
func loadConfig(confSource *conf.Source) {
	if err := conf.Load(confSource); err != nil {
		setupLog.Error(err, "unable to configure")
		os.Exit(1)
	}
	if err := conf.Get().Validate(); err != nil {
		setupLog.Error(err, "invalid configuration", "config", conf.Get())
		os.Exit(1)
	}
	setupLog.Info("loaded configuration successfully", "config", conf.Get())

	planner := pln.New(pln.InstanceConfiguration{
		GlobalConfig: conf.Get(),
	}, nil)
	if _, err := planner.NodeSelector(); err != nil {
		setupLog.Error(err, "invalid node selector configuration value",
			"note", "value must be a JSON object containing strings")
		os.Exit(1)
	}
}

// buildManagerOptions constructs the controller-runtime manager options from
// the parsed command-line options.
func buildManagerOptions(o *managerOptions) ctrl.Options {
	var tlsOpts []func(*tls.Config)

	// if the enable-http2 flag is false (the default), http/2 should be
	// disabled due to its vulnerabilities. Disabling http/2 prevents being
	// vulnerable to the HTTP/2 Stream Cancellation and Rapid Reset CVEs.
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	if !o.enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			setupLog.Info("Disabling HTTP/2")
			c.NextProtos = []string{"http/1.1"}
		})
	}

	webhookServerOptions := webhook.Options{TLSOpts: tlsOpts}
	if len(o.webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher",
			"webhook-cert-path", o.webhookCertPath,
			"webhook-cert-name", o.webhookCertName,
			"webhook-cert-key", o.webhookCertKey)
		webhookServerOptions.CertDir = o.webhookCertPath
		webhookServerOptions.CertName = o.webhookCertName
		webhookServerOptions.KeyName = o.webhookCertKey
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   o.metricsAddr,
		SecureServing: o.secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if o.secureMetrics {
		// FilterProvider protects the metrics endpoint with authn/authz so
		// that only authorized users and service accounts can access it.
		metricsServerOptions.FilterProvider =
			filters.WithAuthenticationAndAuthorization
	}
	if len(o.metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher",
			"metrics-cert-path", o.metricsCertPath,
			"metrics-cert-name", o.metricsCertName,
			"metrics-cert-key", o.metricsCertKey)
		metricsServerOptions.CertDir = o.metricsCertPath
		metricsServerOptions.CertName = o.metricsCertName
		metricsServerOptions.KeyName = o.metricsCertKey
	}

	return ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhook.NewServer(webhookServerOptions),
		HealthProbeBindAddress: o.probeAddr,
		LeaderElection:         o.enableLeaderElection,
		LeaderElectionID:       "e60e6695.samba.org",
		// Opt out of the controller-runtime priority queue (enabled by
		// default since v0.24). This operator's reconcilers make progress by
		// performing one change per pass and requeuing; the priority queue's
		// per-item exponential backoff (without a token-bucket fast path)
		// turns that pattern into minutes-long delays. Restore the previous
		// rate limiter behaviour.
		Controller: config.Controller{
			UsePriorityQueue: ptr.To(false),
		},
	}
}

// setupControllers wires the reconcilers into the manager.
func setupControllers(mgr ctrl.Manager) {
	if err := (&controller.SmbShareReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("SmbShare"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "smbshare")
		os.Exit(1)
	}
	if err := (&controller.SmbSecurityConfigReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("SmbSecurityConfig"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller",
			"controller", "smbsecurityconfig")
		os.Exit(1)
	}
	if err := (&controller.SmbCommonConfigReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("SmbCommonConfig"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller",
			"controller", "smbcommonconfig")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder
}

func main() {
	opts, confSource := bindFlags()

	setupLog.Info("Initializing Manager",
		"ProgramName", os.Args[0],
		"Version", Version,
		"CommitID", CommitID,
		"GoVersion", goruntime.Version(),
	)

	loadConfig(confSource)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), buildManagerOptions(opts))
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	setupControllers(mgr)

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}

package kubernetes

import "gopkg.in/yaml.v3"

// manifest is the common envelope every Kubernetes object shares. The kind-specific
// body is kept as a raw yaml.Node and decoded on demand, because different kinds
// reuse the same field name with different shapes (e.g. a Deployment's
// spec.selector is {matchLabels: ...} while a Service's spec.selector is a flat map).
type manifest struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   objectMeta `yaml:"metadata"`
	Spec       yaml.Node  `yaml:"spec"`
	// Items holds the nested objects of a `kind: ...List` wrapper (e.g. the output
	// of `kubectl get all -o yaml`).
	Items []yaml.Node `yaml:"items"`
}

type objectMeta struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels"`
}

// --- workload specs (Deployment / StatefulSet / DaemonSet / ReplicaSet / Job) ---

type workloadSpec struct {
	Replicas *int        `yaml:"replicas"`
	Template podTemplate `yaml:"template"`
}

// cronJobSpec nests a job template one level deeper.
type cronJobSpec struct {
	JobTemplate struct {
		Spec workloadSpec `yaml:"spec"`
	} `yaml:"jobTemplate"`
}

type podTemplate struct {
	Metadata objectMeta `yaml:"metadata"`
	Spec     podSpec    `yaml:"spec"`
}

type podSpec struct {
	Containers         []container         `yaml:"containers"`
	ServiceAccountName string              `yaml:"serviceAccountName"`
	SecurityContext    *podSecurityContext `yaml:"securityContext"`
	Volumes            []volume            `yaml:"volumes"`
}

type container struct {
	Name            string                    `yaml:"name"`
	Image           string                    `yaml:"image"`
	Ports           []containerPort           `yaml:"ports"`
	SecurityContext *containerSecurityContext `yaml:"securityContext"`
	Env             []envVar                  `yaml:"env"`
	EnvFrom         []envFromSource           `yaml:"envFrom"`
}

type envVar struct {
	Name      string `yaml:"name"`
	ValueFrom *struct {
		SecretKeyRef *struct {
			Name string `yaml:"name"`
		} `yaml:"secretKeyRef"`
	} `yaml:"valueFrom"`
}

type envFromSource struct {
	SecretRef *struct {
		Name string `yaml:"name"`
	} `yaml:"secretRef"`
}

type containerPort struct {
	ContainerPort int    `yaml:"containerPort"`
	Name          string `yaml:"name"`
}

type podSecurityContext struct {
	RunAsNonRoot *bool `yaml:"runAsNonRoot"`
}

type containerSecurityContext struct {
	RunAsNonRoot             *bool `yaml:"runAsNonRoot"`
	Privileged               *bool `yaml:"privileged"`
	ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
}

type volume struct {
	Name                  string `yaml:"name"`
	PersistentVolumeClaim *struct {
		ClaimName string `yaml:"claimName"`
	} `yaml:"persistentVolumeClaim"`
	Secret *struct {
		SecretName string `yaml:"secretName"`
	} `yaml:"secret"`
}

// --- Service ---

type serviceSpec struct {
	Type     string            `yaml:"type"` // ClusterIP (default) / NodePort / LoadBalancer / ExternalName
	Selector map[string]string `yaml:"selector"`
	Ports    []servicePort     `yaml:"ports"`
}

type servicePort struct {
	Name       string `yaml:"name"`
	Port       int    `yaml:"port"`
	TargetPort any    `yaml:"targetPort"`
}

// --- Ingress ---

type ingressSpec struct {
	Rules          []ingressRule   `yaml:"rules"`
	DefaultBackend *ingressBackend `yaml:"defaultBackend"`
}

type ingressRule struct {
	Host string `yaml:"host"`
	HTTP *struct {
		Paths []ingressPath `yaml:"paths"`
	} `yaml:"http"`
}

type ingressPath struct {
	Path    string         `yaml:"path"`
	Backend ingressBackend `yaml:"backend"`
}

type ingressBackend struct {
	// networking.k8s.io/v1 form
	Service *struct {
		Name string `yaml:"name"`
	} `yaml:"service"`
	// legacy extensions/v1beta1 form
	ServiceName string `yaml:"serviceName"`
}

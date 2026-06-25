// Package kubernetes converts Kubernetes manifests (multi-document YAML) into a
// partial Threagile model: workloads (Deployment/StatefulSet/DaemonSet/Pod/Job/
// CronJob) become technical assets, namespaces become trust boundaries, Services
// and Ingresses determine internet exposure and produce communication links, and
// Secrets/PersistentVolumeClaims become data/datastore assets.
//
// It follows the same shape as the terraform and openapi importers:
//
//	model, err := kubernetes.Import(manifestYAML, kubernetes.ImportOptions{})
package kubernetes

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/threagile/threagile/pkg/types"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func toID(parts ...string) string {
	joined := strings.Join(parts, "-")
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(joined), "-"), "-")
}

// ImportOptions controls import behaviour.
type ImportOptions struct {
	// SourceLabel is a short label appended to generated asset IDs to distinguish
	// multiple imported sources (e.g. "prod"). Defaults to "k8s".
	SourceLabel string
}

// workload is an intermediate representation of a parsed workload object.
type workload struct {
	name      string
	namespace string
	kind      string
	labels    map[string]string // combined object + pod-template labels (for service selector matching)
	pod       podSpec
	assetID   string
}

// datastoreImageRule matches a substring of a container image to a Threagile
// technology. An ordered slice (not a map) keeps classification deterministic
// when an image name happens to contain more than one needle — the first match
// in this list wins.
type datastoreImageRule struct {
	needle string
	tech   string
}

var knownDatastoreImages = []datastoreImageRule{
	{"postgres", types.Database},
	{"mysql", types.Database},
	{"mariadb", types.Database},
	{"mongo", types.Database},
	{"redis", types.Database},
	{"memcached", types.Database},
	{"cassandra", types.Database},
	{"cockroach", types.Database},
	{"elasticsearch", types.SearchEngine},
	{"opensearch", types.SearchEngine},
	{"rabbitmq", types.MessageQueue},
	{"kafka", types.MessageQueue},
	{"nats", types.MessageQueue},
	{"minio", types.FileServer},
	{"vault", types.Vault},
}

var workloadKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"ReplicaSet":  true,
	"Pod":         true,
	"Job":         true,
	"CronJob":     true,
}

// Import parses Kubernetes manifest YAML (possibly multi-document) and returns a
// partial *types.Model.
func Import(data []byte, opts ImportOptions) (*types.Model, error) {
	if opts.SourceLabel == "" {
		opts.SourceLabel = "k8s"
	}

	manifests, err := decodeManifests(data)
	if err != nil {
		return nil, err
	}
	if len(manifests) == 0 {
		return nil, errors.New("kubernetes: no manifests found (expected one or more YAML documents with apiVersion/kind)")
	}

	model := &types.Model{
		ThreagileVersion:   "1.0.0",
		Title:              "Imported from Kubernetes",
		TechnicalAssets:    make(map[string]*types.TechnicalAsset),
		TrustBoundaries:    make(map[string]*types.TrustBoundary),
		DataAssets:         make(map[string]*types.DataAsset),
		CommunicationLinks: make(map[string]*types.CommunicationLink),
		TagsAvailable:      []string{},
	}

	b := &builder{
		model:            model,
		label:            opts.SourceLabel,
		services:         map[string]map[string]string{},
		nsExtraAssets:    map[string][]string{},
		secretDataAssets: map[string]string{},
		pvcAssets:        map[string]string{},
	}

	// First pass: collect workloads and Service selectors (so later passes can
	// match regardless of document order).
	for i := range manifests {
		m := &manifests[i]
		switch {
		case workloadKinds[m.Kind]:
			if w := b.parseWorkload(m); w != nil {
				b.workloads = append(b.workloads, w)
			}
		case m.Kind == "Service":
			var spec serviceSpec
			if err := m.Spec.Decode(&spec); err == nil && len(spec.Selector) > 0 {
				b.services[nsOrDefault(m.Metadata.Namespace)+"/"+m.Metadata.Name] = spec.Selector
			}
		}
	}

	// Materialise workload assets.
	for _, w := range b.workloads {
		b.buildWorkloadAsset(w)
	}

	// Second pass: Services & Ingresses (exposure + links), Secrets/PVCs (data).
	for i := range manifests {
		m := &manifests[i]
		switch m.Kind {
		case "Service":
			b.handleService(m)
		case "Ingress":
			b.handleIngress(m)
		case "Secret":
			b.handleSecret(m)
		case "PersistentVolumeClaim":
			b.handlePVC(m)
		}
	}

	// Third pass: now that Secrets/PVCs exist, link them to the workloads that use
	// them (env/envFrom secret refs -> data assets processed; volume PVC claims ->
	// datastore communication links).
	b.linkSecretsAndVolumes()

	b.assignNamespaceBoundaries()

	if len(model.TechnicalAssets) == 0 {
		return nil, errors.New("kubernetes: no supported objects found (no workloads, services or ingresses)")
	}

	// Generic stub data asset so the fragment validates if no Secrets/PVCs were seen.
	if len(model.DataAssets) == 0 {
		da := &types.DataAsset{
			Id:              "data-imported-" + opts.SourceLabel,
			Title:           "Imported Data (review and classify)",
			Description:     "Stub data asset generated by kubernetes import. Review confidentiality and PII fields.",
			Confidentiality: types.Confidential,
			Integrity:       types.Critical,
			Availability:    types.Critical,
		}
		model.DataAssets[da.Id] = da
	}

	return model, nil
}

// decodeManifests splits a multi-document YAML stream and decodes each non-empty
// document into a manifest. A `kind: ...List` wrapper (e.g. `kubectl get all -o
// yaml`, which produces a top-level `List`) is flattened into its items.
func decodeManifests(data []byte) ([]manifest, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	var out []manifest
	for {
		var m manifest
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("kubernetes: failed to parse manifest YAML: %w", err)
		}
		switch {
		case strings.HasSuffix(m.Kind, "List") && len(m.Items) > 0:
			for i := range m.Items {
				var item manifest
				if err := m.Items[i].Decode(&item); err == nil && item.Kind != "" {
					out = append(out, item)
				}
			}
		case m.Kind == "":
			continue // empty document or a non-object (e.g. a bare list separator)
		default:
			out = append(out, m)
		}
	}
	return out, nil
}

type builder struct {
	model     *types.Model
	label     string
	workloads []*workload
	// services maps "namespace/name" -> selector, so an Ingress can resolve the
	// selector of the Service it references rather than guessing.
	services map[string]map[string]string
	// nsExtraAssets holds non-workload asset IDs (e.g. PVCs) that should still be
	// placed inside their namespace trust boundary.
	nsExtraAssets map[string][]string
	// secretDataAssets maps "namespace/secretName" -> the Secret data-asset ID.
	secretDataAssets map[string]string
	// pvcAssets maps "namespace/pvcName" -> the PVC datastore asset ID.
	pvcAssets map[string]string
}

func (b *builder) parseWorkload(m *manifest) *workload {
	pod, ok := extractPodSpec(m)
	if !ok {
		return nil
	}
	labels := mergeLabels(m.Metadata.Labels, podTemplateLabels(m))
	w := &workload{
		name:      m.Metadata.Name,
		namespace: nsOrDefault(m.Metadata.Namespace),
		kind:      m.Kind,
		labels:    labels,
		pod:       pod,
		assetID:   toID(nsOrDefault(m.Metadata.Namespace), m.Metadata.Name, b.label),
	}
	return w
}

// extractPodSpec pulls the pod spec out of the various workload shapes.
func extractPodSpec(m *manifest) (podSpec, bool) {
	switch m.Kind {
	case "Pod":
		var ps podSpec
		if err := m.Spec.Decode(&ps); err != nil {
			return podSpec{}, false
		}
		return ps, true
	case "CronJob":
		var cs cronJobSpec
		if err := m.Spec.Decode(&cs); err != nil {
			return podSpec{}, false
		}
		return cs.JobTemplate.Spec.Template.Spec, true
	default: // Deployment/StatefulSet/DaemonSet/ReplicaSet/Job
		var ws workloadSpec
		if err := m.Spec.Decode(&ws); err != nil {
			return podSpec{}, false
		}
		return ws.Template.Spec, true
	}
}

func podTemplateLabels(m *manifest) map[string]string {
	switch m.Kind {
	case "Pod":
		return nil
	case "CronJob":
		var cs cronJobSpec
		if err := m.Spec.Decode(&cs); err == nil {
			return cs.JobTemplate.Spec.Template.Metadata.Labels
		}
		return nil
	default:
		var ws workloadSpec
		if err := m.Spec.Decode(&ws); err == nil {
			return ws.Template.Metadata.Labels
		}
		return nil
	}
}

func (b *builder) buildWorkloadAsset(w *workload) {
	tech, assetType := classifyWorkload(w)

	title := w.name
	if w.namespace != "default" {
		title = w.namespace + "/" + w.name
	}

	tags := workloadTags(w)

	images := make([]string, 0, len(w.pod.Containers))
	for _, c := range w.pod.Containers {
		if c.Image != "" {
			images = append(images, c.Image)
		}
	}
	desc := fmt.Sprintf("Imported from Kubernetes %s %q", w.kind, w.name)
	if len(images) > 0 {
		desc += " (images: " + strings.Join(images, ", ") + ")"
	}

	asset := &types.TechnicalAsset{
		Id:              w.assetID,
		Title:           title,
		Description:     desc,
		Type:            assetType,
		Technologies:    types.TechnologyList{&types.Technology{Name: tech}},
		Machine:         types.Container,
		Encryption:      types.NoneEncryption,
		Confidentiality: types.Confidential,
		Integrity:       types.Critical,
		Availability:    types.Critical,
		Tags:            tags,
	}
	b.model.TechnicalAssets[asset.Id] = asset
}

// classifyWorkload returns the Threagile technology and asset type for a workload,
// detecting datastores from container images.
func classifyWorkload(w *workload) (string, types.TechnicalAssetType) {
	for _, c := range w.pod.Containers {
		img := strings.ToLower(c.Image)
		for _, rule := range knownDatastoreImages {
			if strings.Contains(img, rule.needle) {
				assetType := types.Datastore
				if rule.tech == types.MessageQueue || rule.tech == types.Vault {
					assetType = types.Process
				}
				return rule.tech, assetType
			}
		}
	}
	return types.ContainerPlatform, types.Process
}

func workloadTags(w *workload) []string {
	var tags []string
	hardened := false
	if sc := w.pod.SecurityContext; sc != nil && sc.RunAsNonRoot != nil && *sc.RunAsNonRoot {
		hardened = true
	}
	privileged := false
	for _, c := range w.pod.Containers {
		if c.SecurityContext == nil {
			continue
		}
		if c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot {
			hardened = true
		}
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			privileged = true
		}
	}
	if hardened {
		tags = append(tags, "run-as-non-root")
	}
	if privileged {
		tags = append(tags, "privileged-container")
	}
	sort.Strings(tags)
	return tags
}

func (b *builder) handleService(m *manifest) {
	var spec serviceSpec
	if err := m.Spec.Decode(&spec); err != nil {
		return
	}
	ns := nsOrDefault(m.Metadata.Namespace)
	exposed := spec.Type == "LoadBalancer" || spec.Type == "NodePort"

	targets := b.selectWorkloads(ns, spec.Selector)
	if !exposed || len(targets) == 0 {
		return
	}
	protocol := types.HTTPS
	if servicePortsLookHTTPOnly(spec.Ports) {
		protocol = types.HTTP
	}
	for _, w := range targets {
		b.markInternetExposed(w.assetID, "kubernetes-internet-client", "Service "+m.Metadata.Name+" ("+spec.Type+")", protocol)
	}
}

func (b *builder) handleIngress(m *manifest) {
	var spec ingressSpec
	if err := m.Spec.Decode(&spec); err != nil {
		return
	}
	ns := nsOrDefault(m.Metadata.Namespace)

	exposeBackend := func(svcName string) {
		if svcName == "" {
			return
		}
		for _, w := range b.resolveServiceTargets(ns, svcName) {
			b.markInternetExposed(w.assetID, "kubernetes-ingress", "Ingress to "+svcName, types.HTTPS)
		}
	}

	exposeBackend(backendServiceName(spec.DefaultBackend))
	for _, rule := range spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, p := range rule.HTTP.Paths {
			exposeBackend(backendServiceName(&p.Backend))
		}
	}
}

// resolveServiceTargets finds the workloads an Ingress backend Service routes to:
// preferably via the real Service selector seen in the manifest stream, falling
// back to the common convention that the workload's app label equals the service
// name when the Service object isn't present.
func (b *builder) resolveServiceTargets(namespace, svcName string) []*workload {
	if selector, ok := b.services[namespace+"/"+svcName]; ok {
		if targets := b.selectWorkloads(namespace, selector); len(targets) > 0 {
			return targets
		}
	}
	var out []*workload
	for _, w := range b.workloadsInNamespace(namespace) {
		if w.labels["app"] == svcName || w.labels["app.kubernetes.io/name"] == svcName || w.name == svcName {
			out = append(out, w)
		}
	}
	return out
}

func backendServiceName(backend *ingressBackend) string {
	if backend == nil {
		return ""
	}
	if backend.Service != nil {
		return backend.Service.Name
	}
	return backend.ServiceName
}

// markInternetExposed flags the target asset as internet-facing and creates a
// communication link from a shared external client/ingress asset.
func (b *builder) markInternetExposed(targetAssetID, clientID, title string, protocol types.Protocol) {
	target, ok := b.model.TechnicalAssets[targetAssetID]
	if !ok {
		return
	}
	target.Internet = true

	client := b.ensureExternalClient(clientID)
	linkID := toID("link", clientID, "to", targetAssetID)
	if _, exists := b.model.CommunicationLinks[linkID]; exists {
		return
	}
	link := &types.CommunicationLink{
		Id:             linkID,
		SourceId:       client.Id,
		TargetId:       targetAssetID,
		Title:          title,
		Description:    title,
		Protocol:       protocol,
		Authentication: types.NoneAuthentication,
		Authorization:  types.NoneAuthorization,
		Usage:          types.Business,
	}
	b.model.CommunicationLinks[linkID] = link
	client.CommunicationLinks = append(client.CommunicationLinks, link)
}

func (b *builder) ensureExternalClient(clientID string) *types.TechnicalAsset {
	id := toID(clientID, b.label)
	if a, ok := b.model.TechnicalAssets[id]; ok {
		return a
	}
	title := "Internet client / ingress"
	switch clientID {
	case "kubernetes-ingress":
		title = "Ingress"
	case "kubernetes-internet-client":
		title = "Internet client (Service)"
	}
	a := &types.TechnicalAsset{
		Id:              id,
		Title:           title,
		Description:     "External traffic source generated from a Kubernetes Service/Ingress exposure",
		Type:            types.ExternalEntity,
		Technologies:    types.TechnologyList{&types.Technology{Name: types.ClientSystem}},
		Internet:        true,
		Confidentiality: types.Public,
		Integrity:       types.Operational,
		Availability:    types.Operational,
	}
	b.model.TechnicalAssets[id] = a
	return a
}

func (b *builder) handleSecret(m *manifest) {
	ns := nsOrDefault(m.Metadata.Namespace)
	id := toID("data", ns, m.Metadata.Name, b.label)
	b.secretDataAssets[ns+"/"+m.Metadata.Name] = id
	b.model.DataAssets[id] = &types.DataAsset{
		Id:              id,
		Title:           "Secret: " + m.Metadata.Name,
		Description:     "Kubernetes Secret (review for credentials / PII)",
		Confidentiality: types.StrictlyConfidential,
		Integrity:       types.Critical,
		Availability:    types.Critical,
		Tags:            []string{"credential"},
	}
}

func (b *builder) handlePVC(m *manifest) {
	ns := nsOrDefault(m.Metadata.Namespace)
	id := toID(ns, m.Metadata.Name, "pvc", b.label)
	if _, exists := b.model.TechnicalAssets[id]; exists {
		return
	}
	b.pvcAssets[ns+"/"+m.Metadata.Name] = id
	b.nsExtraAssets[ns] = append(b.nsExtraAssets[ns], id)
	b.model.TechnicalAssets[id] = &types.TechnicalAsset{
		Id:              id,
		Title:           "PVC: " + m.Metadata.Name,
		Description:     "Imported from Kubernetes PersistentVolumeClaim " + m.Metadata.Name,
		Type:            types.Datastore,
		Technologies:    types.TechnologyList{&types.Technology{Name: types.BlockStorage}},
		Machine:         types.Container,
		Encryption:      types.NoneEncryption,
		Confidentiality: types.Confidential,
		Integrity:       types.Critical,
		Availability:    types.Critical,
	}
}

// linkSecretsAndVolumes connects workloads to the Secrets they consume (via
// env/envFrom) and the PVCs they mount (via volumes), so credential-handling and
// data-at-rest risk rules actually fire on the workloads.
func (b *builder) linkSecretsAndVolumes() {
	for _, w := range b.workloads {
		asset, ok := b.model.TechnicalAssets[w.assetID]
		if !ok {
			continue
		}

		// Secret references in container env / envFrom -> data assets processed.
		for _, secretName := range referencedSecrets(w.pod) {
			if daID, found := b.secretDataAssets[w.namespace+"/"+secretName]; found {
				asset.DataAssetsProcessed = appendUnique(asset.DataAssetsProcessed, daID)
			}
		}

		// PVC volume mounts -> communication link workload -> PVC datastore.
		for _, claim := range referencedPVCs(w.pod) {
			pvcID, found := b.pvcAssets[w.namespace+"/"+claim]
			if !found {
				continue
			}
			linkID := toID("link", w.name, "to", claim, "pvc", b.label)
			if _, exists := b.model.CommunicationLinks[linkID]; exists {
				continue
			}
			link := &types.CommunicationLink{
				Id:             linkID,
				SourceId:       asset.Id,
				TargetId:       pvcID,
				Title:          w.name + " → " + claim,
				Description:    "Mounts PersistentVolumeClaim " + claim,
				Protocol:       types.LocalFileAccess,
				Authentication: types.NoneAuthentication,
				Authorization:  types.NoneAuthorization,
				Usage:          types.Business,
			}
			b.model.CommunicationLinks[linkID] = link
			asset.CommunicationLinks = append(asset.CommunicationLinks, link)
		}
	}
}

// referencedSecrets returns the de-duplicated Secret names a pod consumes via
// container env (secretKeyRef) and envFrom (secretRef).
func referencedSecrets(pod podSpec) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, c := range pod.Containers {
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				add(e.ValueFrom.SecretKeyRef.Name)
			}
		}
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil {
				add(ef.SecretRef.Name)
			}
		}
	}
	// Secrets mounted as volumes are consumed too.
	for _, v := range pod.Volumes {
		if v.Secret != nil {
			add(v.Secret.SecretName)
		}
	}
	return out
}

// referencedPVCs returns the de-duplicated PVC claim names a pod mounts.
func referencedPVCs(pod podSpec) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range pod.Volumes {
		if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName != "" {
			name := v.PersistentVolumeClaim.ClaimName
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// assignNamespaceBoundaries groups every workload/PVC asset by namespace into a
// network-policy-namespace-isolation trust boundary.
func (b *builder) assignNamespaceBoundaries() {
	byNamespace := map[string][]string{}
	for _, w := range b.workloads {
		byNamespace[w.namespace] = append(byNamespace[w.namespace], w.assetID)
	}
	// Include namespace-scoped non-workload assets (PVCs) in their boundary.
	for ns, ids := range b.nsExtraAssets {
		byNamespace[ns] = append(byNamespace[ns], ids...)
	}
	if len(byNamespace) == 0 {
		return
	}
	for ns, assetIDs := range byNamespace {
		sort.Strings(assetIDs)
		tbID := toID("namespace", ns, b.label)
		b.model.TrustBoundaries[tbID] = &types.TrustBoundary{
			Id:                    tbID,
			Title:                 "Namespace: " + ns,
			Description:           "Kubernetes namespace " + ns,
			Type:                  types.NetworkPolicyNamespaceIsolation,
			TechnicalAssetsInside: assetIDs,
		}
	}
}

func (b *builder) selectWorkloads(namespace string, selector map[string]string) []*workload {
	if len(selector) == 0 {
		return nil
	}
	var out []*workload
	for _, w := range b.workloads {
		if w.namespace != namespace {
			continue
		}
		if labelsMatch(w.labels, selector) {
			out = append(out, w)
		}
	}
	return out
}

func (b *builder) workloadsInNamespace(namespace string) []*workload {
	var out []*workload
	for _, w := range b.workloads {
		if w.namespace == namespace {
			out = append(out, w)
		}
	}
	return out
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func mergeLabels(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func nsOrDefault(ns string) string {
	if strings.TrimSpace(ns) == "" {
		return "default"
	}
	return ns
}

func servicePortsLookHTTPOnly(ports []servicePort) bool {
	if len(ports) == 0 {
		return false
	}
	for _, p := range ports {
		if p.Port == 443 || p.Port == 8443 || strings.Contains(strings.ToLower(p.Name), "https") {
			return false
		}
	}
	return true
}

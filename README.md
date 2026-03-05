# Snyk Exporter

[![Build](https://github.com/polarpoint-io/snyk_exporter/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/polarpoint-io/snyk_exporter/actions/workflows/build.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/polarpoint-io/snyk_exporter)](https://goreportcard.com/report/github.com/polarpoint-io/snyk_exporter)

Prometheus exporter for [Snyk](https://snyk.io/) written in Go.
Allows for exporting scanning data into Prometheus by scraping the Snyk REST API v2.

> **Forked from** [lunarway/snyk_exporter](https://github.com/lunarway/snyk_exporter) and updated by [polarpoint-io](https://github.com/polarpoint-io) to use the current **Snyk REST API v2** (`https://api.snyk.io/rest`), replacing the retired v1 API (`https://snyk.io/api/v1`) which returns HTTP 410 Gone.

# Installation

Pre-compiled binaries are available from the [releases page](https://github.com/polarpoint-io/snyk_exporter/releases).

A Docker image can be built locally (see [Build](#build) section below).

# Usage

You need a Snyk API token to access the API.
Get yours through the [Snyk account settings](https://app.snyk.io/account/).

It exposes Prometheus metrics on `/metrics` on port `9532` (can be configured).

```
snyk_exporter --snyk.api-token <api-token>
```

See all configuration options with the `--help` flag:

```
$ snyk_exporter --help
usage: snyk_exporter --snyk.api-token=SNYK.API-TOKEN [<flags>]

Snyk exporter for Prometheus. Provide your Snyk API token and the organization(s) to scrape to expose Prometheus metrics.

Flags:
  -h, --help               Show context-sensitive help (also try --help-long and --help-man).
      --snyk.api-url="https://api.snyk.io/rest"
                           Snyk REST API base URL
      --snyk.api-token=SNYK.API-TOKEN
                           Snyk API token
  -i, --snyk.interval=600  Polling interval for requesting data from Snyk API in seconds
      --snyk.organization=SNYK.ORGANIZATION ...
                           Snyk organization ID to scrape projects from (can be repeated for multiple organizations)
      --snyk.timeout=10    Timeout for requests against Snyk API
      --web.listen-address=":9532"
                           Address on which to expose metrics.
      --version            Show application version.
```

It is possible to use a file to pass arguments to the exporter.
For example:
```
echo --snyk.api-token=<token> > args
```
And run the exporter using:
```
./snyk_exporter @args
```

# Design

The exporter starts a long-running goroutine on startup that scrapes the Snyk REST API v2 with a fixed interval (default every `10` minutes).
The interval can be configured as needed.

## API v2 Migration

This fork migrates all API calls from the retired Snyk v1 API to the current **Snyk REST API v2** (`https://api.snyk.io/rest`):

| Endpoint | v1 (retired, 410 Gone) | REST v2 (current) |
|---|---|---|
| List organisations | `GET /api/v1/orgs` | `GET /rest/orgs?version=2024-10-15` |
| List projects | `GET /api/v1/org/{id}/projects` | `GET /rest/orgs/{id}/projects?version=2024-10-15` |
| List issues | `POST /api/v1/org/{id}/project/{id}/aggregated-issues` | `GET /rest/orgs/{id}/issues?version=2024-10-15&project_id={id}` |

All endpoints support cursor-based pagination via `links.next` and are followed automatically.

## Metrics

The API results are aggregated and recorded on the `snyk_vulnerabilities_total` metric with the following labels:

- `organization` — The organization where the vulnerable project exists
- `project` — The project with a vulnerability
- `severity` — The severity of the vulnerability: `critical`, `high`, `medium` or `low`
- `issue_type` — The type of issue, e.g. `package_vulnerability`, `license`
- `issue_title` — The issue title, e.g. `Denial of Service (DoS)`
- `ignored` — Whether the issue is ignored in Snyk
- `upgradeable` — Whether the issue can be fixed by upgrading a dependency
- `patchable` — Whether the issue is patchable through Snyk
- `monitored` — Whether the project is actively monitored by Snyk

Example metrics output:

```
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="critical",issue_type="package_vulnerability",issue_title="Remote Code Execution",ignored="false",upgradeable="false",patchable="false",monitored="true"} 1
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="high",issue_type="package_vulnerability",issue_title="Privilege Escalation",ignored="false",upgradeable="true",patchable="false",monitored="true"} 1
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="low",issue_type="package_vulnerability",issue_title="Sandbox Escape",ignored="true",upgradeable="false",patchable="false",monitored="false"} 2
snyk_vulnerabilities_total{organization="my-org",project="my-app",severity="medium",issue_type="license",issue_title="MPL-2.0 license",ignored="true",upgradeable="false",patchable="false",monitored="true"} 1
```

# Build

The exporter can be built using the standard Go toolchain (requires Go >=1.25):

```
go build
```

You can also build inside Docker:

```
docker build -t snyk_exporter .
```

This is useful for deploying in Kubernetes or other containerised environments.

# Deployment

## Helm (recommended)

A Helm chart is published to GHCR as an OCI artifact on every release, and is also included locally in `charts/snyk-exporter/`.

### Install from GHCR (OCI)

```bash
# Create a namespace
kubectl create namespace monitoring

# Install directly from the registry
helm install snyk-exporter oci://ghcr.io/polarpoint-io/charts/snyk-exporter \
  --version <chart-version> \
  --namespace monitoring \
  --set snyk.apiToken=<your-snyk-api-token>
```

### Install from local chart

```bash
helm install snyk-exporter ./charts/snyk-exporter \
  --namespace monitoring \
  --set snyk.apiToken=<your-snyk-api-token>
```

### Scoping to specific organisations

By default the exporter scrapes **all** organisations accessible to the token.
To restrict to specific org IDs:

```bash
helm install snyk-exporter ./charts/snyk-exporter \
  --namespace monitoring \
  --set snyk.apiToken=<your-snyk-api-token> \
  --set snyk.organizations[0]=<org-id-1> \
  --set snyk.organizations[1]=<org-id-2>
```

### Using an existing Secret

If you prefer to manage the token secret separately:

```bash
# Create the secret manually
kubectl create secret generic snyk-exporter-token \
  --namespace monitoring \
  --from-literal=api-token=<your-snyk-api-token>

# Install referencing the existing secret
helm install snyk-exporter ./charts/snyk-exporter \
  --namespace monitoring \
  --set snyk.existingSecret=snyk-exporter-token
```

### Common values

| Value | Default | Description |
|---|---|---|
| `snyk.apiToken` | `""` | Snyk API token (creates a Secret) |
| `snyk.existingSecret` | `""` | Name of a pre-existing Secret with key `api-token` |
| `snyk.apiUrl` | `https://api.snyk.io/rest` | Snyk REST API base URL |
| `snyk.interval` | `600` | Scrape interval in seconds |
| `snyk.timeout` | `10` | Request timeout in seconds |
| `snyk.organizations` | `[]` | List of org IDs to scrape (empty = all) |
| `replicaCount` | `1` | Number of replicas |
| `resources.requests.cpu` | `50m` | CPU request |
| `resources.requests.memory` | `32Mi` | Memory request |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `autoscaling.enabled` | `false` | Enable Horizontal Pod Autoscaler |
| `autoscaling.minReplicas` | `1` | HPA minimum replicas |
| `autoscaling.maxReplicas` | `3` | HPA maximum replicas |
| `image.repository` | `ghcr.io/polarpoint-io/snyk_exporter` | Container image repository |
| `image.tag` | `""` | Image tag (defaults to chart `appVersion`) |
| `nodeSelector` | `{}` | Node selector labels |
| `tolerations` | `[]` | Pod tolerations |
| `affinity` | `{}` | Pod affinity rules |

### Full `values.yaml`

```yaml
replicaCount: 1

image:
  repository: ghcr.io/polarpoint-io/snyk_exporter
  pullPolicy: IfNotPresent
  tag: ""

imagePullSecrets: []
nameOverride: ""
fullnameOverride: ""

serviceAccount:
  create: true
  annotations: {}
  name: ""

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9532"
  prometheus.io/path: "/metrics"

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65534
  fsGroup: 65534

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

snyk:
  # Snyk API token — set this or reference an existing secret
  apiToken: ""

  # Name of an existing Secret with key `api-token`
  existingSecret: ""

  apiUrl: "https://api.snyk.io/rest"

  # Polling interval in seconds (default 10 minutes)
  interval: 600

  # Request timeout in seconds
  timeout: 10

  # Restrict to specific org IDs (empty = all orgs)
  organizations: []
  # - "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

service:
  type: ClusterIP
  port: 9532

resources:
  requests:
    cpu: 50m
    memory: 32Mi
  limits:
    cpu: 200m
    memory: 64Mi

livenessProbe:
  httpGet:
    path: /healthz
    port: http
  initialDelaySeconds: 5
  periodSeconds: 15

readinessProbe:
  httpGet:
    path: /ready
    port: http
  initialDelaySeconds: 10
  periodSeconds: 15
  failureThreshold: 3

autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 3
  targetCPUUtilizationPercentage: 80

nodeSelector: {}
tolerations: []
affinity: {}

# Extra environment variables
extraEnv: []

# Extra volumes / volume mounts
extraVolumes: []
extraVolumeMounts: []
```

### Upgrading

```bash
helm upgrade snyk-exporter ./charts/snyk-exporter \
  --namespace monitoring \
  --reuse-values
```

### Uninstalling

```bash
helm uninstall snyk-exporter --namespace monitoring
```

## Raw Kubernetes manifests

If Helm is not available you can apply the manifests below directly.

Create the token secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: snyk-exporter
  namespace: monitoring
stringData:
  api-token: "<your-snyk-api-token>"
```

Create the Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snyk-exporter
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: snyk-exporter
  template:
    metadata:
      labels:
        app: snyk-exporter
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9532"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
      containers:
        - name: snyk-exporter
          image: ghcr.io/polarpoint-io/snyk_exporter:latest
          args:
            - --snyk.api-token=$(SNYK_API_TOKEN)
          env:
            - name: SNYK_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: snyk-exporter
                  key: api-token
          ports:
            - name: http
              containerPort: 9532
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 5
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /ready
              port: http
            initialDelaySeconds: 10
            periodSeconds: 15
            failureThreshold: 3
          resources:
            requests:
              cpu: 50m
              memory: 32Mi
            limits:
              cpu: 200m
              memory: 64Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

Create the Service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: snyk-exporter
  namespace: monitoring
spec:
  type: ClusterIP
  selector:
    app: snyk-exporter
  ports:
    - name: http
      port: 9532
      targetPort: http
```

Apply all three manifests:

```bash
kubectl apply -f secret.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

## Health endpoints

The exporter exposes the following HTTP endpoints for Kubernetes probes:

- `/healthz` — liveness probe, always returns `healthy` with status 200
- `/ready` — readiness probe, returns `true` (200) after the first scrape completes, otherwise `false` (503)

# Development

Requires Go >=1.25. Run builds and tests with the standard Go toolchain:

```
go build
go test ./...
```

To check for security vulnerabilities:

```
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

# Credits

Originally written by [lunarway](https://github.com/lunarway/snyk_exporter) with inspiration from [dnanexus/prometheus_snyk_exporter](https://github.com/dnanexus/prometheus_snyk_exporter).

Updated and maintained by [polarpoint-io](https://github.com/polarpoint-io) with REST API v2 migration, Go 1.25 upgrade, and removal of all known security vulnerabilities.


# Kubernetes examples

A walk from an empty cluster to a routed request, with ReverseDock as the Gateway API controller.
All Gateway API manifests use `gateway.networking.k8s.io/v1`. Host names are `example.com`; use
your own. Nothing here needs a secret.

| File | What it shows |
|---|---|
| [gateway.yaml](gateway.yaml) | A Gateway of class `reversedock`: HTTP on 80, HTTPS on 443 with a certificate Secret. |
| [httproute.yaml](httproute.yaml) | An echo Deployment and Service, and an HTTPRoute to it. |
| [grpcroute.yaml](grpcroute.yaml) | A GRPCRoute matching a gRPC service. |
| [tlsroute.yaml](tlsroute.yaml) | TLS passthrough: a Gateway and a TLSRoute by SNI name. |
| [ingress.yaml](ingress.yaml) | The echo backend through an Ingress and an IngressClass. |
| [cert-manager.yaml](cert-manager.yaml) | An Issuer and Certificate that fill the Gateway's Secret. **Needs cert-manager.** |

## 1. Install the Gateway API CRDs

Version 1.7.0, Standard channel. The chart and the raw manifests do not contain them.

```sh
kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml
```

## 2. Install ReverseDock

With Helm ([chart README](../../deploy/helm/reversedock/README.md)):

```sh
helm install reversedock deploy/helm/reversedock -n reversedock-system --create-namespace
```

or with the raw manifests ([deploy/kubernetes](../../deploy/kubernetes/README.md)):

```sh
kubectl apply -k deploy/kubernetes
```

Wait for the pods and the class:

```sh
kubectl -n reversedock-system rollout status deployment/reversedock
kubectl get gatewayclass reversedock
```

## 3. Create a Gateway

```sh
kubectl apply -f examples/kubernetes/gateway.yaml
```

The HTTPS listener names the Secret `example-com-tls`. Until it exists the listener stays up
without a certificate and reports `ResolvedRefs=False`; it is picked up when the Secret appears.
To get one from cert-manager, apply [cert-manager.yaml](cert-manager.yaml) (cert-manager must be
installed first; it is not part of this project). To use your own, create a `kubernetes.io/tls`
Secret named `example-com-tls` from your certificate and key.

## 4. Route to a backend

```sh
kubectl apply -f examples/kubernetes/httproute.yaml
kubectl get httproute echo -o jsonpath='{.status.parents[0].conditions[?(@.type=="Accepted")].status}'
```

## 5. Find the address and send a request

The controller makes a Service for the Gateway and writes its address to the Gateway's status.
On a cloud this is the load balancer's address, and it can take a minute to appear:

```sh
kubectl get gateway example -o jsonpath='{.status.addresses[0].value}'
```

```sh
ADDRESS=$(kubectl get gateway example -o jsonpath='{.status.addresses[0].value}')
curl -H 'Host: echo.example.com' "http://$ADDRESS/hostname"
```

Without a load balancer (a local cluster), the Gateway's Service has no external address. Set
`gateway.serviceType=cluster_ip` or `node_port` in the chart, or forward a port to the Service the
controller made (`kubectl -n reversedock-system get service`).

## 6. gRPC, TLS passthrough and Ingress

- [grpcroute.yaml](grpcroute.yaml) attaches to the `https` listener of the same Gateway. You supply
  the gRPC backend Service `grpc-echo` on port 9000.
- [tlsroute.yaml](tlsroute.yaml) creates a second Gateway, `passthrough`, with its own Service and
  address; the backend `secure-app` terminates TLS itself.
- [ingress.yaml](ingress.yaml) needs the chart installed with Ingress on:

  ```sh
  helm upgrade reversedock deploy/helm/reversedock -n reversedock-system \
    --set ingress.enabled=true --set ingress.service.enabled=true --set ingressClass.create=true
  ```

  The file also holds the IngressClass; the chart made it with `ingressClass.create=true`, so apply
  only the Ingress (`kubectl apply -f` of the file is harmless: it adopts the same object).

## Clean up

```sh
kubectl delete -f examples/kubernetes/httproute.yaml -f examples/kubernetes/gateway.yaml
```

Conformance with the Gateway API is run in CI; no conformance claim is made yet.

#!/usr/bin/env bash
# 3-node Swarm lab in LXD system containers: rdock global with host ports, whoami x6,
# k6 traffic during start-first and stop-first rolling updates, scaling and a node drain.
set -uo pipefail
L=/opt/queue/swarm-lab; Q=/opt/queue; R=$L/${RESULTS:-results}; mkdir -p $R
log() { echo "$(date -u +%FT%TZ) swarm-lab: $*" | tee -a $Q/status.log; }
on() { local n=$1; shift; lxc exec "$n" -- "$@"; }
die() { log "FAILED: $*"; exit 1; }
log start
lxc storage list -f csv | grep -q . || lxd init --auto || die "lxd init"
iptables -I DOCKER-USER -i lxdbr0 -j ACCEPT; iptables -I DOCKER-USER -o lxdbr0 -j ACCEPT
for m in vxlan overlay br_netfilter ip_vs ip_vs_rr nf_nat xt_conntrack; do modprobe $m 2>/dev/null; done
for n in sw1 sw2 sw3; do
  lxc info $n >/dev/null 2>&1 || lxc launch ubuntu:24.04 $n -c security.nesting=true -c security.privileged=true \
    -c limits.cpu=2 -c limits.memory=4GiB -c linux.kernel_modules=overlay,vxlan,br_netfilter,ip_vs >/dev/null || die "launch $n"
done
for n in sw1 sw2 sw3; do for i in $(seq 1 60); do on $n test -f /var/lib/cloud/instance/boot-finished 2>/dev/null && break; sleep 2; done; done
for n in sw1 sw2 sw3; do
  on $n bash -c "command -v docker >/dev/null || (DEBIAN_FRONTEND=noninteractive apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y docker.io >/dev/null)" || die "docker on $n"
  on $n systemctl enable --now docker >/dev/null 2>&1
done
ip() { lxc list "$1" -c 4 -f csv | tr "," "\n" | grep eth0 | grep -oE "[0-9]+([.][0-9]+){3}" | head -1; }
IP1=$(ip sw1); IP2=$(ip sw2); IP3=$(ip sw3); log "nodes $IP1 $IP2 $IP3; docker $(on sw1 docker version --format {{.Server.Version}})"
on sw1 docker info --format "{{.Swarm.LocalNodeState}}" | grep -qx active || on sw1 docker swarm init --advertise-addr $IP1 >/dev/null || die "swarm init"
TOKEN=$(on sw1 docker swarm join-token -q manager)
for n in sw2 sw3; do on $n docker info --format "{{.Swarm.LocalNodeState}}" | grep -qx active || on $n docker swarm join --token $TOKEN $IP1:2377 >/dev/null || die "join $n"; done
on sw1 docker node ls > $R/nodes.txt
docker save rdock:v06 traefik/whoami:v1.11 -o /tmp/lab-images.tar
for n in sw1 sw2 sw3; do lxc file push /tmp/lab-images.tar $n/tmp/lab-images.tar && on $n docker load -i /tmp/lab-images.tar >/dev/null || die "load images $n"; done
on sw1 docker network inspect proxy >/dev/null 2>&1 || on sw1 docker network create --driver overlay --attachable proxy >/dev/null
lxc file push $L/${STACK:-stack.yaml} sw1/root/stack.yaml; lxc file push $L/rdock.yaml sw1/root/
on sw1 bash -c "cd /root && docker stack deploy -c stack.yaml shop" > $R/deploy.txt 2>&1 || die "deploy"
for i in $(seq 1 60); do
  ok=0; for h in $IP1 $IP2 $IP3; do [ "$(curl -s -o /dev/null -w %{http_code} -H "Host: shop.test" http://$h/)" = 200 ] && ok=$((ok+1)); done
  [ $ok = 3 ] && break; sleep 2
done
log "all three nodes answer: $ok/3"
on sw1 docker service ps shop_web --format "{{.Name}} {{.Node}} {{.CurrentState}}" > $R/tasks-start.txt
K6() { docker run --rm --user 0 --network host -v $L/k6.js:/k6.js:ro -v $R:/out grafana/k6:1.3.0 run --quiet \
  -e TARGETS="$1" -e RATE=300 -e DURATION="$2" --summary-export /out/$3.json /k6.js > $R/$3.log 2>&1; }
ALL="$IP1,$IP2,$IP3"
K6 $ALL 60s baseline; log "baseline done"
( sleep 10; on sw1 docker service update --quiet --force --update-order start-first shop_web > $R/update-start-first.txt 2>&1 ) &
K6 $ALL 120s rolling-start-first; wait; log "start-first rolling update done"
( sleep 10; on sw1 docker service scale shop_web=2 >/dev/null 2>&1; sleep 30; on sw1 docker service scale shop_web=6 >/dev/null 2>&1 ) &
K6 $ALL 90s scale; wait; log "scale 6-2-6 done"
( sleep 10; on sw1 docker node update --availability drain sw3 >/dev/null; sleep 40; on sw1 docker node update --availability active sw3 >/dev/null ) &
K6 "$IP1,$IP2" 90s drain; wait; log "drain of sw3 done (traffic to sw1, sw2)"
on sw1 docker service ps shop_web --format "{{.Name}} {{.Node}} {{.DesiredState}} {{.CurrentState}}" > $R/tasks-after-drain.txt
( sleep 10; on sw1 docker service update --quiet --force --update-order stop-first shop_web > $R/update-stop-first.txt 2>&1 ) &
K6 $ALL 120s rolling-stop-first; wait; log "stop-first rolling update done"
for n in sw1 sw2 sw3; do c=$(on $n docker ps -q -f name=shop_rdock | head -1); on $n docker logs $c > $R/rdock-$n.log 2>&1; done
log done

//go:build ignore

// Command gen writes the test fixtures in testdata/flows by marshalling real
// flowpb structures, i.e. with the same encoder Cilium's flow-log exporter
// uses. Regenerate with:
//
//	go run testdata/gen/gen.go
//
// The output is deterministic and is committed, so the test suite never needs
// a cluster.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var base = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

func ts(min int) *timestamppb.Timestamp {
	return timestamppb.New(base.Add(time.Duration(min) * time.Minute))
}

func env(node string, f *flowpb.Flow) []byte {
	b, err := json.Marshal(&observerpb.ExportEvent{
		Time:          f.GetTime(),
		NodeName:      node,
		ResponseTypes: &observerpb.ExportEvent_Flow{Flow: f},
	})
	if err != nil {
		panic(err)
	}
	return b
}

func bare(f *flowpb.Flow) []byte {
	b, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	return b
}

func workload(ns, name, kind string) *flowpb.Workload {
	return &flowpb.Workload{Name: name, Kind: kind}
}

func tcpFlow(min int, node, srcNS, srcPod, srcIP string, srcWl *flowpb.Workload, dstNS, dstPod, dstIP string, dstWl *flowpb.Workload, names []string, sport, dport uint32, count uint32) *flowpb.Flow {
	f := &flowpb.Flow{
		Time:             ts(min),
		NodeName:         node,
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IsReply:          wrapperspb.Bool(false),
		Source: &flowpb.Endpoint{
			Namespace: srcNS,
			PodName:   srcPod,
			Identity:  12345,
			Workloads: []*flowpb.Workload{srcWl},
		},
		Destination: &flowpb.Endpoint{
			Namespace: dstNS,
			PodName:   dstPod,
			Workloads: nil,
		},
		IP:               &flowpb.IP{Source: srcIP, Destination: dstIP},
		L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: sport, DestinationPort: dport, Flags: &flowpb.TCPFlags{SYN: true}}}},
		DestinationNames: names,
		EventType:        &flowpb.CiliumEventType{Type: 4},
	}
	if dstWl != nil {
		f.Destination.Workloads = []*flowpb.Workload{dstWl}
	}
	if count > 0 {
		f.Aggregate = &flowpb.Aggregate{EgressFlowCount: count}
	}
	return f
}

func main() {
	out := "testdata/flows"
	if err := os.MkdirAll(out, 0o755); err != nil {
		panic(err)
	}

	agg := [][]byte{
		env("kube2.kasil.cloud", tcpFlow(0, "kube2.kasil.cloud", "frigate", "frigate-7d9f8c6b5-abcde", "172.16.1.5", workload("frigate", "frigate", "Deployment"), "nanomq", "nanomq-0", "172.16.2.9", workload("nanomq", "nanomq", "StatefulSet"), []string{"nanomq.nanomq.svc.cluster.local."}, 43210, 1883, 41233)),
		env("kube2.kasil.cloud", tcpFlow(0, "kube2.kasil.cloud", "frigate", "frigate-7d9f8c6b5-abcde", "172.16.1.5", workload("frigate", "frigate", "Deployment"), "", "", "192.168.31.10", nil, nil, 51000, 554, 1988)),
		env("kube2.kasil.cloud", tcpFlow(1, "kube2.kasil.cloud", "frigate", "frigate-7d9f8c6b5-abcde", "172.16.1.5", workload("frigate", "frigate", "Deployment"), "", "", "149.154.167.220", nil, []string{"api.telegram.org."}, 51001, 443, 412)),
		env("kube1.kasil.cloud", tcpFlow(1, "kube1.kasil.cloud", "hermes", "hermes-0", "172.16.4.7", workload("hermes", "hermes", "StatefulSet"), "", "", "140.82.121.6", nil, []string{"api.github.com."}, 51002, 443, 91)),
		env("kube1.kasil.cloud", tcpFlow(2, "kube1.kasil.cloud", "renovate", "renovate-29384756-x7k2p", "172.16.4.9", workload("renovate", "renovate", "CronJob"), "", "", "140.82.121.6", nil, []string{"api.github.com."}, 51003, 443, 12)),
		// An ingress-direction record must be ignored by the collector.
		func() []byte {
			f := tcpFlow(2, "kube3.kasil.cloud", "nanomq", "nanomq-0", "172.16.2.9", workload("nanomq", "nanomq", "StatefulSet"), "frigate", "frigate-7d9f8c6b5-abcde", "172.16.1.5", workload("frigate", "frigate", "Deployment"), nil, 1883, 43210, 5)
			f.TrafficDirection = flowpb.TrafficDirection_INGRESS
			return env("kube3.kasil.cloud", f)
		}(),
		// A reply-direction record must be ignored too.
		func() []byte {
			f := tcpFlow(2, "kube2.kasil.cloud", "frigate", "frigate-7d9f8c6b5-abcde", "172.16.1.5", workload("frigate", "frigate", "Deployment"), "", "", "149.154.167.220", nil, []string{"api.telegram.org."}, 51001, 443, 400)
			f.IsReply = wrapperspb.Bool(true)
			return env("kube2.kasil.cloud", f)
		}(),
	}
	writeLog(filepath.Join(out, "audit-agg.json.log"), agg)

	deny := [][]byte{
		env("kube3.kasil.cloud", func() *flowpb.Flow {
			f := tcpFlow(3, "kube3.kasil.cloud", "renovate", "renovate-29384756-x7k2p", "172.16.4.9", workload("renovate", "renovate", "CronJob"), "", "", "140.82.121.6", nil, []string{"api.github.com."}, 51234, 443, 0)
			f.Verdict = flowpb.Verdict_DROPPED
			f.DropReasonDesc = flowpb.DropReason_POLICY_DENIED
			return f
		}()),
		// Policy-verdict record from the same endpoint: the design stores it
		// too, because the aggregated exporter is filtered to FORWARDED-free
		// verdicts only in deny-raw.
		env("kube3.kasil.cloud", func() *flowpb.Flow {
			f := tcpFlow(3, "kube3.kasil.cloud", "renovate", "renovate-29384756-x7k2p", "172.16.4.9", workload("renovate", "renovate", "CronJob"), "", "", "172.30.0.10", nil, nil, 51235, 53, 0)
			f.Verdict = flowpb.Verdict_DROPPED
			f.DropReasonDesc = flowpb.DropReason_POLICY_DENIED
			f.L4 = &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{SourcePort: 51235, DestinationPort: 53}}}
			return f
		}()),
	}
	writeLog(filepath.Join(out, "deny-raw.json.log"), deny)

	dns := [][]byte{
		env("kube1.kasil.cloud", func() *flowpb.Flow {
			f := tcpFlow(4, "kube1.kasil.cloud", "hermes", "hermes-0", "172.16.4.7", workload("hermes", "hermes", "StatefulSet"), "", "", "172.30.0.10", nil, nil, 40000, 53, 0)
			f.L4 = &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{SourcePort: 40000, DestinationPort: 53}}}
			f.L7 = &flowpb.Layer7{Type: flowpb.L7FlowType_REQUEST, Record: &flowpb.Layer7_Dns{Dns: &flowpb.DNS{Query: "api.telegram.org."}}}
			return f
		}()),
		env("kube1.kasil.cloud", func() *flowpb.Flow {
			f := tcpFlow(4, "kube1.kasil.cloud", "hermes", "hermes-0", "172.16.4.7", workload("hermes", "hermes", "StatefulSet"), "", "", "172.30.0.10", nil, nil, 53, 40000, 0)
			f.L4 = &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{SourcePort: 53, DestinationPort: 40000}}}
			f.L7 = &flowpb.Layer7{Type: flowpb.L7FlowType_RESPONSE, Record: &flowpb.Layer7_Dns{Dns: &flowpb.DNS{Query: "api.telegram.org.", Ips: []string{"149.154.167.220"}, Rcode: 0}}}
			return f
		}()),
	}
	writeLog(filepath.Join(out, "dns-raw.json.log"), dns)

	// A static-exporter file: bare flows, no envelope, and a lost-event line
	// that the parser must skip.
	bareFile := [][]byte{
		bare(tcpFlow(5, "kube4.kasil.cloud", "grafana", "grafana-5f7d9c8b4-qq2vz", "172.16.5.3", workload("grafana", "grafana", "Deployment"), "victoria", "vmsingle-victoria-metrics-k8s-stack-0", "172.16.6.4", workload("vmsingle", "vmsingle", "StatefulSet"), nil, 40001, 8428, 4000)),
		[]byte(`{"lost_events":{"num_events_lost":3,"cpu":"cpu1"},"node_name":"kube1.kasil.cloud","time":"2026-11-25T10:05:00Z"}`),
		[]byte(`not json at all`),
	}
	writeLog(filepath.Join(out, "static-bare.json.log"), bareFile)

	fmt.Println("wrote fixtures to", out)
}

func writeLog(path string, lines [][]byte) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.Write(append(l, '\n')); err != nil {
			panic(err)
		}
	}
}

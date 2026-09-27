// ns3sim/src/saf-sim.cc
//
// Main ns-3 simulation: a star topology (one broker node, N client nodes,
// each on its own point-to-point link with a configurable delay/loss
// profile) running the real SafBrokerApp / SafClientApp state machines
// from this directory -- Algorithm 1 + Algorithm 2 exactly as
// saf/gateway.py and saf/client.py implement them, cross-checked for
// byte-identical crypto against the Python implementation by
// tools/crosscheck_hmac.py (see ns3sim/README.md). ns-3's FlowMonitor
// captures real packet-level network metrics (delay, throughput, loss);
// the broker/client apps' own event streams capture protocol-level
// outcomes (registrations, approvals, denials and why). Both are dumped
// to a single JSON summary at the end of the run.
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-module.h"

#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <vector>

#include "saf-broker-app.h"
#include "saf-client-app.h"

using namespace ns3;
using namespace safsim;
using json = nlohmann::json;

NS_LOG_COMPONENT_DEFINE("SafSim");

namespace {

struct LinkProfile {
  const char *name;
  const char *delay;
  double lossRate;
};

// Three link tiers, cycled across clients -- stands in for the old
// SimPy simulator's "link condition mix", except every number here now
// comes from ns-3's own point-to-point delay model and RateErrorModel,
// not a hand-picked distribution.
const LinkProfile kLinkProfiles[] = {
    {"good", "2ms", 0.0},
    {"medium", "20ms", 0.01},
    {"poor", "80ms", 0.05},
};

std::vector<ClientEvent> g_clientEvents;
std::mutex g_eventsMutex;  // unused in single-threaded ns-3, kept for clarity/safety

void RecordClientEvent(const ClientEvent &ev) {
  std::lock_guard<std::mutex> lock(g_eventsMutex);
  g_clientEvents.push_back(ev);
}

}  // namespace

int main(int argc, char *argv[]) {
  uint32_t nPublishers = 15;
  uint32_t nSubscribers = 10;
  uint32_t nTamperAttackers = 3;
  uint32_t nReplayAttackers = 3;
  uint32_t nGhostAttackers = 3;
  uint32_t publishMessages = 3;
  double publishIntervalSeconds = 2.0;
  double durationSeconds = 30.0;
  std::string topic = "sensors/temperature";
  std::string outFile = "ns3sim-results.json";
  uint16_t brokerPort = 9000;
  uint32_t maxClients = 50;

  CommandLine cmd;
  cmd.AddValue("nPublishers", "Number of legitimate publisher clients", nPublishers);
  cmd.AddValue("nSubscribers", "Number of legitimate subscriber clients", nSubscribers);
  cmd.AddValue("nTamperAttackers", "Number of tampered-HMAC attacker clients", nTamperAttackers);
  cmd.AddValue("nReplayAttackers", "Number of replayed-identifier attacker clients",
               nReplayAttackers);
  cmd.AddValue("nGhostAttackers", "Number of never-registered (ghost) attacker clients",
               nGhostAttackers);
  cmd.AddValue("publishMessages", "Publish attempts per legitimate publisher", publishMessages);
  cmd.AddValue("publishInterval", "Seconds between a publisher's repeated attempts",
               publishIntervalSeconds);
  cmd.AddValue("duration", "Simulation duration in seconds", durationSeconds);
  cmd.AddValue("topic", "Shared application topic every client publishes/subscribes to", topic);
  cmd.AddValue("out", "Output JSON summary path", outFile);
  cmd.AddValue("maxClients", "Broker's Section V-B registration rate-limit cap "
               "(mirrors saf/state_store.py's SAFStateStore max_clients=50 default) -- "
               "raise this if nPublishers+nSubscribers+nTamperAttackers+nReplayAttackers "
               "exceeds it, or some will be correctly denied at registration", maxClients);
  cmd.Parse(argc, argv);

  uint32_t nClients = nPublishers + nSubscribers + nTamperAttackers + nReplayAttackers +
                       nGhostAttackers;

  NodeContainer brokerNode;
  brokerNode.Create(1);
  NodeContainer clientNodes;
  clientNodes.Create(nClients);

  InternetStackHelper stack;
  stack.Install(brokerNode);
  stack.Install(clientNodes);

  Ptr<SafBrokerApp> brokerApp = CreateObject<SafBrokerApp>();
  brokerApp->Setup(brokerPort, maxClients);
  brokerNode.Get(0)->AddApplication(brokerApp);
  brokerApp->SetStartTime(Seconds(0.0));
  brokerApp->SetStopTime(Seconds(durationSeconds));

  FlowMonitorHelper flowHelper;
  Ptr<FlowMonitor> flowMonitor = flowHelper.InstallAll();

  struct ClientSpec {
    ClientRole role;
    std::string label;
  };
  std::vector<ClientSpec> specs;
  for (uint32_t i = 0; i < nPublishers; ++i) specs.push_back({ClientRole::kPublisher, "pub"});
  for (uint32_t i = 0; i < nSubscribers; ++i) specs.push_back({ClientRole::kSubscriber, "sub"});
  for (uint32_t i = 0; i < nTamperAttackers; ++i)
    specs.push_back({ClientRole::kTamperAttacker, "tamper"});
  for (uint32_t i = 0; i < nReplayAttackers; ++i)
    specs.push_back({ClientRole::kReplayAttacker, "replay"});
  for (uint32_t i = 0; i < nGhostAttackers; ++i)
    specs.push_back({ClientRole::kGhostAttacker, "ghost"});

  std::vector<Ptr<SafClientApp>> clientApps;

  for (uint32_t i = 0; i < nClients; ++i) {
    const LinkProfile &profile = kLinkProfiles[i % 3];

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue(profile.delay));

    NodeContainer pair(brokerNode.Get(0), clientNodes.Get(i));
    NetDeviceContainer devices = p2p.Install(pair);

    if (profile.lossRate > 0.0) {
      Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
      em->SetAttribute("ErrorRate", DoubleValue(profile.lossRate));
      em->SetAttribute("ErrorUnit", EnumValue(RateErrorModel::ERROR_UNIT_PACKET));
      devices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));
    }

    Ipv4AddressHelper addrHelper;
    std::ostringstream base;
    base << "10.1." << (i + 1) << ".0";
    addrHelper.SetBase(Ipv4Address(base.str().c_str()), "255.255.255.252");
    Ipv4InterfaceContainer ifaces = addrHelper.Assign(devices);
    // Each client sits on its own point-to-point link/subnet (a star, not
    // a shared LAN with no routing installed between links), so it must
    // dial the broker-side address of *this* link, not a single address
    // shared across every client -- ifaces.GetAddress(0) is that address
    // for this iteration.
    Ipv4Address brokerAddrForThisLink = ifaces.GetAddress(0);

    const ClientSpec &spec = specs[i];
    std::string clientId = spec.label + "-" + std::to_string(i);

    Ptr<SafClientApp> clientApp = CreateObject<SafClientApp>();
    uint32_t numMessages = (spec.role == ClientRole::kSubscriber) ? 1
                            : (spec.role == ClientRole::kTamperAttacker) ? 2
                            : (spec.role == ClientRole::kReplayAttacker) ? 2
                            : (spec.role == ClientRole::kGhostAttacker) ? 1
                                                                        : publishMessages;
    clientApp->Setup(brokerAddrForThisLink, brokerPort, clientId, spec.role, topic, numMessages,
                      Seconds(publishIntervalSeconds));
    clientApp->SetEventCallback(&RecordClientEvent);
    clientNodes.Get(i)->AddApplication(clientApp);
    // Small stagger so nClients TCP connects don't all land in the same
    // microsecond; still well within the run for a `duration`-second sim.
    double startTime = 0.5 + 0.01 * i;
    clientApp->SetStartTime(Seconds(startTime));
    clientApp->SetStopTime(Seconds(durationSeconds));
    clientApps.push_back(clientApp);
  }

  Simulator::Stop(Seconds(durationSeconds + 1.0));
  Simulator::Run();

  // ---- Gather results ----
  flowMonitor->CheckForLostPackets();
  Ptr<Ipv4FlowClassifier> classifier =
      DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
  json flows = json::array();
  for (const auto &kv : flowMonitor->GetFlowStats()) {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(kv.first);
    const FlowMonitor::FlowStats &s = kv.second;
    double meanDelay = s.rxPackets > 0 ? (s.delaySum.GetSeconds() / s.rxPackets) : 0.0;
    double durationS = (s.timeLastRxPacket - s.timeFirstTxPacket).GetSeconds();
    double throughputBps = durationS > 0 ? (s.rxBytes * 8.0 / durationS) : 0.0;
    flows.push_back({
        {"src", t.sourceAddress.Get()},
        {"dst", t.destinationAddress.Get()},
        {"tx_packets", s.txPackets},
        {"rx_packets", s.rxPackets},
        {"lost_packets", s.lostPackets},
        {"mean_delay_seconds", meanDelay},
        {"throughput_bps", throughputBps},
    });
  }

  json decisionLog = json::array();
  for (const auto &e : brokerApp->DecisionLog()) {
    decisionLog.push_back(
        {{"t", e.t}, {"phase", e.phase}, {"client_id", e.client_id}, {"status", e.status},
         {"reason", e.reason}});
  }

  json clientEvents = json::array();
  for (const auto &e : g_clientEvents) {
    clientEvents.push_back(
        {{"t", e.t}, {"client_id", e.client_id}, {"kind", e.kind}, {"detail", e.detail}});
  }

  const BrokerStats &st = brokerApp->Stats();
  json summary = {
      {"config",
       {{"n_publishers", nPublishers},
        {"n_subscribers", nSubscribers},
        {"n_tamper_attackers", nTamperAttackers},
        {"n_replay_attackers", nReplayAttackers},
        {"n_ghost_attackers", nGhostAttackers},
        {"max_clients", maxClients},
        {"topic", topic},
        {"duration_seconds", durationSeconds}}},
      {"broker_stats",
       {{"presession_established", st.presession_established},
        {"presession_denied", st.presession_denied},
        {"phase2_approved", st.phase2_approved},
        {"phase2_denied", st.phase2_denied},
        {"denied_hmac_mismatch", st.denied_hmac_mismatch},
        {"denied_duplicate_identifier", st.denied_duplicate_identifier},
        {"denied_stale_timestamp", st.denied_stale_timestamp},
        {"denied_unregistered", st.denied_unregistered},
        {"app_messages_relayed", st.app_messages_relayed}}},
      {"decision_log", decisionLog},
      {"client_events", clientEvents},
      {"flow_monitor", flows},
  };

  std::ofstream out(outFile);
  out << summary.dump(2);
  out.close();

  std::cout << "=== SAF ns-3 simulation complete ===\n";
  std::cout << "clients: " << nClients << " (pub=" << nPublishers << " sub=" << nSubscribers
            << " tamper=" << nTamperAttackers << " replay=" << nReplayAttackers
            << " ghost=" << nGhostAttackers << ")\n";
  std::cout << "registration rate-limit cap (--maxClients): " << maxClients << "\n";
  std::cout << "presession established/denied: " << st.presession_established << "/"
            << st.presession_denied << "\n";
  std::cout << "phase2 approved/denied: " << st.phase2_approved << "/" << st.phase2_denied
            << " (hmac_mismatch=" << st.denied_hmac_mismatch
            << " duplicate_id=" << st.denied_duplicate_identifier
            << " stale_ts=" << st.denied_stale_timestamp
            << " unregistered=" << st.denied_unregistered << ")\n";
  std::cout << "app messages relayed: " << st.app_messages_relayed << "\n";
  std::cout << "flows tracked: " << flows.size() << "\n";
  std::cout << "results written to " << outFile << "\n";

  Simulator::Destroy();
  return 0;
}

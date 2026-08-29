import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/otp/actor

pub type NodeInfo {
  NodeInfo(
    node_name: String,
    ip_address: String,
    role: String,
    status: String,
    sync_count: Int,
  )
}

pub type ClusterStatus {
  ClusterStatus(
    cluster_id: String,
    leader_node: String,
    active_nodes: List(NodeInfo),
    total_sync_events: Int,
  )
}

pub type ClusterMessage {
  RegisterNode(
    node_name: String,
    ip_address: String,
    role: String,
    reply_with: Subject(NodeInfo),
  )
  GossipSync(from_node: String, payload: String, reply_with: Subject(Int))
  GetClusterStatus(reply_with: Subject(ClusterStatus))
  ElectLeader(reply_with: Subject(String))
}

pub type ClusterState {
  ClusterState(
    cluster_id: String,
    leader_node: String,
    nodes: List(NodeInfo),
    total_syncs: Int,
  )
}

pub fn handle_message(
  state: ClusterState,
  msg: ClusterMessage,
) -> actor.Next(ClusterState, ClusterMessage) {
  case msg {
    RegisterNode(node_name, ip_address, role, reply_with) -> {
      let node = NodeInfo(
        node_name: node_name,
        ip_address: ip_address,
        role: role,
        status: "ONLINE",
        sync_count: 0,
      )
      let updated_nodes = [node, ..list.filter(state.nodes, fn(n) { n.node_name != node_name })]
      
      let leader = case state.leader_node {
        "" -> node_name
        existing -> existing
      }

      let new_state = ClusterState(
        cluster_id: state.cluster_id,
        leader_node: leader,
        nodes: updated_nodes,
        total_syncs: state.total_syncs,
      )

      process.send(reply_with, node)
      actor.continue(new_state)
    }

    GossipSync(from_node, _payload, reply_with) -> {
      let new_total = state.total_syncs + 1
      let updated_nodes = list.map(state.nodes, fn(node) {
        case node.node_name == from_node {
          True -> NodeInfo(
            node_name: node.node_name,
            ip_address: node.ip_address,
            role: node.role,
            status: "ONLINE",
            sync_count: node.sync_count + 1,
          )
          False -> node
        }
      })

      let new_state = ClusterState(
        cluster_id: state.cluster_id,
        leader_node: state.leader_node,
        nodes: updated_nodes,
        total_syncs: new_total,
      )

      process.send(reply_with, new_total)
      actor.continue(new_state)
    }

    GetClusterStatus(reply_with) -> {
      let status = ClusterStatus(
        cluster_id: state.cluster_id,
        leader_node: state.leader_node,
        active_nodes: state.nodes,
        total_sync_events: state.total_syncs,
      )
      process.send(reply_with, status)
      actor.continue(state)
    }

    ElectLeader(reply_with) -> {
      let new_leader = case state.nodes {
        [first, ..] -> first.node_name
        [] -> "jia@standalone"
      }

      let new_state = ClusterState(
        cluster_id: state.cluster_id,
        leader_node: new_leader,
        nodes: state.nodes,
        total_syncs: state.total_syncs,
      )

      process.send(reply_with, new_leader)
      actor.continue(new_state)
    }
  }
}

pub fn start() -> Result(Subject(ClusterMessage), actor.StartError) {
  let initial_state = ClusterState(
    cluster_id: "jia-beam-cluster-v1",
    leader_node: "jia@beam-daemon",
    nodes: [
      NodeInfo(
        node_name: "jia@beam-daemon",
        ip_address: "127.0.0.1",
        role: "BEAM_DAEMON_ORCHESTRATOR",
        status: "ONLINE",
        sync_count: 0,
      ),
      NodeInfo(
        node_name: "jia_native@sidecar",
        ip_address: "127.0.0.1",
        role: "RUST_VELLA_ENGINE",
        status: "ONLINE",
        sync_count: 0,
      ),
    ],
    total_syncs: 0,
  )

  actor.new(initial_state)
  |> actor.on_message(handle_message)
  |> actor.start
  |> fn(res) {
    case res {
      Ok(started) -> Ok(started.data)
      Error(err) -> Error(err)
    }
  }
}

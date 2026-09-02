import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/otp/actor

pub type Role {
  Leader
  Follower
  Candidate
}

pub type LogEntry {
  LogEntry(
    index: Int,
    term: Int,
    command: String,
    data: String,
  )
}

pub type RaftStatus {
  RaftStatus(
    node_id: String,
    role: Role,
    current_term: Int,
    voted_for: String,
    commit_index: Int,
    log_length: Int,
    leader_id: String,
    cluster_size: Int,
  )
}

pub type VoteResponse {
  VoteResponse(term: Int, vote_granted: Bool)
}

pub type AppendResponse {
  AppendResponse(term: Int, success: Bool, match_index: Int)
}

pub type RaftMessage {
  RequestVote(
    term: Int,
    candidate_id: String,
    last_log_index: Int,
    last_log_term: Int,
    reply_to: Subject(VoteResponse),
  )
  ReceiveVoteResponse(resp: VoteResponse)
  AppendEntries(
    term: Int,
    leader_id: String,
    prev_log_index: Int,
    prev_log_term: Int,
    entries: List(LogEntry),
    leader_commit: Int,
    reply_to: Subject(AppendResponse),
  )
  ReceiveAppendResponse(resp: AppendResponse)
  ProposeCommand(command: String, data: String, reply_to: Subject(Result(Int, String)))
  GetStatus(reply_to: Subject(RaftStatus))
  TriggerElection
}



pub type RaftState {
  RaftState(
    node_id: String,
    role: Role,
    current_term: Int,
    voted_for: String,
    log: List(LogEntry),
    commit_index: Int,
    last_applied: Int,
    leader_id: String,
    votes_received: Int,
    peers: List(String),
  )
}

pub fn handle_message(
  state: RaftState,
  msg: RaftMessage,
) -> actor.Next(RaftState, RaftMessage) {
  case msg {
    GetStatus(reply_to) -> {
      let status =
        RaftStatus(
          node_id: state.node_id,
          role: state.role,
          current_term: state.current_term,
          voted_for: state.voted_for,
          commit_index: state.commit_index,
          log_length: list.length(state.log),
          leader_id: state.leader_id,
          cluster_size: list.length(state.peers) + 1,
        )
      process.send(reply_to, status)
      actor.continue(state)
    }

    RequestVote(term, candidate_id, _last_idx, _last_term, reply_to) -> {
      let should_vote = case term > state.current_term {
        True -> True
        False ->
          term == state.current_term
          && { state.voted_for == "" || state.voted_for == candidate_id }
      }

      let new_state = case should_vote {
        True ->
          RaftState(
            ..state,
            current_term: term,
            voted_for: candidate_id,
            role: Follower,
          )
        False -> state
      }

      process.send(reply_to, VoteResponse(term: new_state.current_term, vote_granted: should_vote))
      actor.continue(new_state)
    }

    ReceiveVoteResponse(VoteResponse(term, vote_granted)) -> {
      case state.role == Candidate && term == state.current_term && vote_granted {
        True -> {
          let new_votes = state.votes_received + 1
          let majority = { { list.length(state.peers) + 1 } / 2 } + 1
          let become_leader = new_votes >= majority

          let new_role = case become_leader {
            True -> Leader
            False -> Candidate
          }
          let new_leader_id = case become_leader {
            True -> state.node_id
            False -> state.leader_id
          }

          let new_state =
            RaftState(
              ..state,
              role: new_role,
              leader_id: new_leader_id,
              votes_received: new_votes,
            )
          actor.continue(new_state)
        }
        False -> actor.continue(state)
      }
    }

    AppendEntries(term, leader_id, _prev_idx, _prev_term, entries, leader_commit, reply_to) -> {
      let valid_leader = term >= state.current_term

      case valid_leader {
        True -> {
          let new_log = list.append(state.log, entries)
          let new_commit = case leader_commit > state.commit_index {
            True -> leader_commit
            False -> state.commit_index
          }

          let new_state =
            RaftState(
              ..state,
              current_term: term,
              role: Follower,
              leader_id: leader_id,
              log: new_log,
              commit_index: new_commit,
            )
          process.send(
            reply_to,
            AppendResponse(
              term: term,
              success: True,
              match_index: list.length(new_log),
            ),
          )
          actor.continue(new_state)
        }
        False -> {
          process.send(
            reply_to,
            AppendResponse(
              term: state.current_term,
              success: False,
              match_index: state.commit_index,
            ),
          )
          actor.continue(state)
        }
      }
    }

    ReceiveAppendResponse(AppendResponse(_term, _success, _match_idx)) -> {
      actor.continue(state)
    }


    ProposeCommand(command, data, reply_to) -> {
      case state.role {
        Leader -> {
          let next_index = list.length(state.log) + 1
          let entry =
            LogEntry(
              index: next_index,
              term: state.current_term,
              command: command,
              data: data,
            )
          let new_log = list.append(state.log, [entry])
          let new_commit = next_index // Local quorum commit in single-node testing

          let new_state =
            RaftState(
              ..state,
              log: new_log,
              commit_index: new_commit,
            )
          process.send(reply_to, Ok(next_index))
          actor.continue(new_state)
        }
        _ -> {
          process.send(reply_to, Error("Not the Raft Leader. Current leader: " <> state.leader_id))
          actor.continue(state)
        }
      }
    }

    TriggerElection -> {
      let new_term = state.current_term + 1
      let new_state =
        RaftState(
          ..state,
          role: Candidate,
          current_term: new_term,
          voted_for: state.node_id,
          votes_received: 1, // Vote for self
        )
      actor.continue(new_state)
    }
  }
}

pub fn start(node_id: String, peers: List(String)) -> Result(Subject(RaftMessage), actor.StartError) {
  let initial_state =
    RaftState(
      node_id: node_id,
      role: Follower,
      current_term: 0,
      voted_for: "",
      log: [],
      commit_index: 0,
      last_applied: 0,
      leader_id: "",
      votes_received: 0,
      peers: peers,
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

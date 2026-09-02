import gleam/erlang/process.{type Subject}
import gleam/otp/actor
import jia/actor as threat_actor
import jia/worker_pool

pub type SupervisorMessage {
  GetThreatActor(reply_to: Subject(Subject(threat_actor.ThreatMessage)))
  GetWorkerPool(reply_to: Subject(Subject(worker_pool.PoolMessage)))
}

pub type SupervisorState {
  SupervisorState(
    threat_actor_subject: Subject(threat_actor.ThreatMessage),
    worker_pool_subject: Subject(worker_pool.PoolMessage),
  )
}

pub fn handle_message(
  state: SupervisorState,
  msg: SupervisorMessage,
) -> actor.Next(SupervisorState, SupervisorMessage) {
  case msg {
    GetThreatActor(reply_to) -> {
      process.send(reply_to, state.threat_actor_subject)
      actor.continue(state)
    }

    GetWorkerPool(reply_to) -> {
      process.send(reply_to, state.worker_pool_subject)
      actor.continue(state)
    }
  }
}

pub fn start() -> Result(Subject(SupervisorMessage), actor.StartError) {
  let assert Ok(threat_subj) = threat_actor.start()
  let assert Ok(pool_subj) = worker_pool.start(10)

  let initial_state =
    SupervisorState(
      threat_actor_subject: threat_subj,
      worker_pool_subject: pool_subj,
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

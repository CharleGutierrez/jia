import gleam/erlang/process.{type Subject}
import gleam/otp/actor
import jia/security_rules.{type AnalysisReport, type SecurityLog}

pub type ThreatMessage {
  EnqueueEvent(log: SecurityLog, reply_with: Subject(AnalysisReport))
  QuarantineAlert(target: String, reason: String)
  GetQueueLength(reply_with: Subject(Int))
}

pub type ActorState {
  ActorState(
    event_queue: List(SecurityLog),
    quarantined_targets: List(#(String, String)),
    total_processed: Int,
  )
}

pub fn handle_message(
  state: ActorState,
  msg: ThreatMessage,
) -> actor.Next(ActorState, ThreatMessage) {
  case msg {
    EnqueueEvent(log, reply_with) -> {
      let report = security_rules.classify_event(log)
      process.send(reply_with, report)

      let new_state =
        ActorState(
          event_queue: [log, ..state.event_queue],
          quarantined_targets: state.quarantined_targets,
          total_processed: state.total_processed + 1,
        )
      actor.continue(new_state)
    }

    QuarantineAlert(target, reason) -> {
      let new_quarantined = [#(target, reason), ..state.quarantined_targets]
      let new_state =
        ActorState(
          event_queue: state.event_queue,
          quarantined_targets: new_quarantined,
          total_processed: state.total_processed,
        )
      actor.continue(new_state)
    }

    GetQueueLength(reply_with) -> {
      process.send(reply_with, state.total_processed)
      actor.continue(state)
    }
  }
}

pub fn start() -> Result(Subject(ThreatMessage), actor.StartError) {
  let initial_state =
    ActorState(
      event_queue: [],
      quarantined_targets: [],
      total_processed: 0,
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

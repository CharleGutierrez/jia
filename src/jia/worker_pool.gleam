import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/otp/actor
import jia/security_rules.{type AnalysisReport, type SecurityLog}

pub type PoolMessage {
  SubmitTask(log: SecurityLog, reply_to: Subject(AnalysisReport))
  GetPoolStats(reply_to: Subject(PoolStats))
}

pub type PoolStats {
  PoolStats(
    active_workers: Int,
    queue_depth: Int,
    completed_jobs: Int,
  )
}

pub type PoolState {
  PoolState(
    max_workers: Int,
    active_workers: Int,
    pending_tasks: List(#(SecurityLog, Subject(AnalysisReport))),
    completed_jobs: Int,
  )
}

pub fn handle_message(
  state: PoolState,
  msg: PoolMessage,
) -> actor.Next(PoolState, PoolMessage) {
  case msg {
    SubmitTask(log, reply_to) -> {
      // Execute security classification
      let report = security_rules.classify_event(log)
      process.send(reply_to, report)

      let new_state =
        PoolState(
          max_workers: state.max_workers,
          active_workers: state.active_workers,
          pending_tasks: state.pending_tasks,
          completed_jobs: state.completed_jobs + 1,
        )
      actor.continue(new_state)
    }

    GetPoolStats(reply_to) -> {
      let stats =
        PoolStats(
          active_workers: state.active_workers,
          queue_depth: list.length(state.pending_tasks),
          completed_jobs: state.completed_jobs,
        )
      process.send(reply_to, stats)
      actor.continue(state)
    }
  }
}

pub fn start(max_workers: Int) -> Result(Subject(PoolMessage), actor.StartError) {
  let initial_state =
    PoolState(
      max_workers: max_workers,
      active_workers: 0,
      pending_tasks: [],
      completed_jobs: 0,
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

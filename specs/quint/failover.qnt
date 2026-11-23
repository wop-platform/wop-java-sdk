/// Failover 重试策略的形式化模型（§7.3 P2 / K4）。
///
/// 关注的不是"重试几次"，而是"哪些失败允许切换候选"：
///   - 连接建立失败（拒绝 / 域名不存在 / 无路由）：请求字节未发出，重试无副作用；
///   - 连接超时：TCP 握手未完成，请求字节同样未发出，语义上同属"发送前失败"；
///   - 读超时：请求已完整发出，重试可能产生重复副作用，必须致命。
///
/// `failoverCurrent` 是现状实现（FailoverTransport.isPreSendRetryable 只认
/// ConnectException / UnknownHostException / NoRouteToHostException）；
/// `failoverFixed` 把连接超时也纳入可重试。其余状态机逐行相同，便于对照。
///
/// 规模取最小可证伪实例：N=2 候选、budget=1 次重试，任一候选都可达预算内，
/// 于是"有 Up 候选却失败"必然意味着策略丢了可用性，而不是预算不够。

module failover_current {

  pure val N = 2
  pure val budget = 1

  type Status = Up | ConnectRefused | ConnectTimeout | ReadTimeout
  pure val statuses = Set(Up, ConnectRefused, ConnectTimeout, ReadTimeout)

  /// 现状策略：仅连接建立失败可重试。连接超时不在其中。
  pure def retryable(s: Status): bool = s == ConnectRefused

  /// 候选网关的真实可用性，init 时非确定选取，覆盖全部组合。
  var env: List[Status]
  /// 下一个待尝试的候选下标；单调递增即保证按序且不重复。
  var idx: int
  var budgetLeft: int
  /// 已尝试结果序列，用于表达"发出后不得再试"。
  var history: List[Status]
  var outcome: str

  action init = all {
    nondet e0 = statuses.oneOf()
    nondet e1 = statuses.oneOf()
    env' = [e0, e1],
    idx' = 0,
    budgetLeft' = budget,
    history' = [],
    outcome' = "running",
  }

  action succeed = all {
    outcome == "running",
    idx < N,
    env[idx] == Up,
    history' = history.append(Up),
    outcome' = "succeeded",
    env' = env,
    idx' = idx,
    budgetLeft' = budgetLeft,
  }

  action failAndRetry = all {
    outcome == "running",
    idx < N,
    retryable(env[idx]),
    budgetLeft > 0,
    history' = history.append(env[idx]),
    idx' = idx + 1,
    budgetLeft' = budgetLeft - 1,
    outcome' = "running",
    env' = env,
  }

  action giveUp = all {
    outcome == "running",
    not(idx < N and env[idx] == Up),
    not(idx < N and retryable(env[idx]) and budgetLeft > 0),
    history' = if (idx < N) history.append(env[idx]) else history,
    outcome' = "failed",
    env' = env,
    idx' = idx,
    budgetLeft' = budgetLeft,
  }

  /// 终态空转：避免 Apalache 把 quiescence 判成死锁。
  action stutter = all {
    outcome != "running",
    env' = env,
    idx' = idx,
    budgetLeft' = budgetLeft,
    history' = history,
    outcome' = outcome,
  }

  action step = any { succeed, failAndRetry, giveUp, stutter }

  /// 尝试次数不超过 1 + budget。
  val boundedAttempts = history.length() <= budget + 1

  /// 读超时一旦出现，不得再有后续尝试（请求已发出）。
  val noRetryAfterSend =
    not(history.foldl(false, (acc, s) => acc or s == ReadTimeout)) or outcome != "running"

  /// 成功必然对应命中了 Up 候选。
  val successOnlyWhenUp = outcome != "succeeded" or env[idx] == Up

  /// 可用性：没有发生"已发出请求的失败"时，失败即意味着确实没有可用候选。
  ///
  /// 现状实现在 (ConnectTimeout, Up) 环境下违反此性质 —— 主网关握手超时、
  /// 备用网关健康，却直接失败，failover 在最需要它的场景下不生效。
  val availability =
    outcome != "failed"
      or history.foldl(false, (acc, s) => acc or s == ReadTimeout)
      or not(env.foldl(false, (acc, s) => acc or s == Up))
}

module failover_fixed {

  pure val N = 2
  pure val budget = 1

  type Status = Up | ConnectRefused | ConnectTimeout | ReadTimeout
  pure val statuses = Set(Up, ConnectRefused, ConnectTimeout, ReadTimeout)

  /// 修正策略：连接超时与连接拒绝同等对待（两者都未发出请求字节），
  /// 读超时仍然致命。
  pure def retryable(s: Status): bool =
    s == ConnectRefused or s == ConnectTimeout

  var env: List[Status]
  var idx: int
  var budgetLeft: int
  var history: List[Status]
  var outcome: str

  action init = all {
    nondet e0 = statuses.oneOf()
    nondet e1 = statuses.oneOf()
    env' = [e0, e1],
    idx' = 0,
    budgetLeft' = budget,
    history' = [],
    outcome' = "running",
  }

  action succeed = all {
    outcome == "running",
    idx < N,
    env[idx] == Up,
    history' = history.append(Up),
    outcome' = "succeeded",
    env' = env,
    idx' = idx,
    budgetLeft' = budgetLeft,
  }

  action failAndRetry = all {
    outcome == "running",
    idx < N,
    retryable(env[idx]),
    budgetLeft > 0,
    history' = history.append(env[idx]),
    idx' = idx + 1,
    budgetLeft' = budgetLeft - 1,
    outcome' = "running",
    env' = env,
  }

  action giveUp = all {
    outcome == "running",
    not(idx < N and env[idx] == Up),
    not(idx < N and retryable(env[idx]) and budgetLeft > 0),
    history' = if (idx < N) history.append(env[idx]) else history,
    outcome' = "failed",
    env' = env,
    idx' = idx,
    budgetLeft' = budgetLeft,
  }

  action stutter = all {
    outcome != "running",
    env' = env,
    idx' = idx,
    budgetLeft' = budgetLeft,
    history' = history,
    outcome' = outcome,
  }

  action step = any { succeed, failAndRetry, giveUp, stutter }

  val boundedAttempts = history.length() <= budget + 1

  val noRetryAfterSend =
    not(history.foldl(false, (acc, s) => acc or s == ReadTimeout)) or outcome != "running"

  val successOnlyWhenUp = outcome != "succeeded" or env[idx] == Up

  val availability =
    outcome != "failed"
      or history.foldl(false, (acc, s) => acc or s == ReadTimeout)
      or not(env.foldl(false, (acc, s) => acc or s == Up))
}

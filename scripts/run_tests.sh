#!/usr/bin/env bash
# 工厂测试门（wop-java-sdk 本地化）——mvn verify 全量（测试 + jacoco 覆盖率门禁 LINE/BRANCH 1.00）。
# 用法: scripts/run_tests.sh [--no-lock] [mvn-args...]
#   --no-lock 为工厂链约定旗标（上游 run_tests.sh 的锁语义），本仓无锁，消费并忽略。
set -euo pipefail
ARGS=()
for a in "$@"; do
  [ "$a" = "--no-lock" ] && continue
  ARGS+=("$a")
done
exec mvn -q verify "${ARGS[@]+"${ARGS[@]}"}"

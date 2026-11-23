#!/usr/bin/env bash
# JMH 微基准运行器（与 gateway / service 仓 scripts/perf/run-jmh.sh 同口径）。
# 基准源码在 <module>/src/perf/java/perf/jmh，不是 Maven source root：常规 mvn test /
# package / CI 不编译、不执行，JCA 与覆盖率门禁完全不受影响。
# JMH 四件套优先软链 ~/.m2 本地仓库，缺失才回落到中央仓。
#
#   scripts/perf/run-jmh.sh                                   # wop-sdk-core 全量
#   scripts/perf/run-jmh.sh wop-sdk-core SdkRequestPrepBenchmark.trimall_manual
set -euo pipefail
cd "$(dirname "$0")/../.."

MODULE="${1:-wop-sdk-core}"
SELECTOR="${2:-perf.jmh.*}"

JAVA_HOME_17="${JAVA_HOME_17:-$(/usr/libexec/java_home -v 17)}"
LIBS=target/perf/libs
SRC="$MODULE/src/perf/java/perf/jmh"
CLS="$MODULE/target/perf/jmh-classes"
mkdir -p "$LIBS" "$CLS" "$MODULE/target/perf/results"

[ -d "$SRC" ] || { echo "$MODULE 无基准源码目录 $SRC" >&2; exit 2; }

echo "compile module + deps (test scope), gen cp.txt"
mvn -q -o -pl "$MODULE" -am test-compile dependency:build-classpath \
  -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=test

MAVEN_CENTRAL=https://repo1.maven.org/maven2
M2="${HOME}/.m2/repository"
fetch() { # path-in-repo（本地文件名取路径尾段）
  local f="${1##*/}"
  [ -s "$LIBS/$f" ] && return 0
  if [ -s "$M2/$1" ]; then
    ln -sf "$M2/$1" "$LIBS/$f"
  else
    echo "fetch $f"
    curl -fsSL -o "$LIBS/$f" "$MAVEN_CENTRAL/$1"
  fi
}
fetch org/openjdk/jmh/jmh-core/1.37/jmh-core-1.37.jar
fetch org/openjdk/jmh/jmh-generator-annprocess/1.37/jmh-generator-annprocess-1.37.jar
fetch net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar
fetch org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar

PROJ_CP="$MODULE/target/classes:$MODULE/target/test-classes:$(cat "$MODULE/target/cp.txt")"
JMH_CP="$LIBS/jmh-core-1.37.jar:$LIBS/jopt-simple-5.0.4.jar:$LIBS/commons-math3-3.6.1.jar"

echo "compile benchmarks"
"$JAVA_HOME_17/bin/javac" -encoding UTF-8 -cp "$PROJ_CP:$LIBS/jmh-core-1.37.jar" \
  -processorpath "$LIBS/jmh-generator-annprocess-1.37.jar:$LIBS/jmh-core-1.37.jar" \
  -d "$CLS" "$SRC"/*.java

echo "run: $SELECTOR (JSON → $MODULE/target/perf/results/jmh.json)"
"$JAVA_HOME_17/bin/java" -cp "$CLS:$PROJ_CP:$JMH_CP" org.openjdk.jmh.Main \
  -rf json -rff "$MODULE/target/perf/results/jmh.json" -foe true "$SELECTOR"

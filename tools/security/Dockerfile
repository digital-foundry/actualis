# Security-testing image: Kali's packaged tools, pinned to what this repo needs.
#
# Nothing here ships. It runs the scanners and the transcript fuzzer against a
# read-only copy of the checkout, with no network after the build and a
# throwaway HOME, so it can never read the transcripts on the host.
#
#     make security            # builds this image, then runs tools/security/run.sh
FROM kalilinux/kali-rolling@sha256:02f5d6c019e549b0f55da58e835cad5355ef1030c6b2645265a324e37dfc4acc

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 bandit zzuf trufflehog gitleaks git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /src

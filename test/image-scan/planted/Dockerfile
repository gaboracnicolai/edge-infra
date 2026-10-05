# A known-vulnerable package planted in an image: PyYAML 5.3.1, whose
# full_load() can run arbitrary code (CVE-2020-14343, CRITICAL, fixed in 5.4).
# Only its installed-package metadata is planted — what a scanner reads to know
# what an image contains — and no code. images.yaml builds this on the OSB image
# it just pushed and requires deploy/hack/image-scan.sh to refuse the result.
ARG BASE
FROM ${BASE}
COPY PyYAML-5.3.1.dist-info/ /usr/local/lib/python3.12/site-packages/PyYAML-5.3.1.dist-info/

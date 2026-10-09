# Task 1 report (phase A)
Commit d418063. Spec: no model bcond/parts; bridge openvibes-llm-model (MIT, LICENSE only, owns %ghost 0444 model path + %config(noreplace) model.conf, Obsoletes part1/part2, Requires openvibes-llm, %posttrans message with file name from pin via %global llm_model_file); openvibes-llm installs /usr/share/openvibes-llm/model.pin. build-rpm.sh: no model fetch/OV_LLM_MODEL. check-rpm.sh: OV_CHECK_BUILT=1 mode with built-RPM checks. ci.yml: model cache and join-model check replaced by that mode. join-model.sh deleted. Docs updated.
Checks: rpmspec -P / -q parse, bash -n, shellcheck (only info notes), grep no join-model/OV_LLM_MODEL left.
Not run: build (phase B).
Doubts: scripts/fetch-llm-model.sh now unused (kept; Task 2 may reuse); bridge licence is MIT since no model bytes ship.

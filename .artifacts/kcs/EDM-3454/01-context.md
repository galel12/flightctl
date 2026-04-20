# KCS Context — EDM-3454

## Source

- **Jira:** [EDM-3454](https://issues.redhat.com/browse/EDM-3454)
- **User context:** Root cause analysis from bugfix workflow, code-level investigation of `LoadWithOverrides()` in `internal/agent/config/config.go`

## Product and Version

- Red Hat Edge Manager 1.0 (flightctl agent, fix version 1.2.0-rc1)

## Symptoms

When a device spec includes both an OS image update and an invalid agent configuration drop-in file (under `/etc/flightctl/conf.d/`), the agent fails to start after the OS update reboot. The agent log shows:

```
level=fatal msg="Error loading config: unmarshalling override config
/etc/flightctl/conf.d/enable-pruning.yaml: error converting YAML to JSON:
yaml: line 3: mapping values are not allowed in this context"
```

Greenboot health checks fail and the system enters an unhealthy state:

```
greenboot: Script '20_check_flightctl_agent.sh' FAILURE (exit code '1').
greenboot: Boot Status is RED - Health Check FAILURE!
redboot-auto-reboot: SYSTEM is UNHEALTHY, but boot_counter is unset in grubenv. Manual intervention necessary.
```

The device becomes permanently unmanageable without manual SSH intervention.

## Diagnostic Steps

1. Check the agent service status — it will show as failed/inactive.
2. Inspect the agent journal log for the `level=fatal msg="Error loading config"` message.
3. Check for invalid YAML files under `/etc/flightctl/conf.d/`.
4. Verify greenboot status shows RED.

## Workaround / Resolution

**Workaround:** Manually remove or fix the invalid configuration drop-in file, then restart the agent.

1. SSH into the affected device.
2. Identify the invalid drop-in file from the agent log.
3. Remove or correct the file under `/etc/flightctl/conf.d/`.
4. Restart the flightctl-agent service.
5. Verify the agent connects back to the management server and reports healthy status.

**Permanent fix:** `LoadWithOverrides()` should skip invalid drop-in files with a warning instead of fatally exiting, allowing the agent to start and execute rollback logic. Tracked in [EDM-3454](https://issues.redhat.com/browse/EDM-3454), fix version 1.2.0-rc1.

## Root Cause

`LoadWithOverrides()` at `internal/agent/config/config.go:432` treats invalid YAML in any `conf.d/` drop-in file as a fatal error. The error propagates to `cmd/flightctl-agent/main.go:97` where `log.Fatalf` terminates the process. Because config loading happens before bootstrap, the agent never reaches the rollback logic in `bootstrap.go`. The invalid file persists across OS rollbacks because `/etc` is a persistent overlay in bootc/ostree systems.

Introduced in PR #1126 (commit `e06ae0f8c`, EDM-1492) when `LoadWithOverrides` was added without distinguishing base config failures (truly fatal) from drop-in failures (potentially recoverable).

## Gaps

None — all sections covered.

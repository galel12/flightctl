# KCS Solution Draft — EDM-3454

> **Article Type:** Solution
> **Article Confidence:** Not-Validated (WIP)
> **Product:** Red Hat Edge Manager 1.0

---

## Title

Agent fails to start after OS update when an invalid configuration drop-in is present in Red Hat Edge Manager

## Issue

When a device spec includes both an OS image update and an invalid agent configuration drop-in file under `/etc/flightctl/conf.d/`, the flightctl agent fails to start after the reboot triggered by the OS update. The agent exits immediately with a fatal error:

```
level=fatal msg="Error loading config: unmarshalling override config
/etc/flightctl/conf.d/enable-pruning.yaml: error converting YAML to JSON:
yaml: line 3: mapping values are not allowed in this context"
```

Because the agent never starts, it cannot execute its rollback logic to revert the bad configuration. Greenboot health checks detect the agent failure and report the system as unhealthy:

```
greenboot: Boot Status is RED - Health Check FAILURE!
redboot-auto-reboot: SYSTEM is UNHEALTHY, but boot_counter is unset in grubenv.
Manual intervention necessary.
```

The device remains in this state indefinitely, requiring manual intervention to recover. [Jira: EDM-3454]

Without the OS update, the invalid drop-in does not immediately affect the running agent because configuration drop-ins are only read at agent startup or on `SIGHUP`. The OS update triggers a reboot, which restarts the agent and exposes the invalid configuration. [Jira: EDM-3454]

## Environment

- Red Hat Edge Manager 1.0 (flightctl agent)

## Diagnostic Steps

1. Check the flightctl agent service status on the affected device:

   ```
   systemctl status flightctl-agent
   ```

   The service shows as `failed` or `inactive`.

2. Inspect the agent journal log for the fatal configuration error:

   ```
   journalctl -u flightctl-agent --no-pager | grep "Error loading config"
   ```

   The output contains a line matching `level=fatal msg="Error loading config: unmarshalling override config /etc/flightctl/conf.d/<FILENAME>: ..."`.

3. Verify greenboot reports an unhealthy boot status:

   ```
   journalctl -u greenboot-healthcheck --no-pager | grep "Boot Status"
   ```

   The output shows `Boot Status is RED - Health Check FAILURE!`.

4. Identify the invalid drop-in file referenced in the agent error message and inspect its contents:

   ```
   cat /etc/flightctl/conf.d/<FILENAME>
   ```

   The file contains malformed YAML (for example, tabs used instead of spaces for indentation, or missing colons in key-value pairs).

## Resolution

**Workaround**

Remove or correct the invalid configuration drop-in file, then restart the agent so it can reconnect to the management server and resume normal operation.

**Prerequisites:** SSH or console access to the affected device.

1. Identify the invalid drop-in file from the agent log:

   ```
   journalctl -u flightctl-agent --no-pager | grep "unmarshalling override config"
   ```

   Note the file path shown in the error message (e.g., `/etc/flightctl/conf.d/enable-pruning.yaml`).

2. Remove the invalid drop-in file:

   ```
   sudo rm /etc/flightctl/conf.d/<FILENAME>
   ```

3. Restart the flightctl agent service:

   ```
   sudo systemctl restart flightctl-agent
   ```

4. Verify the agent starts successfully and connects to the management server:

   ```
   systemctl status flightctl-agent
   ```

   The service shows as `active (running)`.

5. Confirm the device reports a healthy status in the management server:

   ```
   flightctl get device <DEVICE_NAME> -o yaml | grep -A2 'status:'
   ```

   The device status shows `Online` and the update status returns to a non-error state.

A permanent fix is available in version 1.2.0-rc1. See the Root Cause section for details.

## Root Cause

The `LoadWithOverrides()` function in `internal/agent/config/config.go` treats invalid YAML in any `/etc/flightctl/conf.d/` drop-in file as a fatal error. This error propagates to the agent's `main.go` entry point, where `log.Fatalf` terminates the process before the bootstrap and rollback logic can execute. Because `/etc` is a persistent overlay in bootc/ostree systems, the invalid file survives OS rollbacks, leaving the agent permanently unable to start.

The issue was introduced in PR #1126 (EDM-1492) when `LoadWithOverrides` was added without distinguishing base configuration failures (truly fatal — the agent cannot function without its base config) from drop-in file failures (potentially recoverable — the agent can function without optional overrides). The permanent fix changes `LoadWithOverrides` to skip invalid drop-in files with a warning, allowing the agent to start and execute its rollback logic. Tracked in [EDM-3454](https://issues.redhat.com/browse/EDM-3454).

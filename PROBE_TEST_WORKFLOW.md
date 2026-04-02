# Probe Test Workflow

This is the shortest repeatable loop for live probe testing.

## 1. Check Current State

```powershell
py -3 .\tools\deploy_condition_probe.py status
py -3 .\tools\deploy_condition_probe.py list
```

## 2. Apply the First Probe

Start with the top-ranked single probes:

1. `probe_cancel_541`
2. `probe_cancel_212`
3. `probe_guard_423`
4. `probe_cancel_206`

Example:

```powershell
py -3 .\tools\deploy_condition_probe.py apply probe_cancel_541 --notes "first live test"
```

Safe rehearsal:

```powershell
py -3 .\tools\deploy_condition_probe.py apply probe_cancel_541 --dry-run
```

## 3. Launch the Game and Test

Recommended scenario:

- Load into normal sword combat
- Try light combo -> press LB during startup / active / recovery
- Try heavy attack -> press LB
- Try repeated LB taps during combo continuation

## 4. Record the Result

Examples:

```powershell
py -3 .\tools\deploy_condition_probe.py record signal --notes "LB interrupted 3rd hit once"
py -3 .\tools\deploy_condition_probe.py record no_signal --notes "No visible change across light/heavy tests"
py -3 .\tools\deploy_condition_probe.py record crash --notes "Crash during load into combat zone"
```

Suggested meanings:

- `signal`: clearly promising behavior change
- `partial`: behavior changed, but not the target behavior
- `no_signal`: no visible gameplay change
- `crash`: load or gameplay crash
- `blocked`: could not get a clean test run

## 5. Restore Before Switching Tracks

```powershell
py -3 .\tools\deploy_condition_probe.py restore --notes "returning to baseline"
py -3 .\tools\deploy_condition_probe.py restore --dry-run
```

## 6. Escalation Rules

- If a **single probe** shows signal, move to the verified exact combos built around it.
- If the top **four single probes** all show `no_signal`, stop broad swapping and decode
  the `target=13001 / opcode=0x2902 / params=(9,0,15)` source-id cluster more deeply.
- Ignore `combo_cancel_dual.*` and `combo_mixed_exact.*` if they are still present in
  `mod_test/`. They are older non-verified artifacts.

## 7. Good Commands to Keep Handy

```powershell
py -3 .\tools\deploy_condition_probe.py status
py -3 .\tools\deploy_condition_probe.py apply probe_cancel_541
py -3 .\tools\deploy_condition_probe.py restore
Get-Content .\PROBE_TEST_LOG.csv
```

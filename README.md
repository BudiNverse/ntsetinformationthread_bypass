# `NtSetInformationThread_bypass`
This is a simple dll that helps to undo `ThreadHideFromDebugger`.
Must injected before `NtSetInformationThread` is called. This works by checking if `THREADINFOCLASS`
is `17` and if it is, then return from the function instead of calling `NtSetInformationThread`. If not then it just logs the inputs and calls `NtSetInformationThread` normally.
TBH, am still a noob at this so I have no other ideas on how to bypass this but this works I guess lmao.

## How to build
```
cargo build --release
```
Your dll file should be at `target/release/ntsetinformationthread_bypass.dll`
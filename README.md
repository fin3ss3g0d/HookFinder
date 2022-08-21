# HookFinder

A simple PoC to locate hooked functions within ntdll.dll to further EDR evasion research.

## About

This PoC uses the same checks that [TartarusGate](https://github.com/trickster0/TartarusGate) uses in order to find hooked system calls. Breaking it down further, the first and third bytes of a function are checked for the bytes matching a JMP instruction. If either are a match, this is a good indicator that the function is hooked.

## Demo

The below screenshot is a demo running the program against an endpoint with EDR.

![demo](demo/demo.png)

## Credits

Code heavily borrowed from [TartarusGate](https://github.com/trickster0/TartarusGate).

## Contributing

To further the research of EDR, email a similar output of the program to `fin3ss3g0d@pm.me` in `.txt` format with a subject including `HookFinder` and the vendor name. Hook statistics based on vendor will be added to this repository in the future logging hooks for various vendors based on contributions.

requires http://github.com/isage/rubberduck/ to piggyback on the net recv fix (should add that here later)
optionally install https://github.com/SKGleba/psp2spl/releases/tag/1.0 for peek/poke and (todo hw breakpoint enabling)
use:
- install vitasdk, rust nightly, just
- `just release`
- target/armv7-sony-vita-newlibeabihf/release/vita-gdb.skprx
- optionally install psp2spl for peek / poke and (when it actually works) hardware break & watch
- copy vita-gdb.skprx to ur0|ux0:/tai/
- add to kernel section in config
- `arm-vita-eabi-gdb -ex "target extended-remote <vitaip>:31337"` to connect to the stub
- use `mon ps` to list processese
- `attach <pid>` to attach
- `set remote exec-file <TITLEID>` and then `run` to run an app (this times out sometimes gdb seems to have unrealistic standards for how fast a process can launch)

todo:
- stepping may be broken which also breaks sw breakpoints maybe?
- neon registers dont read correctly
- vfp (floating point) exceptions arent handled yet
- enabling hardware breakpoints doesnt work yet

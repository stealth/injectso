luda (luajit like frida)
========================

<p align="center">
<a href="https://github.com/c-skills/welcome">
<img src="https://github.com/stealth/injectso/blob/master/contrib/luda.jpg"/>
</a>
</p>


```
$ git clone https://luajit.org/git/luajit.git
$ cd luajit
$ git checkout f9140a622a0c44
$ patch -p1 < luajit-luda-f9140a622a0c44.diff
$ make -j 8
...
$ LUAJIT_MAIN=1 ./luajit test-luda.lua

```

If you want to inject it as DSO, copy `open-luda.lua` to `/tmp/luda.lua`, make sure the
target process has permissions to open it, and inject `libluajit.so` into the target
process.
`test-luda.lua` will work as inject too, but will not print trapped info, as at the time
of hook invocation it is still ptraced.

Note that injectso by intention is not fully working across all distros. Full support is not for free :)




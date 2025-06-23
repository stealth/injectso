injectso
========

Injecting DSO's since 2001. Inside `attic` folder you will find code that was needed for my
*Adventures in heap-cloning* paper from 2009, which is not longer supported.

You most likely want to check the [contrib](https://github.com/stealth/injectso/tree/master/contrib) folder on how to use `LuaJIT` like frida.
Changing of hooked function parameters is not yet supported and so is no other arch than `x86_64`.
I made the patch as clear and isolated as possible, so anything could easily added though.

Note: This tool exists for 20+ years and it is almos impossible to keep it stable across all
distros since then, given evolving *glibc* and *ld.so* features. On somewhat older systems,
the entry-point is `__libc_dlopen_mode` but that seems to have disappeared on newer glibcs.
Adding `-S dlopen` helps in most cases then.


*Produly sponsored by:*
<p align="center">
<a href="https://github.com/c-skills/welcome">
<img src="https://github.com/c-skills/welcome/blob/master/logo-black.jpg"/>
</a>
</p>


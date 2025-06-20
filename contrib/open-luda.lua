-- This script is run inside the injected host process
-- Prefix of "H:" printouts denote printf() called from the host binary, "L:" prefix shows printouts from this script,
-- "T:" prefix denotes printout from this script, inside a trapped function

local ffi = require("ffi")
local luda = require("luda")


-- hooking functions must be placed before the hook is injected
-- so that luaL_loadfile() has processed it before luda.hook() internally tries
-- to find the symbol of this hook

function my_open(regs)
	print(string.format("T: open('%s')", luda.peek_string(string.format("%x", regs['reg_rdi']))))
end

ffi.cdef([[
	extern uint64_t dlsym(void *, const char *);	// actually a `void *` return but u64 makes conversion easier later on
]])

charp = ffi.typeof('char *')

u64 = ffi.C.dlsym(NULL, ffi.cast(charp, "open"))
addr = string.format("%x", u64)

print("L: Hooking open @", addr)
luda.hook(addr, "my_open")


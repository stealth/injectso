-- This script is run inside the injected host process
-- Prefix of "H:" printouts denote printf() called from the host binary, "L:" prefix shows printouts from this script,
-- "T:" prefix denotes printout from this script, inside a trapped function

local ffi = require("ffi")
local luda = require("luda")


-- hooking functions must be placed before the hook is injected
-- so that luaL_loadfile() has processed it before luda.hook() internally tries
-- to find the symbol of this hook

function my_hook(regs)
	print("T: inside my_hook(), running Lua code from injected ELF host")
	print("T: trapped RIP was: ", regs['reg_rip'], " should match @luda_testfunc_ptr")

	-- args passing as per ABI
	print(string.format("T: Args i=0x%x str='%s'", regs['reg_rdi'], luda.peek_string(string.format("%x", regs['reg_rsi']))))
end

ffi.cdef([[
	extern uint32_t luda_testval;
	extern uint64_t luda_testval_ptr;
	extern int luda_testfunc(int i, char *);
	extern uint64_t luda_testfunc_ptr;

	extern uint64_t dlsym(void *, const char *);	// actually a `void *` return but u64 makes conversion easier later on
]])

print(string.format("L: luda_testval = %x luda_testval_ptr = %x luda_testfunc_ptr = %x", ffi.C.luda_testval, ffi.C.luda_testval_ptr, ffi.C.luda_testfunc_ptr))

-- Due to luajit limitation of not cleanly passing 64bit ints, addresses must be passed as strings
addr = string.format("%x", ffi.C.luda_testval_ptr)

print(string.format("L: peek32 @luda_testval_ptr => %x", luda.peek32(addr)))
print(string.format("L: peek16 @luda_testval_ptr => %x", luda.peek16(addr)))
print(string.format("L: peek8  @luda_testval_ptr => %x", luda.peek8(addr)))


luda.poke8(addr, 0x51)
print(string.format("L: After poke8 @luda_testval_ptr => %x", luda.peek32(addr)))

charp = ffi.typeof('char *')
voidp = ffi.typeof('void *')

ffi.C.luda_testfunc(0x7350, ffi.cast(charp, "luajit rulez"))

u64 = ffi.C.dlsym(NULL, ffi.cast(charp, "luda_testfunc"))
addr = string.format("%x", u64)

print("L: Hooking ffi.C.luda_testfunc @", addr)
luda.hook(addr, "my_hook")

for i=1,3 do
	print "L: call:"
	ffi.C.luda_testfunc(0x7350, ffi.cast(charp, "luajit rulez"))
end

luda.unhook(addr)
print "L: call, after unhook:"
ffi.C.luda_testfunc(0x7350, ffi.cast(charp, "luajit rulez"))


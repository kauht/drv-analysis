-- drvinspect: a Windows driver (.sys) inspector for LOLDrivers-style analysis
set_project("drvinspect")
set_version("0.1.0")

set_languages("c++20")
set_warnings("all")
add_rules("mode.debug", "mode.release")

-- Zydis: fast, permissively-licensed x86/x64 disassembler. Used to analyse a
-- driver's dispatch routine (find the IOCTL handler and trace to primitives).
add_requires("zydis")

target("drvinspect")
    set_kind("binary")
    add_files("src/*.cpp")  -- hashing, pe, sigdb, heuristics, disasm, main
    add_packages("zydis")

    -- Windows-only for now: we rely on BCrypt + the PE structures in <windows.h>
    if is_plat("windows") then
        add_defines("WIN32_LEAN_AND_MEAN", "NOMINMAX", "_CRT_SECURE_NO_WARNINGS")
        add_syslinks("bcrypt")
    end
target_end()

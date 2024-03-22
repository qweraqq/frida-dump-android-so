#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import sys
import argparse
import frida

ss = """
const sleep = new NativeFunction(Module.getExportByName('libc.so', 'sleep'), 'uint', ['uint']);

function dumpSo(so_name){{
    const libso = Process.findModuleByName(so_name);
    if (libso == null) {{
        console.log(`module ${{so_name}} not found`);
        return -1;
    }}
    Memory.protect(ptr(libso.base), libso.size, 'rwx');
    const libso_buffer = ptr(libso.base).readByteArray(libso.size);
    send(so_name, libso_buffer);
}}

function hook_JNI_OnLoad(so_name){{
    const module = Process.findModuleByName(so_name);
    console.log(`${{so_name}} module base: ${{module["base"]}}`)
    const JNI_OnLoad = Module.getExportByName(so_name, 'JNI_OnLoad');
    console.log(`${{so_name}} JNI_OnLoad addr: ${{JNI_OnLoad}}`)
    Interceptor.attach(JNI_OnLoad, {{
        onEnter(args){{
            console.log(`JNI_OnLoad onEnter: ${{so_name}}`);
            // 也可在JNI_OnLoad进入时dump so
            console.log('start: dump so on JNI_OnLoad');
            dumpSo(so_name);
            console.log('finish: dump so on JNI_OnLoad');
            sleep(10);
        }},
        onLeave: function(retval){{
            console.log(`JNI_OnLoad onLeave: ${{so_name}}`);
            sleep(10);
        }}
    }})
}}

function hook_constructor() {{
    let linker = null;
    if (Process.pointerSize == 4) {{
        linker = Process.findModuleByName("linker");
    }} else {{
        linker = Process.findModuleByName("linker64");
    }}
 
    let addr_call_function = null;
    let addr_g_ld_debug_verbosity = null;
    let addr_async_safe_format_log = null;
    if (linker) {{
        //console.log("found linker");
        let symbols = linker.enumerateSymbols();
        for (let i = 0; i < symbols.length; i++) {{
            let name = symbols[i].name;
            if (name.indexOf("call_function") >= 0) {{
                addr_call_function = symbols[i].address;
               // console.log("call_function",JSON.stringify(symbols[i]));
            }}
            else if(name.indexOf("g_ld_debug_verbosity") >=0) {{
                addr_g_ld_debug_verbosity = symbols[i].address;
                ptr(addr_g_ld_debug_verbosity).writeInt(2);
            }} else if(name.indexOf("async_safe_format_log") >=0 && name.indexOf('va_list') < 0) {{
                addr_async_safe_format_log = symbols[i].address;
            }}
        }}
    }}
    if(addr_async_safe_format_log){{
        Interceptor.attach(addr_async_safe_format_log,{{
            onEnter: function(args){{
                this.log_level  = args[0];
                this.tag = ptr(args[1]).readCString()
                this.fmt = ptr(args[2]).readCString() // [Calling / Done calling ...]
                if(this.fmt.indexOf("Calling c-tor") >= 0 || this.fmt.indexOf("Done calling c-tor") >=0) {{
                    this.function_type = ptr(args[3]).readCString(), // func_type
                    this.so_path = ptr(args[5]).readCString();
                    var strs = new Array(); //定义一数组
                    strs = this.so_path.split("/"); //字符分割
                    this.so_name = strs.pop();
                    this.func_offset  = ptr(args[4]).sub(Module.findBaseAddress(this.so_name))
                    console.log("fmt:", this.fmt, "; func_type:", this.function_type, '; so_name:',this.so_name, '; func_offset:',this.func_offset);
                    // hook代码在这加
                    if(this.so_name.indexOf("{so_name}") >= 0){{
                        console.log('start: dump so call_function on c-tor');
                        dumpSo("{so_name}");
                        console.log('finish: dump so call_function on c-tor');
                        sleep(1);
                    }}
                }}

                if(this.fmt.indexOf("Calling d-tor") >= 0 || this.fmt.indexOf("Done calling d-tor") >= 0){{
                    this.function_type = ptr(args[3]).readCString(), // func_type
                    this.so_path = ptr(args[5]).readCString();
                    var strs = new Array(); //定义一数组
                    strs = this.so_path.split("/"); //字符分割
                    this.so_name = strs.pop();
                    this.func_offset  = ptr(args[4]).sub(Module.findBaseAddress(this.so_name))
                    console.log("fmt:", this.fmt, "; func_type:", this.function_type, '; so_name:',this.so_name, '; func_offset:',this.func_offset);
                    // hook代码在这加
                    if(this.so_name.indexOf("{so_name}") >= 0){{
                        console.log('start: dump so on call_function d-tor');
                        dumpSo("{so_name}");
                        console.log('finish: dump so on call_function d-tor');
                        sleep(1);
                    }}
                }}


            }},
            onLeave: function(retval){{
            }}
        }})
    }}
}}


function hookDlopen() {{
    console.log("start hook dl open");
    const android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(android_dlopen_ext, {{
      onEnter: function(args){{
        this.name = args[0].readCString();
        console.log(`dlopen onEnter ${{this.name}}`);
      }}, 
      onLeave: function(retval){{
            console.log(`dlopen onLeave: ${{this.name}}`);
            if (this.name != null && this.name.indexOf('{so_name}') >= 0) {{
                // hook_JNI_OnLoad(this.name);
                const module = Process.findModuleByName('{so_name}');
                send(module["base"]);
                console.log(`{so_name} module base: ${{module["base"]}}`)
                const JNI_OnLoad = Module.getExportByName('{so_name}', 'JNI_OnLoad');
                console.log(`{so_name} JNI_OnLoad addr: ${{JNI_OnLoad}}`)
                console.log('start: dump so on dl_open leave');
                dumpSo("{so_name}");
                console.log('finish: dump so on dl_open leave');
                sleep(10);
        }}
      }}
    }})
}}

setImmediate(hookDlopen);
setImmediate(hook_constructor);
"""



if __name__ == "__main__":
    module_base = None
    parser = argparse.ArgumentParser()
    parser.add_argument("app_name", type=str, help="specify app name here, e.g. com.abc.abc")
    parser.add_argument("so_name", type=str, help="specify so file here, e.g. libtmp.so")
    args = parser.parse_args()
    app_name = args.app_name
    so_name = args.so_name

    def on_message(message, data):
        global module_base
        if not "payload" in message:
            return
        
        if message["payload"].startswith("0x"):
            module_base = message["payload"]
            return
        
        if message["payload"].endswith(".so"):
            filename = f"{time.time()}-{so_name}"
            print(f"Saving {filename}")
            with open(filename, "wb") as f:
                f.write(data)
            # print(f"received module base = {module_base}")
            return
        # TODO: auto so fix



    device = frida.get_usb_device()
    pid = device.spawn([app_name])
    session = device.attach(pid)
    script = session.create_script(ss.format(so_name=so_name))
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()


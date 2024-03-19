import sys
import argparse
import frida

ss = """
let sleep = new NativeFunction(Module.getExportByName('libc.so', 'sleep'), 'uint', ['uint']);

function dumpSo(so_name){{
    let libso = Process.findModuleByName(so_name);
    if (libso == null) {{
        console.log(`module ${{so_name}} not found`);
        return -1;
    }}
    Memory.protect(ptr(libso.base), libso.size, 'rwx');
    let libso_buffer = ptr(libso.base).readByteArray(libso.size);
    send(so_name, libso_buffer);
}}

function hook_JNI_OnLoad(so_name){{
    let module = Process.findModuleByName(so_name);
    console.log(`${{so_name}} module base: ${{module["base"]}}`)
    let JNI_OnLoad = Module.getExportByName(so_name, 'JNI_OnLoad');
    Interceptor.attach(JNI_OnLoad, {{
        onEnter(args){{
            console.log(`JNI_OnLoad onEnter: ${{so_name}}`);
            // 在JNI_OnLoad进入时dump so
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

function hookDlopen() {{
    console.log("start hook dl open");
    // let android_dlopen_ext = Module.findExportByName(null, "dlopen");
    let linker64_base_addr = Module.getBaseAddress('linker64');
    let offset = {dlopen_offset}; // __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv
    let android_dlopen_ext = linker64_base_addr.add(offset);
    Interceptor.attach(android_dlopen_ext, {{
      onEnter: function(args){{
        this.name = args[0].readCString();
        console.log(`dlopen onEnter ${{this.name}}`);
      }}, 
      onLeave: function(retval){{
            console.log(`dlopen onLeave: ${{this.name}}`);
            if (this.name != null && this.name.indexOf('{so_name}') >= 0) {{
                hook_JNI_OnLoad(this.name);
                // dumpSo("libDexHelper.so");
                sleep(3);
        }}
      }}
    }})
}}

setImmediate(hookDlopen);
"""



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dlopen_offset", type=str, help="adb pull /data/local/tmp/linker64 & readelf -sW linker64 | grep do_dlopen, e.g. 0x3c2c4")
    parser.add_argument("app_name", type=str, help="specify app name here, e.g. com.abc.abc")
    parser.add_argument("so_name", type=str, help="specify so file here, e.g. libtmp.so")
    args = parser.parse_args()
    dlopen_offset = args.dlopen_offset
    app_name = args.app_name
    so_name = args.so_name

    def on_message(message, data):
        with open(so_name, "wb") as f:
            f.write(data)


    try:
        device = frida.get_usb_device()
        pid = device.spawn([app_name])
        session = device.attach(pid)
        script = session.create_script(ss.format(dlopen_offset=dlopen_offset, so_name=so_name))
        script.on('message', on_message)
        script.load()
        device.resume(pid)
        sys.stdin.read()
    except Exception as e:
        print(e)

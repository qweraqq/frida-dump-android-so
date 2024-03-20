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
            // console.log('start: dump so on JNI_OnLoad');
            // dumpSo(so_name);
            // console.log('finish: dump so on JNI_OnLoad');
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
        if message["payload"].startswith("0x"):
            module_base = message["payload"]
            return    
        with open(so_name, "wb") as f:
            f.write(data)
        print(f"received module base = {module_base}")
        # TODO: auto so fix


    try:
        device = frida.get_usb_device()
        pid = device.spawn([app_name])
        session = device.attach(pid)
        script = session.create_script(ss.format(so_name=so_name))
        script.on('message', on_message)
        script.load()
        device.resume(pid)
        sys.stdin.read()
    except Exception as e:
        print(e)

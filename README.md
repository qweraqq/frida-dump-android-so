# frida-dump-android-so
## refs
- [hook dlopen看一下so的加载流程](https://bbs.kanxue.com/thread-277034.htm)
- [frida hook init_array](https://bbs.kanxue.com/thread-267430.htm)

## How to use

```bash
python frida-dump-so.py com.abc libDexHelper.so
```

fix so
- [https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)

注意: frida inline hook 会在函数开头增加 trampoline

```bash
./SoFixer-Linux-64 -s libDexHelper.so -o libDexHelper-fixed.so -m 0x78017d8000 -d
# sofixer  -s soruce.so -o fix.so -m 0x78017d8000 -d 
# -s 待修復的so路徑
# -o 修復後的so路徑
# -m 內存dump的基地址(16位) 0xABC
# -d 輸出debug信息

```
# frida-dump-android-so

## How to use

### 1. get dlopen offset
```bash
cp /apex/com.android.runtime/bin/linker64 /data/local/tmp/
chmod 777 /data/local/tmp/linker64
```

```bash
adb pull /data/local/tmp/linker64
readelf -sW linker64 | grep do_dlopen

# 216: 000000000003c2c4  2856 FUNC    LOCAL  HIDDEN    10 __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv
```

### 2. run
```bash
python frida-dump-so.py 0x3c2c4 com.abc libDexHelper.so
```

#### 3. fix so
- [https://github.com/F8LEFT/SoFixer](https://github.com/F8LEFT/SoFixer)

```bash
./SoFixer-Linux-64 -s libDexHelper.so -o libDexHelper-fixed.so -m 0x78017d8000 -d
# sofixer  -s soruce.so -o fix.so -m 0x78017d8000 -d 
# -s 待修復的so路徑
# -o 修復後的so路徑
# -m 內存dump的基地址(16位) 0xABC
# -d 輸出debug信息

```
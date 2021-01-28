# Created by malwareunicorn
# To compile a macho: gcc mymacho.c -o mymacho.macho -fno-stack-protector -fno-builtin
# To compile asm: nasm -f macho64 cipher.asm -o cipher.o && ld -o cipher.macho -macosx_version_min 10.7 -e start cipher.o && ./cipher.macho

# ----------------------------------
# CONFIGURATION OPTIONS
# ----------------------------------
DIST_DIR             = "dist"
SRC_DIR              = "src"

def generate_downloader_macho(filename):
    # compile mach-o
    cmd = "gcc %s/gen_%s.c -o %s/%s.macho -fno-stack-protector -fno-builtin" % (
            SRC_DIR,filename,DIST_DIR,filename)
    return subprocess.call(cmd, shell=True)

def extract_shellcode(filename):
    # find offset of _text and _data and extract to bin file
    b = os.path.splitext(filename)[0]
    macho_filename = os.path.join(SRC_DIR,"%s.macho" % (b))
    fileoffset = 0
    shellcodesize = 0
    m = MachO(macho_filename)
    for (load_cmd, cmd, data) in m.headers[0].commands:
        if data:
            if hasattr(data[0], "sectname"):
                sectionName = getattr(data[0], 'sectname', '').rstrip('\0')
                if "text" in sectionName:
                    fileoffset=data[0].offset
                    shellcodesize+=data[0].size
                if "data" in sectionName:
                    shellcodesize+=data[0].size
    shellcode_filename = os.path.join(SRC_DIR,"%s_shellcode.bin" % (b))
    with open(macho_filename, 'rb') as f:
        f.seek(fileoffset, 1)
        shellcode_bytes = f.read(shellcodesize)
        with open(shellcode_filename, 'wb') as sf:
            sf.write(shellcode_bytes)
            sf.close()
        f.close()
    return shellcode_bytes

def main():
    xor_shellcode = extract_shellcode("mymacho.macho")

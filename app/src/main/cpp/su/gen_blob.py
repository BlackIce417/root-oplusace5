import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, "rb") as f:
    b = f.read()

rows = []
for i in range(0, len(b), 16):
    rows.append(",".join("0x%02x" % x for x in b[i:i + 16]) + ",")

with open(dst, "w", newline="\n") as f:
    f.write("// Generated from su/su_aarch64_pie by su/gen_blob.py -- do not edit.\n")
    f.write("// Standalone arm64 dynamic-PIE su: `su --daemon` serves, `su -c CMD` and\n")
    f.write("// bare `su` are clients. Written to /data/local/tmp/su once we are root.\n")
    f.write("#ifndef ROOT_OPLUS_ACE5_SU_BLOB_H\n#define ROOT_OPLUS_ACE5_SU_BLOB_H\n\n")
    f.write("static const unsigned char SU_BLOB[] = {\n")
    for r in rows:
        f.write(r + "\n")
    f.write("};\n")
    f.write("static const unsigned int SU_BLOB_LEN = %du;\n" % len(b))
    f.write("\n#endif //ROOT_OPLUS_ACE5_SU_BLOB_H\n")

print("su_blob.h: %d bytes -> %d rows" % (len(b), len(rows)))

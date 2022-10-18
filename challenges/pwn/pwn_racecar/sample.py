data1="\x7b\x42\x54\x48"[::-1]
data2="\x5f\x79\x68\x77"[::-1]
data3="\x5f\x64\x31\x64"[::-1]
data4="\x34\x73\x5f\x31"[::-1]
data5="\x74\x5f\x33\x76"[::-1]
d6="\x66\x5f\x33\x68"[::-1]
d7="\x5f\x67\x34\x6c"[::-1]
d8="\x74\x5f\x6e\x30"[::-1]
d9="\x35\x5f\x33\x68"[::-1]
d10="\x6b\x63\x34\x74"[::-1]
d11="\x7d\x21\x3f"[::-1]


data = ""
print(data+data1+data2+data3+data4+data5+d6+d7+d8+d9+d10+d11)


flag = "0x7b4254480x5f7968770x5f6431640x34735f310x745f33760x665f33680x5f67346c0x745f6e300x355f33680x6b6334740x7d213f"
decoded_flag = []
print(flag.split("0x")[1:])

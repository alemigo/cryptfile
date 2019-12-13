
import cryptfile
import os

os.remove('/home/alex/cftest.dat')
f = cryptfile.open('/home/alex/cftest.dat', 'wb+', aes_key = b'a'*32, block_num=2)

for r in range(10):
    f.write(b'testingthishellolongerstringherefortest\n')

f.seek(0)
for r in range(5):
    print(f.readline())

f.close()


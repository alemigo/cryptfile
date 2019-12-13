import cryptfile
import splitfile
import tarfile
import zipfile
import lzma
import os
os.remove('/home/alex/cftest.dat')
sf = splitfile.open('/home/alex/cftest.dat', mode = 'wb+', volume_size=1000000)
f = cryptfile.open(sf, 'wb+', aes_key = b'a'*32)
#z = tarfile.TarFile(mode = 'w', fileobj=f)
#z = zipfile.ZipFile(f, mode = 'w')
z = lzma.open(f, mode = 'wb')

for fn in os.scandir('/home/alex/music/hanna'):
    if fn.is_file():
        print(fn.path)
        with open(fn.path, 'rb') as fi:
            z.write(fi.read())
        #z.write(fn.path, fn.name)
        #z.add(fn.path, fn.name)

z.close()
f.close()
sf.close()

#sf = splitfile.open('/home/alex/cftest.dat', 'rb')
#f = cryptfile.open(sf, 'rb', aes_key = b'a'*32)
##z = tarfile.TarFile(mode = 'r', fileobj=f)
#z = zipfile.ZipFile(f, mode = 'r')
#print(z.namelist())
#print(z.testzip())

##print(z.list())
##z.extractall('/home/alex/temp')
#z.close()
#f.close()
#sf.close()


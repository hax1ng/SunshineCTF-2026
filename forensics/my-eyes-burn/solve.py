import re
t=open('boardwriter.klc','rb').read().decode('utf-16')
dk={}
for m in re.finditer(r'DEADKEY\t(\w+)\r?\n(\w+)\t(\w+@?)',t):
    dk[m.group(1)]=(m.group(2),m.group(3))
state='0060'  # OEM_3 (backtick) is the only dead key on the layout
out=''
while state in dk:
    k,r=dk[state]; out+=chr(int(k,16)); print(f'dead {state} + {chr(int(k,16))!r} -> {r}')
    if not r.endswith('@'): print('final char:',chr(int(r,16))); break
    state=r[:-1]
print(out)

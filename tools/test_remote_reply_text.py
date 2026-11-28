"""Actual remote reply splitting: bounded UTF-8 and line alignment, host only."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
text=("Gateway café\nNAS reachable\nPrinter éè à中文🙂\n"*150).encode()
values=','.join(str(x) for x in text)
program=r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "remote_commands.h"
static const unsigned char text[]={''' + values + r''',0};
int main(void) {
 size_t length=sizeof(text)-1;
 assert(!remote_reply_chunk_size(NULL,length,0,20));
 assert(!remote_reply_chunk_size((char*)text,length,length,20));
 assert(!remote_reply_chunk_size((char*)text,length,0,0));
 assert(remote_reply_chunk_size("first\nlast",10,0,8)==6);
 const size_t limits[]={4,7,31,900,3500};
 for(unsigned i=0;i<sizeof(limits)/sizeof(*limits);i++){
  size_t at=0;
  printf("LIMIT %zu\n",limits[i]);
  while(at<length){
   size_t take=remote_reply_chunk_size((char*)text,length,at,limits[i]);
   assert(take && take<=limits[i] && take<=length-at);
   for(size_t j=0;j<take;j++)printf("%02x",text[at+j]);
   putchar('\n');at+=take;
  }
 }
}
'''
with tempfile.TemporaryDirectory(prefix='remote-reply-') as folder:
 p=Path(folder);(p/'test.c').write_text(program)
 exe=p/('test.exe' if os.name=='nt' else 'test')
 subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror','-I',str(ROOT/'main'),str(p/'test.c'),'-o',str(exe)],check=True)
 output=subprocess.check_output([str(exe)],text=True,timeout=10)
 rebuilt=b'';limit=None
 for line in output.splitlines():
  if line.startswith('LIMIT '):
   if limit is not None:assert rebuilt==text
   rebuilt=b'';limit=int(line[6:])
  else:
   chunk=bytes.fromhex(line);assert 0<len(chunk)<=limit;chunk.decode('utf-8');rebuilt+=chunk
 assert rebuilt==text
 print('PASS: actual shared reply splitter: complete UTF-8, newline preference, exact reconstruction and both channel limits')

"""Exercise the real SD snapshot and HTTP download paths with storage faults."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
storage = (ROOT / 'components/sdlog/sdlog.c').read_text(encoding='utf-8')
web = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8')


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}\n', start) + 3]


fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
typedef int esp_err_t;
typedef esp_err_t (*sdlog_chunk_cb)(void *,const char *,size_t);
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_ARG -2
#define ESP_ERR_INVALID_STATE -3
#define ESP_ERR_TIMEOUT -4
#define ESP_ERR_NOT_FOUND -5
#define HTTPD_404_NOT_FOUND 404
#define HTTPD_400_BAD_REQUEST 400
#define SDLOG_NAME_MAX 16
#define SDLOG_DIR "/fixture"
#define pdMS_TO_TICKS(x) (x)
#define pdTRUE 1
#define portMAX_DELAY 9999
static atomic_bool s_present=true;
static char s_download_name[SDLOG_NAME_MAX];
static int lock_storage,*s_file_mutex=&lock_storage;
static bool locked,stat_error,read_error,close_error,send_error,append_on_send,authorized=true;
static unsigned refuse_read,reads,closes;
static int open_error, seek_error;
static bool tell_error, tail_mode;
static const char *tail_data;
static size_t tail_position;
static size_t snapshot,available;
static int xSemaphoreTake(int *mutex,int wait){
    assert(mutex==s_file_mutex&&!locked&&(wait==3000||wait==9999));locked=true;return pdTRUE;
}
static void xSemaphoreGive(int *mutex){assert(mutex==s_file_mutex&&locked);locked=false;}
static FILE *mock_open(const char *path,const char *mode){
    assert(locked&&!strcmp(path,"/fixture/TEST.LOG")&&!strcmp(mode,"rb"));
    if(open_error){errno=open_error;return NULL;}return (FILE *)&lock_storage;
}
static int mock_fd(FILE *file){assert(file==(FILE *)&lock_storage&&locked);return 2;}
static int mock_stat(int fd,struct stat *st){
    assert(fd==2&&locked); if(stat_error)return -1;st->st_size=(long)snapshot;return 0;
}
static size_t mock_read(void *buf,size_t n,size_t count,FILE *file){
    assert(locked&&n==1&&file==(FILE *)&lock_storage&&(tail_mode||!strcmp(s_download_name,"TEST.LOG")));
    reads++; if(reads==refuse_read)return 0;
    if (tail_mode) {
        assert(tail_position + count <= snapshot);
        memcpy(buf, tail_data + tail_position, count); tail_position += count; return count;
    }
    assert(count<=available);available-=count;memset(buf,'L',count);return count;
}
static int mock_error(FILE *file){assert(locked&&file==(FILE *)&lock_storage);return read_error;}
static int mock_close(FILE *file){assert(locked&&file==(FILE *)&lock_storage);closes++;return close_error?-1:0;}
static int mock_seek(FILE *file,long offset,int origin){
    assert(locked&&file==(FILE *)&lock_storage&&tail_mode&&offset>=0);
    if(seek_error==origin)return -1;
    tail_position=origin==SEEK_END?snapshot:(size_t)offset;return 0;
}
static long mock_tell(FILE *file){
    assert(locked&&file==(FILE *)&lock_storage&&tail_mode);
    return tell_error?-1:(long)tail_position;
}
#undef fopen
#undef fileno
#undef fstat
#undef fread
#undef ferror
#undef fclose
#define fopen mock_open
#define fseek mock_seek
#define ftell mock_tell
#define fileno mock_fd
#define fstat mock_stat
#define fread mock_read
#define ferror mock_error
#define fclose mock_close
typedef struct {int status,headers,terminators;size_t sent;const char *name;} httpd_req_t;
static int require_auth(httpd_req_t *req){if(authorized)return ESP_OK;req->status=401;return ESP_FAIL;}
static int sdlog_query_str(httpd_req_t *req,const char *key,char *buf,size_t cap){
    assert(!strcmp(key,"file"));if(!req->name)return ESP_FAIL;snprintf(buf,cap,"%s",req->name);return ESP_OK;
}
static int httpd_resp_send_err(httpd_req_t *req,int status,const char *message){
    assert(!locked&&message&&!req->sent&&!req->headers);req->status=status;return ESP_OK;
}
static int httpd_resp_send_500(httpd_req_t *req){return httpd_resp_send_err(req,500,"failed");}
static int web_transfer_start(httpd_req_t *req,int (*serve)(httpd_req_t *,const void *),
                              const void *argument,size_t argument_size){
    assert(authorized&&argument_size==strlen(argument)+1);
    return serve(req,argument);
}
static int httpd_resp_set_type(httpd_req_t *req,const char *type){
    assert(!locked&&!strcmp(type,"text/plain; charset=utf-8"));req->headers++;return ESP_OK;
}
static int httpd_resp_set_hdr(httpd_req_t *req,const char *name,const char *value){
    assert(!locked&&!strcmp(name,"Content-Disposition")&&!strcmp(value,"attachment; filename=\"TEST.LOG\""));
    req->headers++;return ESP_OK;
}
'''

storage_code = ''.join(function(storage, sig) for sig in (
    'static void build_path(', 'static bool name_is_safe(', 'esp_err_t sdlog_read_file(', 'esp_err_t sdlog_tail_file('))
web_code = web[web.index('/* Forward each file chunk'):web.index('/* GET /sdlog/tail')]
transport = r'''
static int httpd_resp_send_chunk(httpd_req_t *req,const char *buf,size_t len){
    assert(!locked&&req->headers==2);
    if(!buf){assert(!len&&!s_download_name[0]);req->terminators++;return ESP_OK;}
    assert(s_download_name[0]&&len>0&&buf[0]=='L'&&buf[len-1]=='L');
    if(send_error)return ESP_FAIL;
    if(append_on_send){
        assert(xSemaphoreTake(s_file_mutex,3000)==pdTRUE);
        available+=500;append_on_send=false;xSemaphoreGive(s_file_mutex);
    }
    req->sent+=len;return ESP_OK;
}
'''

tests = r'''
static void download(int result,int status,size_t sent,int ended){
    httpd_req_t req={.status=200,.name="TEST.LOG"};
    reads=closes=0;available=snapshot;
    assert(sdlog_download_handler(&req)==result);
    assert(!locked&&!s_download_name[0]&&req.status==status&&req.sent==sent&&req.terminators==ended);
}
static void tail(const char *input,int count,size_t cap,int expected,const char *out){
    char buf[64];
    assert(cap<=sizeof buf);
    tail_mode=true;tail_data=input;snapshot=strlen(input);reads=closes=0;
    size_t result=999;
    assert(sdlog_tail_file("TEST.LOG",count,buf,cap,&result)==expected&&!locked);
    if(out)assert(result==strlen(out)&&!strcmp(buf,out)&&closes==1);
    else assert(result==999);
}
int main(void){
    snapshot=2300;append_on_send=true;download(ESP_OK,200,2300,1);
    assert(!append_on_send&&available==500&&reads==3&&closes==1);
    refuse_read=1;download(ESP_FAIL,500,0,0);assert(closes==1);
    refuse_read=2;download(ESP_FAIL,200,1024,0);assert(closes==1);
    refuse_read=0;read_error=true;download(ESP_FAIL,500,0,0);read_error=false;
    stat_error=true;download(ESP_FAIL,500,0,0);assert(closes==1);stat_error=false;
    close_error=true;download(ESP_FAIL,200,2300,0);close_error=false;
    send_error=true;download(ESP_FAIL,200,0,0);assert(reads==1);send_error=false;
    open_error=ENOENT;download(ESP_FAIL,404,0,0);assert(!closes);
    open_error=EIO;download(ESP_FAIL,500,0,0);assert(!closes);open_error=0;
    snapshot=0;download(ESP_OK,200,0,1);assert(!reads&&closes==1);
    httpd_req_t invalid={.name="../PRIVATE"};
    assert(sdlog_download_handler(&invalid)==ESP_FAIL&&invalid.status==404&&!invalid.headers);
    authorized=false;download(ESP_FAIL,401,0,0);assert(!closes);
    seek_error=-1;
    tail("a\nb\nc\n",2,64,ESP_OK,"b\nc\n");
    tail("a\nb\nc",2,64,ESP_OK,"b\nc");
    tail("a\n\n",1,64,ESP_OK,"\n");
    tail("",1,64,ESP_OK,"");
    tail("longer\nshort\n",1,9,ESP_OK,"short\n");
    seek_error=SEEK_END;tail("line\n",1,64,ESP_FAIL,NULL);assert(!reads&&closes==1);
    seek_error=SEEK_SET;tail("line\n",1,64,ESP_FAIL,NULL);assert(!reads&&closes==1);
    seek_error=-1;tell_error=true;tail("line\n",1,64,ESP_FAIL,NULL);assert(!reads&&closes==1);
    tell_error=false;read_error=true;tail("line\n",1,64,ESP_FAIL,NULL);read_error=false;
    refuse_read=1;tail("line\n",1,64,ESP_FAIL,NULL);refuse_read=0;
    close_error=true;tail("line\n",1,64,ESP_FAIL,NULL);close_error=false;
    open_error=EIO;tail("line\n",1,64,ESP_FAIL,NULL);
    open_error=ENOENT;tail("line\n",1,64,ESP_ERR_NOT_FOUND,NULL);
    puts("PASS: SD tail reports I/O faults and honors exact line counts");
    puts("PASS: SD snapshot, writer access during sends, incomplete reads and precise HTTP termination");
}
'''

with tempfile.TemporaryDirectory(prefix='sdlog-download-') as directory:
    src = Path(directory) / 'test.c'
    exe = src.with_suffix('.exe' if os.name == 'nt' else '.out')
    src.write_text(fixture + storage_code + transport + web_code + tests, encoding='utf-8')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror']
    if os.environ.get('SDLOG_DOWNLOAD_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

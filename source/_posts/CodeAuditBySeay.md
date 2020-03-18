---
title: CodeAuditBySeay
date: 2019-01-16 16:56:59
tags:
	[-php,-ReadingNote,-basic]
password: 666bbb
---





- 代码审计通用思路：关键字回溯、可控变量、敏感功能点。
- 需要关注的点：了解框架、关注配置文件、关注过滤文件（函数）、跟读首页文件。
- 需要关注的功能：文件上传、文件管理、登录、注册、转账、找回密码、修改密码。



## sql注入

> 普通注入、盲注、报错注入、宽字节、二次注入等

- 需要关注的函数：`select` 、`insert` 、`update` 、`delete` 、`mysql_connect` 、`mysql_query` 、`mysql_fetch_row` 等。

- 宽字节注入（%df）`id=-1%df'`

  > mysql_set_charset('gbk')、character_set_client=gbk、SET NAMES 'gbk'
  >
  > 修改：character_set_client=binary

- 二次urldecode注入（略）



### MySQL报错注入

sql server用 convert() 和 cast()

MySQL常见的有 floor 、 updatexml、 extractvalue。

floor():

```sql
id=1 and (select 1 from (select count(*),concat(user(),floor(rand(0)*2))x from information_schema.tables group by x)a)
```

updatexml():

```sql
id=1 and (updatexml(1,concat(0x5e24,select user()),0x5e24,1))
```

extractvalue():

```sql
id=1 and (extractvalue(1, concat(0x5c, (select user()))))
```

除了以上三种，还有GeometryCollection(), polygon(), multipoint(), multilinestring(), multipolygon(), linestring(), exp() 等



### pod防注入

```php
$dbh = new PDO("mysql:host=localhost; dbname=test", "username","password");
$dbh->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);//禁用PHP本地模拟prepare
$dbh->exec("set names 'utf8'");
$sql="select * from test where name = ? and password = ?";
$stmt = $dbh->prepare($sql);
$exeres = $stmt->execute(array($name, $pass));  
if ($exeres) {  
 while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {  
     print_r($row);  
 }  
}  
$dbh = null;  

```

当调用`prepare()`时，查询语句已经发送给了数据库，此时只有占位符 `? `发送过去，没有用户提交的数据，调用 `execute()` 时，用户提交的值才会传到数据库，分开传送，两者独立，避免了恶意sql语句拼接到原有语句中并被执行。

> 类似php的PDO的还有.net的SqlParameter，Java的prepareStatement



## XSS

- 经常出现的地方：文章发表（富文本）、评论回复、留言、资料设置等。

防御：特殊字符HTML实体转码、实体化、标签黑白名单 等。



## CSRF

- 经常出现的地方：后台、论坛、交易......

挖掘和验证时注意token和不带referer的请求。

防御：①token、referer、②敏感操作加入验证码

一个简单的token实现：

```php+HTML
<?php
session_start();

function set_token() {
	$_SESSION['token'] = md5(time()+rand(1,1000));
}

function check_token() {
	if(isset($_POST['token']) && $_POST['token'] === $_SESSION['token']) {
		return ture;
	}
	else {
		return false;
	}
}

if(isset($_SESSION['token']) $$ check_token()) {
	echo "success";
}
else {
	echo "failed";
}

set_token();
?>

<form method="_POST">
	<input type="hidden" name="token" value="<?=$_SESSION['token']?>">
	<input type="submit">
</form>
```



## 文件包含

- 关注点：`include()` 、 `include_once()` 、`require()`、 `require_once()` ， 回溯可控变量。

- `%00`  截断（php5.3前）

- `.` 、`/` 截断（php5.3前）

- `?` 伪截断，例如：

  ```php
  <?php
      include($_GET['a'].'.php');
  ```

  请求 `http://xxxxxx/2.txt?` ，2.txt的内容为 `<?php phpinfo();?>` ，可以代码执行phpinfo。



## 文件读取

- 关注点：`file_get_contents()` 、 `highlight_file()` 、`fopen()` 、`readfile()` 、`fread()`、`fgetss()`、`fgets()`、`parse_ini_file()`、`show_source()`、`file()`， php流、伪协议。

文件操作防御：权限、限制目录、禁止目录跳转符（`.`、`/`、`\`）



## 文件上传

- 关注点：`move_uploaded_file()` 、webserver解析洞、`%00`截断、文件头

防御：白名单、`in_array` 、三等于对比拓展名、文件随机重命名。



## 代码执行

- 关注点：`eval()` 、`assert()` 、`preg_replace()` 、`call_user_func()`、`call_user_funn_array()`、`array_map()` ，动态函数执行。

call_user_func()：调用函数并且第二个参数作为调用函数的参数。例：

​	call_user_func($_GET['a']; $_GET['b']);` 

​	请求`http://xxxxxxx/1.php?a=assert&b=phpinfo()` ，可以代码执行。

防御： 白名单、disable_function。



## 命令执行

cmd or bash

- 关注点： `system()`、`exec()`、`shell_exec()`、`passthru()`、`pcntl_exec()`、`popen()`、`proc_oprn()`，反引号（ `` ` ）。 

例：`system('whoami');`、`popen('whoami >> D://1.txt', 'r');`，反引号命令执行是调用了函数 `shell_exec()` ，例：

```php
echo `whoami`;
```

防御：白名单、disable_function，使用PHP中的 `escapeshellcmd()` 和 `escapeshellarg()` 



escapeshellcmd()：linux平台下，反斜线（\）会在以下字符之前插入： 

```
&#;`|*?~<>^()[]{}$\, \x0A 和 \xFF
```

Windows平台下，以上字符以及 % 和 ! 都会被空格代替。

escapeshellarg()： 将给字符串增加一个单引号并且能引用或者转码任何已经存在的单引号，确保参数是一个字符串。



## 变量覆盖

- 关注点：`extract()` 、`parse_str()` 、`import_request_variables()` (php5.4后取消该函数)、 双$ （`$$`） 变量覆盖。

extract()：从数组中将变量导入到当前符号表（将数组中的键值对注册成变量），例：

```php
$b = 3;
$a = array('b'=>'1');
extract($a);
print_r($b);
```

这里的 $b 由3变成1。

parse_str()：解析字符串并注册变量，例：

```php
$b = 1;
parse_str('b=2');
print_r($b);
```

这里 $b 由1变成2。



防御：使用原始变量、extract() 第二个参数设置为 EXTR_SKIP。



## 逻辑漏洞

支付、找回密码、程序安装......

- 等于与存在的判断
- in_array()
- in_numerc() （判断数字的16进制绕过、php7中该函数把16进制判断为字符串）
- 双等、三等（弱类型）
- 越权
- 会话认证（cookie、session、token）（注意cookie可逆）



## 二次漏洞

略，以二次注入为主



## 加密

对称加密：加密解密都只有一个密钥（DES、AES、IDEA、RC2、RC4）

非对称加密：加密为公钥，解密为私钥（RSA）

单向加密：（MD5、sha1）



## 一些技巧

- 不受GPC保护的变量，例如：`$_SERVER`、`$_FILE` （php5）

- 注意字符串（编码），例如：宽字节、截断 等。

- php流、伪协议

- php代码解析标签，例如

  脚本标签：

  ```php
  <script language="php">
      phpinfo();
  </script>
  ```

  短标签：`<?......?>` ，使用短标签需要在 php.ini 中设置 `short_open_tag=on` ，默认为on

  asp标签：`<%......%>`，使用asp标签需要在php.ini中设置 `asp_tags=on`，默认为off

- fuzz（暴破）

- 不严谨的正则，例如 没有使用 `^` 和 `$`  限定匹配开始位置；特殊字符未转义，比如文件上传过滤时：

  ```php
  preg_match('/.(jpg|gif|png|bmp)$/i', $filename); 
  ```

  英文句号 `.`  前没有 `\` 转义，会变成全匹配符，所以 `xxx.php%00jpg` 可绕过。

- php中，单引号代表纯字符串，双引号回解析中间的变量，例如：`echo '$a+$b';` 和 `echo "$a+$b";` 是用区别的。

- php可变变量：例如：

  ```php
  $a = 'test';
  $$a = '123';
  
  echo $test;
  ```

  这里会输出 123，所以 $$a 就等于 $test。

  还有一种代码执行，某个php文件内容如下：

  ```php
  <?php
      $a="${@phpinfo()}";
  ```

  

  请求这个页面可以代码执行，其中 `@` 必须存在，也可以用 空格、TAB、`/**/` 注释、回车、`+`、`-` 、`!` 、`~` 、`\` 等代替。




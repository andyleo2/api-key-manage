# RSA - API私钥 

## 环境准备

以windows为例，需要安装：

- php工具；
- openssl库；



## 配置php支持的库

### 配置库

 编辑php安装目录下的php.ini文件，如果没有此文件，拷贝`php.ini-development`文件为`php.ini`，并编辑文件（将注释去掉），包括：OpenSSL和Curl：

```ini
extension=openssl
extension=curl
; On windows:
extension_dir = "ext"
openssl.cafile=D:\ca\cafile
openssl.capath=D:\ca\capath
```

### 检查配置

检查配置openssl是否成功：

```bash
php -m | grep openssl
php -m | grep curl
```


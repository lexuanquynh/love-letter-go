## Desploy service
### Chỉnh file env về dạng:
```
configs, err := LoadConfig("/usr/local/src/")
```
Sau đó copy file này lên:
```
scp app.env root@ipadress:/usr/local/src 
```
### Create service:

vi /etc/systemd/system/love_letter.service

### To build for Linux system:

```
 GOOS=linux GOARCH=amd64 go build cmd/authorization/auth.go
 ```

 ### Copy auth file to server:

```
scp path/to/file/tomove user@host:path/to/file/topaste
scp auth root@<ipaddress>:go
```

 ### To run service:

 ```
systemctl start love_letter.service
systemctl enable love_letter.service
systemctl status love_letter.service
```

### Create a config in /etc/nginx/sites-available/love_letter file:

```
vi /etc/nginx/sites-available/love_letter
```

### Create a symbolic link of our config file to the sites-enabled folder:

```
ln -s /etc/nginx/sites-available/love_letter.conf /etc/nginx/sites-enabled/love_letter.conf
```

### Finally, reload nginx to apply config:

```
nginx -t && nginx -s reload
```

if server not run, try:

```
cd /etc/nginx/sites-enabled
unlink default
service nginx restart
```

## Cài đặt tường lửa
### Cài đặt ufw:

```
sudo apt install ufw
```

### Thiết lập mặc định:

```
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

### Cho phép SSH:

```
sudo ufw allow ssh
```

### Bật UFW:

```
sudo ufw enable
```

### Xem thông tin cài đặt:

```
sudo ufw status verbose
```

### Mở cổng 8081:

```
sudo ufw allow 8081
```
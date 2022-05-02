## Desploy service
### Chỉnh file env về dạng:
```
configs, err := LoadConfig("/usr/local/src/love_letter")
```
Sau đó copy file này lên:
```
scp app.env root@ipadress:/usr/local/src/love_letter
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
### Create a service:
```
sudo vi /etc/systemd/system/love_letter.service
```
 ### To run service:

 ```
sudo systemctl start love_letter.service
sudo systemctl enable love_letter.service
sudo systemctl status love_letter.service
```
To stop:
```
sudo systemctl stop love_letter.service
```
### Create a config in /etc/nginx/sites-available/love_letter file:

```
vi /etc/nginx/sites-available/love_letter.conf
```

### Create a symbolic link of our config file to the sites-enabled folder:

```
ln -s /etc/nginx/sites-available/love_letter.conf /etc/nginx/sites-enabled/love_letter.conf
```

### Finally, reload nginx to apply config:

```
nginx -t && nginx -s reload
```

check status:

```
systemctl status nginx.service
systemctl status love_letter.service
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

<!-- ### Mở nginx:

```
sudo ufw app list
sudo ufw allow 'Nginx Full'
sudo ufw allow 'Nginx HTTP'
sudo ufw allow 'Nginx HTTPS' -->
<!-- ```

check status:
```
sudo ufw status
``` -->
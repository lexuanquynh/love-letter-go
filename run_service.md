## Desploy service
### Chỉnh file env về dạng:
for pre-production:
```
configs, err := LoadConfig("/usr/local/src/love_letter")
```
for production:
```
configs, err := LoadConfig("/usr/local/src/love_letter_product")
```

Sau đó copy file này lên:

for pre-production:
```
 scp app.env root@156.67.214.17:/usr/local/src/love_letter
```
for production:
```
scp app-product.env root@156.67.214.17:/usr/local/src/love_letter_product
```

### Create service:
for pre-production:
```
vi /etc/systemd/system/love_letter.service
```
for production:
```
vi /etc/systemd/system/love_letter_product.service
```


### To build for Linux system:

```
 GOOS=linux GOARCH=amd64 go build cmd/authorization/auth.go
 ```

 ### Copy auth file to server:

```
scp path/to/file/tomove user@host:path/to/file/topaste
scp auth root@<ipaddress>:go
```
for pre-production:
```
 scp auth root@156.67.214.17:/usr/local/src/love_letter
  scp app.env root@156.67.214.17:/usr/local/src/love_letter
```

for production:
```
 scp auth root@156.67.214.17:/usr/local/src/love_letter_product
  scp app-product.env root@156.67.214.17:/usr/local/src/love_letter_product
```

### Create a service:
for pre-production:
```
sudo vi /etc/systemd/system/love_letter.service
```
or for production:
```
sudo vi /etc/systemd/system/love_letter_product.service
```
with code:
for pre-production:
```
[Unit]
Description=Love letter APIs pre-production
After=multi-user.target

[Service]
User=root
Group=root
Type=simple
Restart=always
RestartSec=5s
ExecStart=/usr/local/src/love_letter/auth

[Install]
WantedBy=multi-user.target
```

for production:
```
[Unit]
Description=Love letter APIs production
After=multi-user.target

[Service]
User=root
Group=root
Type=simple
Restart=always
RestartSec=5s
ExecStart=/usr/local/src/love_letter_product/auth

[Install]
WantedBy=multi-user.target
```



 ### To run service:
for pre-production:
 ```
sudo systemctl start love_letter.service
sudo systemctl enable love_letter.service
sudo systemctl status love_letter.service
```

for production:
```
sudo systemctl start love_letter_product.service
sudo systemctl enable love_letter_product.service
sudo systemctl status love_letter_product.service
```

To stop:
for pre-production:
```
sudo systemctl stop love_letter.service
```
for production:
```
sudo systemctl stop love_letter_product.service
```

Thêm nội dung file như file mẫu.

### Create a config in /etc/nginx/sites-available/love_letter file:

for pre-production:
```
vi /etc/nginx/sites-available/love_letter
```
or for production:
```
vi /etc/nginx/sites-available/love_letter_product
```

Thêm nội dung file như file mẫu.
```
server {
        listen 80;

        location /dev {
                proxy_pass http://127.0.0.1:8081/api/v1;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
         location /production {
                proxy_pass http://127.0.0.1:8082/api/v1;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
}
```

### Create a symbolic link of our config file to the sites-enabled folder:
for pre-production:
```
ln -s /etc/nginx/sites-available/love_letter /etc/nginx/sites-enabled/love_letter
```

for production:
```
ln -s /etc/nginx/sites-available/love_letter_product /etc/nginx/sites-enabled/love_letter_product
```

### Finally, reload nginx to apply config:

```
nginx -t && nginx -s reload
```

check status:

for pre-production:
```
systemctl status nginx.service
systemctl status love_letter.service
```
for production:
```
systemctl status nginx.service
systemctl status love_letter_product.service
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

Để xóa:
```
sudo ufw status numbered
sudo ufw delete xxx
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

### Thao tác với postgres trên server
Để login vào postgres trên server:

```
sudo -u postgres psql
```
Hiển thị database:

```
\l
```

Để chọn database trên server:

```
\c database_name
```

### Test request trên server:

```
wrk -c 10 -d 10s -t10 http://localhost:8081/api/v1/health
```

### Thêm https cho nginx:

```
sudo apt install certbot python3-certbot-nginx
sudo vi /etc/nginx/sites-available/love_letter
```

thêm mỗi dòng:
```
server_name loveletter.codetoanbug.com;
```
sau đó chạy:

```
sudo nginx -t
sudo systemctl reload nginx
```
mở https cho nginx:
```
sudo ufw allow 'Nginx Full'
sudo ufw delete allow 'Nginx HTTP'
```

Sau đó chạy lệnh để tạo https:
```
sudo certbot --nginx -d loveletter.codetoanbug.com
```
Khi hết hạn https chạy:
```
sudo certbot renew --dry-run
```

file /etc/nginx/sites-available/love_letter sẽ có dạng như sau:
```
server {
        server_name loveletter.codetoanbug.com;

        location /dev {
                proxy_pass http://127.0.0.1:8081/api/v1;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
         location /production {
                proxy_pass http://127.0.0.1:8082/api/v1;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/loveletter.codetoanbug.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/loveletter.codetoanbug.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

}
server {
    if ($host = loveletter.codetoanbug.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


        listen 80;
        server_name loveletter.codetoanbug.com;
    return 404; # managed by Certbot
	
}
```



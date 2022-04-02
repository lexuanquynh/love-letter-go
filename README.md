# Love-letter-backend
Backend service for Love letter.
The first golang source code, I make it for learning Golang.

## How to run:
1. Install postgress in your marchine: https://postgresapp.com/downloads.html
2. Open postgress terminal and type:
    ```py
    create database <DB_NAME>;
    create user <DB_USER> with encrypted password 'DB_PASSWORD';
    grant all privileges on database <DB_NAME> to <DB_USER>;
    ```
with DB_NAME, DB_PASSWORD and DB_USER in app.env file. Please read app.env.example file.

3. How to geretate .pem file:
- Generate rsa private key:
  ```py
  openssl genrsa -out access-private.pem 2048
  openssl genrsa -out refresh-private.pem 2048
   
   ```
- Export rsa public key:
  ```py      
  openssl rsa -in access-private.pem -outform PEM -pubout -out access-public.pem
  openssl rsa -in refresh-private.pem -outform PEM -pubout -out refresh-public.pem
  ```

6. Run this command line:
   ```go
   go run cmd/authorization/auth.go
   ```

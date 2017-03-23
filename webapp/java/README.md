# Pixiv 社内 ISUCON 2016, Java 実装

[Pixiv 社内 ISUCON](https://github.com/catatsuy/private-isu) 2016 の Java 版実装です。

## セットアップ
### チェックアウト
`webapp`ディレクトリにこのリポジトリをチェックアウトしてください。

```console
$ cd private_isu/webapp
$ git clone https://github.com/kissyml/pixiv-isucon2016-java java
$ cd java
```

### nignxの設定を変更
`/@myName`で`myName`が取れないので、nginxで`@`を`%40`に書き換えるように設定を変更します。
```console
$ sudo vi /etc/nginx/sites-enabled/isucon.conf 

server {
  listen 80;

  client_max_body_size 10m;
  root /home/isucon/private_isu/webapp/public/;

  location / {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://localhost:8080;
  }

  location ^~ /@ {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://localhost:8080/%40;
  }
}
```

### 実行環境の準備
`Java` の実行環境を用意してください。

// TODO コマンドを書く

### 実行
```console
$ ./gradlew run
```
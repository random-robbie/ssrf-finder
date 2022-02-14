# ssrf-finder
Pass list of urls with FUZZ in and it will check if it has found a potential SSRF.

```
cat urls.txt | ./ssrf-finder
```

or

```
echo https://www.someting.com/?url=FUZZ&whatever=adsa&id=1  | ./ssrf-finder
```

if it generates a ssrf.log file then you have some SSRF's if not no SSRF.

URLs must look like.

```
http://www.something.com/url?=FUZZ&somethingelse=whatever
```



99% of this code is from @tomnomnom the hero!

raise issues if you have questions!

Use a VPS from DO

[![DigitalOcean Referral Badge](https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg)](https://www.digitalocean.com/?refcode=e22bbff5f6f1&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge)

# ssrf-finder
Pass list of urls with FUZZ in and it will check if it has found a potential SSRF.

```
cat urls.txt | ./ssrf-finder
```

if it generates a ssrf.log file then you have some SSRF's if not no SSRF.

URLs must look like.

```
http://www.something.com/url?=FUZZ&somethingelse=whatever
```



99% of this code is from @tomnomnom the hero!

raise issues if you have questions!

